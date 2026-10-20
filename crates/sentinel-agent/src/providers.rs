//! Explicitly best-effort local CLI integrations: upstream hook failures can fail open.
use super::*;
use std::process::{Command, ExitStatus};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Claude,
    Codex,
    Copilot,
}
impl Provider {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "copilot" => Ok(Self::Copilot),
            _ => Err("Unsupported agent provider"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
        }
    }
}
pub struct CodexAdapter;
pub struct CopilotAdapter;
fn translated(
    root: &Path,
    input: &Value,
    scope: &[String],
    provider: Provider,
    tool: &str,
    args: Value,
    context: (&str, &str),
) -> Result<ActionContext> {
    let (session, cwd) = context;
    let mut a=ClaudeAdapter.normalize(root,&serde_json::json!({"hook_event_name":"PreToolUse","session_id":session,"tool_use_id":hash(&sentinel_audit::canonical(input).map_err(|_|"Invalid callback")?),"cwd":cwd,"tool_name":tool,"tool_input":args}),scope)?;
    a.agent_id = provider.name();
    a.arguments_hash = hash(
        &sentinel_audit::canonical(
            input
                .get("tool_input")
                .or_else(|| input.get("toolArgs"))
                .ok_or("Missing tool arguments")?,
        )
        .map_err(|_| "Invalid arguments")?,
    );
    Ok(a)
}
impl AgentAdapter for CopilotAdapter {
    fn normalize(&self, root: &Path, input: &Value, scope: &[String]) -> Result<ActionContext> {
        let session = input
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or("Missing Copilot session")?;
        let cwd = input
            .get("cwd")
            .and_then(Value::as_str)
            .ok_or("Missing Copilot cwd")?;
        let args = input.get("toolArgs").ok_or("Missing Copilot arguments")?;
        let args = if let Some(s) = args.as_str() {
            serde_json::from_str(s).map_err(|_| "Malformed Copilot arguments")?
        } else {
            args.clone()
        };
        if !args.is_object() {
            return Err("Copilot arguments must be an object");
        }
        let tool = match input.get("toolName").and_then(Value::as_str) {
            Some("view") => "Read",
            Some("create" | "edit") => "Write",
            Some("bash" | "powershell") => "Bash",
            Some("web_fetch" | "web_search") => "WebFetch",
            _ => return Err("Unsupported Copilot tool is denied"),
        };
        let path = args.get("path").cloned().unwrap_or(Value::Null);
        translated(
            root,
            input,
            scope,
            Provider::Copilot,
            tool,
            serde_json::json!({"file_path":path}),
            (session, cwd),
        )
    }
}
impl AgentAdapter for CodexAdapter {
    fn normalize(&self, root: &Path, input: &Value, scope: &[String]) -> Result<ActionContext> {
        let v: HookInput =
            serde_json::from_value(input.clone()).map_err(|_| "Malformed Codex callback")?;
        if v.hook_event_name != "PreToolUse"
            || v.tool_use_id.is_empty()
            || v.tool_use_id.len() > 256
        {
            return Err("Unsupported Codex event");
        }
        if v.tool_name == "Bash" {
            return translated(
                root,
                input,
                scope,
                Provider::Codex,
                "Bash",
                v.tool_input.clone(),
                (&v.session_id, &v.cwd),
            );
        }
        if v.tool_name != "apply_patch" {
            return Err("Unsupported Codex tool is denied");
        }
        let patch = v
            .tool_input
            .get("command")
            .and_then(Value::as_str)
            .ok_or("Missing Codex patch")?;
        let paths = patch_paths(patch)?;
        let mut action: Option<ActionContext> = None;
        for path in paths {
            let a = translated(
                root,
                input,
                scope,
                Provider::Codex,
                "Write",
                serde_json::json!({"file_path":path}),
                (&v.session_id, &v.cwd),
            )?;
            if let Some(existing) = &mut action {
                existing.target_paths.extend(a.target_paths);
                existing.target_state_hashes.extend(a.target_state_hashes);
            } else {
                action = Some(a)
            }
        }
        let mut a = action.ok_or("Patch has no targets")?;
        a.target_paths.sort();
        a.target_paths.dedup();
        Ok(a)
    }
}
fn patch_paths(patch: &str) -> Result<Vec<String>> {
    let lines: Vec<_> = patch.lines().collect();
    if lines.first() != Some(&"*** Begin Patch") || lines.last() != Some(&"*** End Patch") {
        return Err("Unsupported patch framing");
    }
    let mut paths = Vec::new();
    let mut active = false;
    let mut update = false;
    for line in &lines[1..lines.len() - 1] {
        let target = if let Some(p) = line.strip_prefix("*** Add File: ") {
            active = true;
            update = false;
            Some(p)
        } else if let Some(p) = line.strip_prefix("*** Update File: ") {
            active = true;
            update = true;
            Some(p)
        } else if let Some(p) = line.strip_prefix("*** Delete File: ") {
            active = true;
            update = false;
            Some(p)
        } else if let Some(p) = line.strip_prefix("*** Move to: ") {
            if !update {
                return Err("Unbound patch move");
            };
            update = false;
            Some(p)
        } else {
            None
        };
        if let Some(p) = target {
            if p.is_empty() || p.trim() != p || paths.len() >= 32 {
                return Err("Invalid or excessive patch targets");
            };
            paths.push(p.to_owned());
        } else if !active || !(line.starts_with(['+', '-', ' ', '@']) || *line == "*** End of File")
        {
            return Err("Unsupported patch syntax");
        }
    }
    if paths.is_empty() {
        return Err("Patch has no targets");
    };
    Ok(paths)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u32,
    provider: String,
    binary: PathBuf,
    binary_hash: String,
    config: PathBuf,
    settings_hash: String,
}
fn state_path(root: &Path, p: Provider) -> Result<PathBuf> {
    Ok(directory(root)?.join(format!("installation-{}.json", p.name())))
}
fn hook_path(root: &Path, p: Provider) -> Result<PathBuf> {
    let parts: &[&str] = match p {
        Provider::Codex => &[".codex"],
        Provider::Copilot => &[".github", "hooks"],
        _ => return Err("Use Claude setup"),
    };
    Ok(sentinel_audit::storage_directory(root, parts)
        .map_err(|_| "Unsafe provider hook directory")?
        .join(if p == Provider::Codex {
            "hooks.json"
        } else {
            "sentinel.json"
        }))
}
fn load(root: &Path, p: Provider) -> Result<State> {
    serde_json::from_slice(&read(&state_path(root, p)?, 1024 * 1024)?)
        .map_err(|_| "Invalid provider installation")
}
pub(crate) fn binary(root: &Path, p: Provider) -> Result<PathBuf> {
    if p == Provider::Claude {
        claude::installed_binary(root)
    } else {
        Ok(load(root, p)?.binary)
    }
}
fn definition(root: &Path, config: &Path, binary: &Path, p: Provider) -> Result<Value> {
    let args = vec![
        "agent".to_owned(),
        "hook".into(),
        "--provider".into(),
        p.name().into(),
        "--project".into(),
        root.to_str().ok_or("Project path must be UTF-8")?.into(),
        "--config".into(),
        config.to_str().ok_or("Config path must be UTF-8")?.into(),
    ];
    if p == Provider::Copilot {
        return Ok(serde_json::json!({"type":"command","exec":binary,"args":args,"timeoutSec":30}));
    }
    if cfg!(windows) {
        return Err("Codex command-hook installation currently supports macOS/Linux only");
    }
    fn quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
    let command = std::iter::once(
        binary
            .to_str()
            .ok_or("Binary path must be UTF-8")?
            .to_owned(),
    )
    .chain(args)
    .map(|s| quote(&s))
    .collect::<Vec<_>>()
    .join(" ");
    Ok(
        serde_json::json!({"matcher":"*","hooks":[{"type":"command","command":command,"timeout":30}]}),
    )
}
pub fn setup_for(root: &Path, config: &Path, binary: &Path, p: Provider) -> Result<Value> {
    if p == Provider::Claude {
        return serde_json::to_value(setup(root, config, binary)?).map_err(|_| "Invalid status");
    }
    let _lock = locked(root)?;
    let binary = binary.canonicalize().map_err(|_| "Binary is unavailable")?;
    let hook = definition(root, config, &binary, p)?;
    let path = hook_path(root, p)?;
    let existed = path.symlink_metadata().is_ok();
    let mut settings = if existed {
        serde_json::from_slice::<Value>(&read(&path, 1024 * 1024)?)
            .map_err(|_| "Invalid existing hook configuration")?
    } else {
        serde_json::json!({})
    };
    if !settings.is_object() || settings.get("disableAllHooks") == Some(&Value::Bool(true)) {
        return Err("Provider hooks are malformed or disabled");
    }
    if p == Provider::Copilot {
        if settings
            .get("version")
            .is_some_and(|v| v != &serde_json::json!(1))
        {
            return Err("Unsupported Copilot hook version");
        };
        settings["version"] = serde_json::json!(1);
    }
    if settings.get("hooks").is_none() {
        settings["hooks"] = serde_json::json!({})
    }
    let key = if p == Provider::Codex {
        "PreToolUse"
    } else {
        "preToolUse"
    };
    let entries = settings
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or("Hook map must be an object")?
        .entry(key)
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("Hook event must be an array")?;
    if !entries.contains(&hook) {
        // Only merge a new hook into a file with no prior Sentinel installation;
        // changed hooks require explicit reconciliation rather than duplication.
        if state_path(root, p)?.exists() {
            return Err("Installed hook changed; reconcile explicitly");
        }
        entries.push(hook);
        if existed {
            let backup =
                path.with_file_name(format!("sentinel-backup-{}.json", uuid::Uuid::new_v4()));
            let original: Value = serde_json::from_slice(&read(&path, 1024 * 1024)?)
                .map_err(|_| "Invalid original hooks")?;
            atomic(&backup, &original)?;
        }
        atomic(&path, &settings)?;
    }
    atomic(
        &state_path(root, p)?,
        &State {
            schema_version: 2,
            provider: p.name().into(),
            binary_hash: hash(&claude::binary_bytes(&binary)?),
            binary,
            config: config.to_path_buf(),
            settings_hash: hash(&read(&path, 1024 * 1024)?),
        },
    )?;
    let store = sentinel_audit::Store::new(root);
    store
        .append(
            &sentinel_audit::command_events(sentinel_audit::Command::Audit, 0, None, None)
                .map_err(|_| "Audit unavailable")?,
        )
        .map_err(|_| "Audit unavailable")?;
    store
        .enable_integrity()
        .map_err(|_| "Audit integrity unavailable")?;
    drop(_lock);
    status_for(root, config, p)
}
pub fn status_for(root: &Path, config: &Path, p: Provider) -> Result<Value> {
    if p == Provider::Claude {
        return serde_json::to_value(status(root, config)?).map_err(|_| "Invalid status");
    }
    let state = load(root, p)?;
    let path = hook_path(root, p)?;
    let settings: Value =
        serde_json::from_slice(&read(&path, 1024 * 1024)?).map_err(|_| "Invalid provider hooks")?;
    let key = if p == Provider::Codex {
        "PreToolUse"
    } else {
        "preToolUse"
    };
    let expected = definition(root, config, &state.binary, p)?;
    let healthy = state.schema_version == 2
        && state.provider == p.name()
        && state.config == config
        && state.binary_hash == hash(&claude::binary_bytes(&state.binary)?)
        && state.settings_hash == hash(&read(&path, 1024 * 1024)?)
        && settings["hooks"][key]
            .as_array()
            .is_some_and(|a| a.contains(&expected));
    Ok(
        serde_json::json!({"schema_version":2,"healthy":healthy,"provider":p.name(),"adapter":format!("{}-pretooluse-v2",p.name()),"enforcement":"best_effort","client_validation":"protocol_fixtures_only","coverage":if p==Provider::Codex{vec!["Local Codex CLI apply_patch targets, including moves and multiple files","Bash and unknown local tools denied when callback executes"]}else{vec!["Local Copilot CLI view/create/edit explicit path targets","Shell, ambiguous patch tools, subagents and unknown tools denied when callback executes"]},"limitations":["Upstream hook errors/timeouts can continue tools: strict fail-closed protection is unavailable","Configuration integrity is not proof that provider trust/admission enabled hooks","Codex requires project and exact hook trust through /hooks; no trust bypass is installed","Other hooks, plugins, cloud/IDE clients and hosted tools are outside this integration","Protocol fixtures tested; real-client tool execution is not yet validated","No operating-system sandbox or containment guarantee"]}),
    )
}
pub fn guarded_for(
    root: &Path,
    config: &Path,
    program: &[String],
    scope: Vec<String>,
    p: Provider,
    allow_degraded: bool,
) -> Result<ExitStatus> {
    if p == Provider::Claude {
        return guarded(root, config, program, scope);
    }
    if !allow_degraded {
        return Err("This provider can fail open; explicit --allow-degraded-hooks is required");
    }
    if status_for(root, config, p)?["healthy"] != true {
        return Err("Provider installation failed verification");
    }
    if program.len() != 1 {
        return Err(
            "Preview integrations accept only the provider executable; overrides are rejected",
        );
    }
    verify_audit(root, None)?;
    let exe = claude::executable(&program[0], root)?;
    let session = begin_session_for(root, scope, p)?;
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            if let Ok(_l) = locked(self.0) {
                if let Ok(d) = directory(self.0) {
                    let _ = fs::remove_file(d.join("session.json"));
                }
            }
        }
    }
    let _cleanup = Cleanup(root);
    eprintln!("Sentinel: BEST-EFFORT hooks only. Provider errors/timeouts or missing trust can bypass decisions. No strict protection is claimed.");
    Command::new(exe)
        .current_dir(root)
        .env("SENTINEL_GUARD_PROVIDER", p.name())
        .env("SENTINEL_GUARD_NONCE", session.nonce)
        .env("SENTINEL_GUARD_PROJECT", root)
        .status()
        .map_err(|_| "Unable to launch provider")
}

/// A validated foreign session lets shared Copilot/Claude discovery abstain only
/// from this provider's hook. The active provider's own hook still decides.
pub fn foreign_session(root: &Path, configured: Provider, active: &str, nonce: &str) -> bool {
    let Ok(active) = Provider::parse(active) else {
        return false;
    };
    if active == configured {
        return false;
    }
    let Ok(_lock) = locked(root) else {
        return false;
    };
    read(
        &directory(root).unwrap_or_default().join("session.json"),
        64 * 1024,
    )
    .ok()
    .and_then(|bytes| serde_json::from_slice::<Session>(&bytes).ok())
    .is_some_and(|s| {
        s.actor == active.name()
            && s.nonce == nonce
            && s.created <= now()
            && now() - s.created < 8 * 3600
    })
}
