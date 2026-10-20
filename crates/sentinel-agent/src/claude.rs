use super::*;
use std::process::{Command, ExitStatus};
#[derive(Deserialize)]
pub struct HookInput {
    pub hook_event_name: String,
    pub session_id: String,
    pub tool_use_id: String,
    pub cwd: String,
    pub tool_name: String,
    pub tool_input: Value,
}
pub struct ClaudeAdapter;
impl AgentAdapter for ClaudeAdapter {
    fn normalize(&self, root: &Path, input: &Value, scope: &[String]) -> Result<ActionContext> {
        let v: HookInput =
            serde_json::from_value(input.clone()).map_err(|_| "Malformed Claude hook input")?;
        if v.hook_event_name != "PreToolUse"
            || v.session_id.is_empty()
            || v.session_id.len() > 256
            || v.tool_use_id.is_empty()
            || v.tool_use_id.len() > 256
        {
            return Err("Invalid Claude event or binding identifiers");
        }
        let cwd = Path::new(&v.cwd)
            .canonicalize()
            .map_err(|_| "Invalid Claude working directory")?;
        if !cwd.starts_with(root) {
            return Err("Claude working directory escapes guarded project");
        }
        let (action_type, key) = match v.tool_name.as_str() {
            "Read" => (ActionType::FileRead, "file_path"),
            "Write" | "Edit" => (ActionType::FileWrite, "file_path"),
            "NotebookEdit" => (ActionType::FileWrite, "notebook_path"),
            "Bash" | "PowerShell" => (ActionType::ShellExecute, ""),
            "WebFetch" | "WebSearch" => (ActionType::NetworkAccess, ""),
            _ => return Err("Unknown or unsupported Claude tool is denied"),
        };
        let paths = if key.is_empty() {
            Vec::new()
        } else {
            let path = v
                .tool_input
                .get(key)
                .and_then(Value::as_str)
                .ok_or("File tool has no target path")?;
            let absolute = if Path::new(path).is_absolute() {
                PathBuf::from(path)
            } else {
                cwd.join(path)
            };
            vec![normalize_path(
                root,
                absolute.to_str().ok_or("Action path must be UTF-8")?,
            )?]
        };
        let mut target_state_hashes = std::collections::BTreeMap::new();
        for p in &paths {
            let selected = root.join(p);
            let state = match selected.symlink_metadata() {
                Ok(_) => hash(&read(&selected, 16 * 1024 * 1024)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing".into(),
                Err(_) => return Err("Unable to bind current target state"),
            };
            target_state_hashes.insert(p.clone(), state);
        }
        Ok(ActionContext {
            action_id: v.tool_use_id,
            agent_id: "claude",
            session_id: v.session_id,
            action_type,
            target_paths: paths,
            target_state_hashes,
            arguments_hash: hash(
                &sentinel_audit::canonical(&v.tool_input)
                    .map_err(|_| "Tool arguments cannot be normalized")?,
            ),
            task_scope: scope.to_vec(),
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    schema_version: u32,
    binary: PathBuf,
    binary_hash: String,
    config: PathBuf,
    settings_hash: String,
    hook: Value,
}
#[derive(Debug, Serialize)]
pub struct Installation {
    pub schema_version: u32,
    pub healthy: bool,
    pub adapter: &'static str,
    pub minimum_claude_version: &'static str,
    pub coverage: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}
fn settings_path(root: &Path) -> Result<PathBuf> {
    let p = root.join(".claude");
    match fs::create_dir(&p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        _ => return Err("Unable to create Claude settings directory"),
    };
    if !fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
        return Err("Claude settings directory is unsafe");
    }
    Ok(p.join("settings.json"))
}
fn settings(root: &Path) -> Result<(PathBuf, Value)> {
    let path = settings_path(root)?;
    let value = if path.symlink_metadata().is_ok() {
        serde_json::from_slice(&read(&path, 1024 * 1024)?)
            .map_err(|_| "Malformed Claude settings")?
    } else {
        serde_json::json!({})
    };
    if !value.is_object() {
        return Err("Claude settings must be an object");
    }
    if value.get("disableAllHooks").and_then(Value::as_bool) == Some(true) {
        return Err("Claude hooks are disabled");
    };
    Ok((path, value))
}
fn binary_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "Sentinel executable is unavailable")?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
        return Err("Sentinel executable is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(256 * 1024 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| "Sentinel executable cannot be read")?;
    if bytes.len() > 256 * 1024 * 1024 {
        return Err("Sentinel executable exceeds bound");
    }
    Ok(bytes)
}
pub(crate) fn installed_binary(root: &Path) -> Result<PathBuf> {
    let state: Installed = serde_json::from_slice(&read(
        &directory(root)?.join("installation.json"),
        1024 * 1024,
    )?)
    .map_err(|_| "Invalid installation state")?;
    Ok(state.binary)
}
pub fn setup(root: &Path, config: &Path, binary: &Path) -> Result<Installation> {
    let _lock = locked(root)?;
    let binary = binary
        .canonicalize()
        .map_err(|_| "Sentinel executable is unavailable")?;
    let binary_hash = hash(&binary_bytes(&binary)?);
    let (path, mut value) = settings(root)?;
    value["disableAllHooks"] = serde_json::json!(false);
    let hook = serde_json::json!({"matcher":".*","hooks":[{"type":"command","command":binary,"args":["agent","hook","--project",root,"--config",config],"timeout":10,"onFailure":"block"}]});
    if value.get("hooks").is_none() {
        value["hooks"] = serde_json::json!({})
    }
    let hooks = value
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or("Claude hooks configuration must be an object")?;
    let pre = hooks
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("Claude PreToolUse hooks must be an array")?;
    let present = pre.iter().any(|h| h == &hook);
    if !present {
        if pre.iter().any(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|h| {
                    h.iter().any(|h| {
                        h.get("args").and_then(Value::as_array).is_some_and(|a| {
                            a.windows(2).any(|p| {
                                p == [Value::String("agent".into()), Value::String("hook".into())]
                            })
                        })
                    })
                })
        }) {
            return Err("A different Sentinel hook already exists; reconcile it explicitly");
        }
        if path.exists() {
            let backup = path.with_file_name(format!(
                "settings.sentinel-backup-{}.json",
                uuid::Uuid::new_v4()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(backup)
                .map_err(|_| "Unable to back up Claude settings")?;
            file.write_all(&read(&path, 1024 * 1024)?)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Unable to persist Claude settings backup")?;
        }
        pre.push(hook.clone());
        atomic(&path, &value)?;
    }
    let installed = Installed {
        schema_version: 2,
        binary,
        binary_hash,
        config: config.into(),
        settings_hash: hash(&read(&path, 1024 * 1024)?),
        hook,
    };
    atomic(&directory(root)?.join("installation.json"), &installed)?;
    // Initialization explicitly creates integrity evidence for the existing redacted log.
    let audit = sentinel_audit::Store::new(root);
    audit
        .append(
            &sentinel_audit::command_events(sentinel_audit::Command::Audit, 0, None, None)
                .map_err(|_| "Audit initialization failed")?,
        )
        .map_err(|_| "Audit initialization failed")?;
    audit
        .enable_integrity()
        .map_err(|_| "Audit integrity initialization failed")?;
    status(root, config)
}
pub fn status(root: &Path, config: &Path) -> Result<Installation> {
    let state: Installed = serde_json::from_slice(&read(
        &directory(root)?.join("installation.json"),
        1024 * 1024,
    )?)
    .map_err(|_| "Invalid agent installation state")?;
    let (path, value) = settings(root)?;
    let healthy = state.schema_version == 2
        && state.config == config
        && state.binary_hash == hash(&binary_bytes(&state.binary)?)
        && state.settings_hash == hash(&read(&path, 1024 * 1024)?)
        && value
            .get("hooks")
            .and_then(|v| v.get("PreToolUse"))
            .and_then(Value::as_array)
            .is_some_and(|a| a.contains(&state.hook));
    Ok(Installation{schema_version:2,healthy,adapter:"claude-pretooluse-v2",minimum_claude_version:"2.1.295",coverage:vec!["Read, Write, Edit, NotebookEdit paths within the selected project","Bash and PowerShell denied: indirect writes are not safely inspectable","Network tools use deterministic policy; unknown tools are denied","External exact-action approvals, five-minute expiry, single consumption"],limitations:vec!["Hooks are not an operating-system sandbox","Same-user processes can alter state; external filesystem protection is required against that threat","No containment of already-running processes, plugins, external clients or hook-disabling users","Provider version and hook health must be checked by sentinel guard; setup alone is not active enforcement"]})
}
fn executable(value: &str, root: &Path) -> Result<PathBuf> {
    let requested = Path::new(value);
    let candidates = if requested.components().count() > 1 {
        vec![requested.to_path_buf()]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .flat_map(|p| {
                let mut v = vec![p.join(value)];
                if cfg!(windows) {
                    v.push(p.join(format!("{value}.exe")));
                }
                v
            })
            .collect()
    };
    let found = candidates
        .into_iter()
        .find_map(|p| p.canonicalize().ok().filter(|p| p.is_file()))
        .ok_or("Claude executable not found")?;
    if found.starts_with(root) {
        return Err("Refusing a project-local provider executable");
    };
    Ok(found)
}
pub fn guarded(
    root: &Path,
    config: &Path,
    program: &[String],
    scope: Vec<String>,
) -> Result<ExitStatus> {
    let installation = status(root, config)?;
    if !installation.healthy {
        return Err("Agent installation verification failed");
    }
    let selected = program.first().ok_or("Claude executable is required")?;
    let mut index = 1;
    while index < program.len() {
        match program[index].as_str(){
            "-p"|"--print"|"--verbose"=>index+=1,
            "--output-format"=>{if !program.get(index+1).is_some_and(|v|matches!(v.as_str(),"text"|"json"|"stream-json")){return Err("Unsupported provider output format")}index+=2},
            "--max-turns"=>{if !program.get(index+1).and_then(|v|v.parse::<u8>().ok()).is_some_and(|v|(1..=10).contains(&v)){return Err("Provider max-turns must be 1–10")}index+=2},
            _=>return Err("Provider overrides are rejected; supported options are --print, --verbose, --output-format and --max-turns"),
        }
    }
    let exe = executable(selected, root)?;
    let mut child = Command::new(&exe)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "Unable to inspect Claude version")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err("Claude version command failed");
                }
                break;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Claude version inspection timed out");
            }
        }
    }
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or("Claude version stdout missing")?
        .take(4097)
        .read_to_end(&mut output)
        .map_err(|_| "Claude version cannot be read")?;
    if output.len() > 4096 {
        return Err("Claude version output exceeds bound");
    }
    let text = String::from_utf8(output).map_err(|_| "Claude version output is invalid")?;
    let version = text
        .split_whitespace()
        .find_map(|v| semver::Version::parse(v).ok())
        .ok_or("Claude semantic version is missing")?;
    if version.major != 2 || version < semver::Version::new(2, 1, 304) {
        return Err("Claude Code 2.1.304+ within major version 2 is required for the validated restricted-mode hook gate");
    }
    sentinel_audit::Store::new(root)
        .verify(None)
        .map_err(|_| "Audit integrity verification failed")?;
    let installed: Installed = serde_json::from_slice(&read(
        &directory(root)?.join("installation.json"),
        1024 * 1024,
    )?)
    .map_err(|_| "Invalid installation state")?;
    let owned_settings = serde_json::to_string(
        &serde_json::json!({"disableAllHooks":false,"hooks":{"PreToolUse":[installed.hook]}}),
    )
    .map_err(|_| "Unable to construct guarded settings")?;
    let session = begin_session(root, scope)?;
    eprintln!("Sentinel: hook gate verified for supported pre-actions; shell and unsupported tools are denied. This is not an OS sandbox.");
    let result = Command::new(exe)
        .arg("--restricted")
        .arg("--settings")
        .arg(owned_settings)
        .arg("--strict-mcp-config")
        .arg("--mcp-config")
        .arg(r#"{"mcpServers":{}}"#)
        .arg("--disable-slash-commands")
        .arg("--setting-sources")
        .arg("project")
        .args(&program[1..])
        .env_remove("CLAUDE_CODE_SAFE_MODE")
        .env_remove("CLAUDE_CODE_SIMPLE")
        .env_remove("CLAUDE_CODE_BARE")
        .env_remove("CLAUDE_CODE_DISABLE_HOOKS")
        .env_remove("CLAUDE_CODE_DISABLE_ALL_HOOKS")
        .current_dir(root)
        .env("SENTINEL_GUARD_NONCE", &session.nonce)
        .env("SENTINEL_GUARD_PROJECT", root)
        .status()
        .map_err(|_| "Unable to launch guarded Claude session");
    if let Ok(_lock) = locked(root) {
        let _ = fs::remove_file(directory(root)?.join("session.json"));
    }
    result
}
