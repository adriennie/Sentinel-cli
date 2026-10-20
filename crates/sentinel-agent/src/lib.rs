//! Hook policy gate, not process containment. No provider-specific data enters policy.
mod approvals;
mod claude;
mod journal;
mod risk;
pub use approvals::{grant as grant_approval, list as list_approvals, Approval, ApprovalStatus};
pub use claude::{guarded, setup, status, ClaudeAdapter, HookInput, Installation};
pub use journal::{checkpoint as audit_checkpoint, verify_audit};
pub use risk::{store as store_risk, RiskEntry};
use sentinel_policy::{ActionType, Decision, Level, Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
fn folded_path(value: &str) -> String {
    value.nfc().flat_map(char::to_lowercase).nfc().collect()
}
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub type Result<T> = std::result::Result<T, &'static str>;
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
pub(crate) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|_| "Required agent state is unavailable")?;
    if !m.is_file() || m.len() > limit {
        return Err("Agent input must be a bounded regular file");
    }
    sentinel_audit::single_link(path).map_err(|_| "Linked or unsafe agent state is rejected")?;
    let mut b = Vec::new();
    File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_end(&mut b))
        .map_err(|_| "Unable to read agent state")?;
    if b.len() as u64 > limit {
        return Err("Agent state exceeds bound");
    }
    Ok(b)
}
pub(crate) fn directory(root: &Path) -> Result<PathBuf> {
    let base = sentinel_audit::storage_directory(root, &[".sentinel"])
        .map_err(|_| "Agent storage is unsafe")?;
    let p = base.join("agent");
    if let Err(e) = fs::create_dir(&p) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err("Unable to create agent storage");
        }
    }
    if !fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
        return Err("Agent storage must not be a symlink");
    }
    Ok(p)
}
pub(crate) fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if path.symlink_metadata().is_ok() {
        read(path, 4 * 1024 * 1024)?;
    }
    let parent = path.parent().ok_or("State path needs a parent")?;
    let mut t =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "Unable to create agent state")?;
    let bytes = serde_json::to_vec(value).map_err(|_| "Unable to serialize agent state")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Agent state exceeds 4 MiB bound");
    }
    t.write_all(&bytes)
        .map_err(|_| "Unable to write agent state")?;
    t.as_file()
        .sync_all()
        .map_err(|_| "Unable to sync agent state")?;
    t.persist(path)
        .map_err(|_| "Unable to persist agent state")?;
    Ok(())
}
pub(crate) fn locked(root: &Path) -> Result<File> {
    let p = directory(root)?.join("state.lock");
    if p.symlink_metadata().is_ok() {
        read(&p, 1)?;
    }
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(p)
        .map_err(|_| "Unable to open agent lock")?;
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(TryLockError::WouldBlock) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5))
            }
            _ => return Err("Agent state lock unavailable"),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub nonce: String,
    pub created: u64,
    pub scope: Vec<String>,
    pub actor: String,
}
pub fn begin_session(root: &Path, scope: Vec<String>) -> Result<Session> {
    let _lock = locked(root)?;
    for s in &scope {
        if s.starts_with('/') || s.contains(['\\', ':']) || s.split('/').any(|p| p == "..") {
            return Err("Task scope must be project-relative");
        }
        globset::Glob::new(s).map_err(|_| "Invalid task scope pattern")?;
    }
    let existing = directory(root)?.join("session.json");
    if existing.exists() {
        let old: Session = serde_json::from_slice(&read(&existing, 64 * 1024)?)
            .map_err(|_| "Invalid existing session")?;
        if old.created <= now() && now() - old.created < 8 * 3600 {
            return Err("Another guarded session is active; end it before starting another");
        }
    }
    let s = Session {
        nonce: uuid::Uuid::new_v4().to_string(),
        created: now(),
        scope,
        actor: "claude".into(),
    };
    atomic(&directory(root)?.join("session.json"), &s)?;
    Ok(s)
}
#[derive(Debug, Serialize)]
pub struct ActionContext {
    pub action_id: String,
    pub agent_id: &'static str,
    pub session_id: String,
    pub action_type: ActionType,
    pub target_paths: Vec<String>,
    pub arguments_hash: String,
    pub target_state_hashes: std::collections::BTreeMap<String, String>,
    pub task_scope: Vec<String>,
}
pub trait AgentAdapter {
    fn normalize(&self, root: &Path, input: &Value, scope: &[String]) -> Result<ActionContext>;
}
#[derive(Debug, Serialize)]
pub struct GateResult {
    pub decision: Decision,
    pub code: &'static str,
    pub action_id: String,
    pub approval_id: Option<String>,
    pub risk_score: u8,
}
pub fn normalize_path(root: &Path, input: &str) -> Result<String> {
    if input.is_empty() || input.len() > 4096 || input.chars().any(|c| {
        c.is_control()
            || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'|'\u{200b}'..='\u{200f}')
    }) {
        return Err("Invalid action path");
    }
    let supplied = Path::new(input);
    if supplied
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Parent traversal is denied");
    }
    let path = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        root.join(supplied)
    };
    #[cfg(windows)]
    let relative_owned = {
        fn standard(p: &Path) -> Result<PathBuf> {
            let s = p.to_str().ok_or("Windows path must be UTF-8")?;
            let s = s.strip_prefix("\\\\?\\").unwrap_or(s);
            if s.starts_with("UNC\\") || s.starts_with("\\\\") {
                return Err("UNC/device guarded roots are not supported");
            }
            Ok(PathBuf::from(s))
        }
        let base = standard(root)?;
        let selected = standard(&path)?;
        let base: Vec<_> = base.components().collect();
        let selected: Vec<_> = selected.components().collect();
        if selected.len() < base.len()
            || !base.iter().zip(&selected).all(|(a, b)| {
                a.as_os_str().to_string_lossy().to_lowercase()
                    == b.as_os_str().to_string_lossy().to_lowercase()
            })
        {
            return Err("Action escapes selected project");
        }
        // Resolve the existing ancestor to expand DOS short names and obtain
        // filesystem canonical casing before checking the actual root boundary.
        let mut ancestor = standard(&path)?;
        let mut suffix = Vec::new();
        loop {
            match fs::symlink_metadata(&ancestor) {
                Ok(m) => {
                    if m.file_type().is_symlink() {
                        return Err("Action symlinks are denied");
                    }
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    suffix.push(
                        ancestor
                            .file_name()
                            .ok_or("Invalid Windows action path")?
                            .to_os_string(),
                    );
                    if !ancestor.pop() {
                        return Err("Action ancestor is unavailable");
                    }
                }
                _ => return Err("Unable to inspect Windows action ancestor"),
            }
        }
        for parent in ancestor.ancestors() {
            if fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err("Action symlinks are denied");
            }
        }
        let mut resolved = ancestor
            .canonicalize()
            .map_err(|_| "Unable to resolve Windows action ancestor")?;
        for part in suffix.into_iter().rev() {
            resolved.push(part)
        }
        resolved
            .strip_prefix(root)
            .map_err(|_| "Windows action escapes actual project root")?
            .to_path_buf()
    };
    #[cfg(windows)]
    let rel = relative_owned.as_path();
    #[cfg(not(windows))]
    let rel = path
        .strip_prefix(root)
        .map_err(|_| "Action escapes selected project")?;
    let mut checked = root.to_path_buf();
    let mut parts = Vec::new();
    for p in rel.components() {
        match p {
            Component::Normal(s) => {
                let text = s.to_str().ok_or("Path must be UTF-8")?;
                if text.contains([':', '\\']) || text.ends_with(['.', ' ']) {
                    return Err("Ambiguous platform path is denied");
                }
                #[cfg(windows)]
                {
                    let base = text.split('.').next().unwrap_or("").to_ascii_uppercase();
                    if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                        || (base.len() == 4
                            && (base.starts_with("COM") || base.starts_with("LPT"))
                            && matches!(base.as_bytes()[3], b'1'..=b'9'))
                    {
                        return Err("Windows reserved device paths are denied");
                    }
                }
                checked.push(s);
                match fs::symlink_metadata(&checked) {
                    Ok(m) => {
                        if m.file_type().is_symlink() {
                            return Err("Action symlinks are denied");
                        }
                        if m.is_file() {
                            sentinel_audit::single_link(&checked)
                                .map_err(|_| "Linked action files are denied")?;
                        }
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::MetadataExt;
                            if m.file_attributes() & 0x400 != 0 {
                                return Err("Windows reparse paths are denied");
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("Unable to inspect action path"),
                };
                parts.push(text)
            }
            Component::CurDir => {}
            _ => return Err("Invalid path component"),
        }
    }
    if parts.is_empty() {
        return Err("Action must identify a file");
    };
    Ok(parts.join("/"))
}
fn stronger(a: Decision, b: Decision) -> Decision {
    fn rank(d: Decision) -> u8 {
        match d {
            Decision::Allow => 0,
            Decision::LogOnly => 1,
            Decision::RequireApproval => 2,
            Decision::Deny => 3,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}
/// Fixed 0–10 additive evidence model; never grants permission.
pub fn risk(
    protected: bool,
    destructive: bool,
    secret: bool,
    reachable: bool,
    kev: bool,
    unknown: bool,
) -> u8 {
    sentinel_policy::risk_score(&sentinel_policy::RiskEvidence {
        protected_path: protected,
        destructive_operation: destructive,
        secret_access: secret,
        reachable_dependency: reachable,
        known_exploitation: kev,
        uncertain: unknown,
        ..Default::default()
    })
}
pub fn gate(
    root: &Path,
    config: &Path,
    policy: &Policy,
    input: &Value,
    nonce: &str,
) -> Result<GateResult> {
    let _lock = locked(root)?;
    if !status(root, config)?.healthy {
        return Err("Agent installation integrity failed");
    }
    sentinel_audit::Store::new(root)
        .verify(None)
        .map_err(|_| "Audit integrity verification failed")?;
    let s: Session =
        serde_json::from_slice(&read(&directory(root)?.join("session.json"), 64 * 1024)?)
            .map_err(|_| "Invalid guarded session")?;
    if s.nonce != nonce
        || now().saturating_sub(s.created) > 8 * 3600
        || s.created > now()
        || s.actor != "claude"
    {
        return Err("Guarded session is missing or expired");
    }
    journal::verify_locked(root)?;
    let action = ClaudeAdapter.normalize(root, input, &s.scope)?;
    let evaluated = policy
        .evaluate(&sentinel_policy::ActionContext {
            action_type: action.action_type,
            target_paths: action.target_paths.clone(),
        })
        .map_err(|_| "Policy evaluation failed")?;
    let mut decision = evaluated.decision;
    let mut rules = evaluated.matched_rules;
    let mut folded: Policy = serde_json::from_value(
        serde_json::to_value(policy).map_err(|_| "Policy serialization failed")?,
    )
    .map_err(|_| "Policy normalization failed")?;
    for p in &mut folded.policy.protected_paths {
        *p = folded_path(p)
    }
    for r in &mut folded.policy.rules {
        for p in &mut r.paths {
            *p = folded_path(p)
        }
    }
    let folded_result = folded
        .evaluate(&sentinel_policy::ActionContext {
            action_type: action.action_type,
            target_paths: action.target_paths.iter().map(|p| folded_path(p)).collect(),
        })
        .map_err(|_| "Policy normalization failed")?;
    decision = stronger(decision, folded_result.decision);
    rules.extend(folded_result.matched_rules);
    rules.sort();
    rules.dedup();
    let mut code = "AGENT_POLICY";
    let write = action.action_type == ActionType::FileWrite;
    let selected_config = config.canonicalize().ok().and_then(|c| {
        c.strip_prefix(root)
            .ok()
            .map(|p| folded_path(&p.to_string_lossy().replace('\\', "/")))
    });
    let executable = claude::installed_binary(root)?;
    let binary = executable
        .strip_prefix(root)
        .ok()
        .map(|p| folded_path(&p.to_string_lossy().replace('\\', "/")));
    let protected = action.target_paths.iter().any(|p| {
        let p = folded_path(p);
        p == "sentinel.yml"
            || matches!(p.as_str(), ".git" | ".sentinel" | ".claude")
            || p.starts_with(".git/")
            || p.starts_with(".sentinel/")
            || p.starts_with(".claude/")
            || selected_config.as_ref() == Some(&p)
            || binary.as_ref() == Some(&p)
    });
    let secret = action.target_paths.iter().any(|p| {
        p.split('/')
            .any(|part| part.to_lowercase().starts_with(".env"))
    });
    if action.action_type == ActionType::ShellExecute {
        decision = Decision::Deny;
        code = "AGENT_INDIRECT_SHELL_DENIED"
    }
    if protected || (secret && !write) {
        decision = Decision::Deny;
        code = "AGENT_SELF_PROTECTION"
    }
    if write
        && matches!(policy.project.level, Level::L2 | Level::L3)
        && !action.target_paths.iter().all(|p| {
            s.scope
                .iter()
                .any(|g| globset::Glob::new(g).is_ok_and(|g| g.compile_matcher().is_match(p)))
        })
    {
        decision = Decision::Deny;
        code = "AGENT_OUT_OF_SCOPE"
    }
    let policy_protected = action.target_paths.iter().any(|p| {
        policy.policy.protected_paths.iter().any(|g| {
            globset::Glob::new(&folded_path(g))
                .is_ok_and(|g| g.compile_matcher().is_match(folded_path(p)))
        })
    });
    let mut evidence = risk::evidence(root, &action.target_paths);
    evidence.protected_path |= protected || policy_protected;
    evidence.destructive_operation |= action.action_type == ActionType::ShellExecute;
    evidence.secret_access |= secret;
    let score = sentinel_policy::risk_score(&evidence);
    let policy_hash = hash(&serde_json::to_vec(policy).map_err(|_| "Policy binding failed")?);
    let binding=hash(&serde_json::to_vec(&serde_json::json!({"action":{"agent":action.agent_id,"session":action.session_id,"operation":action.action_type,"targets":action.target_paths,"arguments_hash":action.arguments_hash,"target_state_hashes":action.target_state_hashes,"scope":action.task_scope},"project":hash(root.to_string_lossy().as_bytes()),"nonce":hash(nonce.as_bytes()),"policy":policy_hash,"risk_evidence":evidence,"config":hash(config.to_string_lossy().as_bytes())})).map_err(|_|"Action binding failed")?);
    let mut approval_id = None;
    if decision == Decision::RequireApproval {
        let (id, approved) =
            approvals::request_or_consume(root, &binding, &action, &rules, &evidence)?;
        approval_id = Some(id);
        if approved {
            decision = Decision::Allow;
            code = "AGENT_APPROVAL_CONSUMED"
        } else {
            decision = Decision::Deny;
            code = "AGENT_APPROVAL_UNAVAILABLE"
        }
    }
    let head = journal::append(root, &action, &binding, decision, code, &evidence, &rules)?;
    let events = sentinel_audit::command_events(
        sentinel_audit::Command::Audit,
        if matches!(decision, Decision::Allow | Decision::LogOnly) {
            0
        } else {
            5
        },
        None,
        None,
    )
    .map_err(|_| "Unable to construct decision audit summary")?;
    sentinel_audit::Store::new(root)
        .append_attached(&events, &head)
        .map_err(|_| "Decision audit summary failed")?;
    Ok(GateResult {
        decision,
        code,
        action_id: action.action_id,
        approval_id,
        risk_score: score,
    })
}
