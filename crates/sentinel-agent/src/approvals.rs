use super::*;
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Consumed,
    Denied,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub schema_version: u32,
    pub id: String,
    pub binding: String,
    pub actor: String,
    pub session_hash: String,
    pub action_hash: String,
    pub paths: Vec<String>,
    pub operation: ActionType,
    pub expires_at: u64,
    pub status: ApprovalStatus,
    pub preview: String,
    pub matched_rules: Vec<String>,
    pub risk_score: u8,
    pub risk_explanation: String,
    pub risk_evidence: sentinel_policy::RiskEvidence,
}
// Persistence uses owned preview; never deserialize a borrowed static string.

fn file(root: &Path) -> Result<PathBuf> {
    Ok(directory(root)?.join("approvals.json"))
}
fn load(root: &Path) -> Result<Vec<Approval>> {
    let p = file(root)?;
    if !p.exists() {
        return Ok(Vec::new());
    }
    let values: Vec<Approval> = serde_json::from_slice(&read(&p, 4 * 1024 * 1024)?)
        .map_err(|_| "Invalid approval state")?;
    if values.len() > 1000 {
        return Err("Approval state exceeds bound");
    }
    for a in &values {
        let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        if a.schema_version != 2
            || a.actor != "claude"
            || uuid::Uuid::parse_str(&a.id).is_err()
            || !hex(&a.binding)
            || !hex(&a.session_hash)
            || !hex(&a.action_hash)
            || a.risk_score != sentinel_policy::risk_score(&a.risk_evidence)
            || a.paths.len() > 32
            || a.paths
                .iter()
                .any(|p| p.len() > 4096 || p.chars().any(char::is_control))
            || a.preview!="[REDACTED proposed tool arguments/content; review the original request in the trusted client]"
            || a.risk_explanation
                != "Deterministic evidence score; explicit denial is never overridden by approval"
        {
            return Err("Approval metadata is malformed");
        }
    }
    Ok(values)
}
pub fn list(root: &Path) -> Result<Vec<Approval>> {
    let _lock = locked(root)?;
    Ok(load(root)?
        .into_iter()
        .filter(|a| {
            matches!(a.status, ApprovalStatus::Pending | ApprovalStatus::Granted)
                && a.expires_at > now()
        })
        .collect())
}
pub fn grant(root: &Path, id: &str, binding: &str) -> Result<()> {
    let _lock = locked(root)?;
    let mut values = load(root)?;
    let a = values
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or("Unknown approval")?;
    if a.binding != binding
        || a.status != ApprovalStatus::Pending
        || a.expires_at <= now()
        || a.expires_at > now() + 300
    {
        return Err("Approval expired, changed, or unavailable");
    }
    journal::verify_locked(root)?;
    let intent = ActionContext {
        action_id: a.id.clone(),
        agent_id: "operator",
        session_id: a.session_hash.clone(),
        action_type: a.operation,
        target_paths: a.paths.clone(),
        arguments_hash: a.action_hash.clone(),
        target_state_hashes: std::collections::BTreeMap::new(),
        task_scope: Vec::new(),
    };
    let head = journal::append(
        root,
        &intent,
        &a.binding,
        Decision::Allow,
        "APPROVAL_GRANT_INTENT",
        &a.risk_evidence,
        &a.matched_rules,
    )?;
    let events = sentinel_audit::command_events(sentinel_audit::Command::Audit, 0, None, None)
        .map_err(|_| "Approval audit unavailable")?;
    sentinel_audit::Store::new(root)
        .append_attached(&events, &head)
        .map_err(|_| "Approval audit unavailable")?;
    a.status = ApprovalStatus::Granted;
    atomic(&file(root)?, &values)
}
pub(crate) fn request_or_consume(
    root: &Path,
    binding: &str,
    action: &ActionContext,
    rules: &[String],
    evidence: &sentinel_policy::RiskEvidence,
) -> Result<(String, bool)> {
    let mut values = load(root)?;
    if let Some(a) = values.iter_mut().find(|a| a.binding == binding) {
        if a.schema_version != 2
            || a.actor != "claude"
            || a.session_hash != hash(action.session_id.as_bytes())
            || a.action_hash != action.arguments_hash
            || a.expires_at <= now()
            || a.expires_at > now() + 300
        {
            return Err("Approval expired or binding invalid");
        }
        let approved = a.status == ApprovalStatus::Granted;
        if approved {
            a.status = ApprovalStatus::Consumed
        }
        let id = a.id.clone();
        atomic(&file(root)?, &values)?;
        return Ok((id, approved));
    }
    if values.len() >= 1000 {
        return Err("Approval capacity reached; archive expired state manually");
    }
    let id = uuid::Uuid::new_v4().to_string();
    values.push(Approval{schema_version:2,id:id.clone(),binding:binding.into(),actor:"claude".into(),session_hash:hash(action.session_id.as_bytes()),action_hash:action.arguments_hash.clone(),paths:action.target_paths.iter().map(|p|redacted(p)).collect(),operation:action.action_type,expires_at:now()+300,status:ApprovalStatus::Pending,matched_rules:rules.iter().map(|r|if r.len()<=64&&r.bytes().all(|b|b.is_ascii_alphanumeric()||b"._-".contains(&b)){redacted(r)}else{"[REDACTED rule identifier]".into()}).collect(),risk_score:sentinel_policy::risk_score(evidence),risk_evidence:evidence.clone(),risk_explanation:"Deterministic evidence score; explicit denial is never overridden by approval".into(),preview:"[REDACTED proposed tool arguments/content; review the original request in the trusted client]".into()});
    atomic(&file(root)?, &values)?;
    Ok((id, false))
}
fn redacted(path: &str) -> String {
    if path.contains("ghp_")
        || path.contains("github_pat_")
        || path.contains("glpat-")
        || path.contains("xox")
        || path.contains("sk_live_")
    {
        "[REDACTED path]".into()
    } else {
        path.into()
    }
}
