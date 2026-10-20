//! Detailed decisions are hash-chained and their heads are attached to the command audit chain.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    actor: String,
    sequence: u64,
    previous_hash: String,
    hash: String,
    action_id_hash: String,
    session_id_hash: String,
    binding: String,
    decision: Decision,
    code: String,
    risk_score: u8,
    risk_evidence: sentinel_policy::RiskEvidence,
    timestamp: u64,
    matched_rules: Vec<String>,
}
fn digest(record: &Record) -> Result<String> {
    let mut value = serde_json::to_value(record).map_err(|_| "Decision serialization failed")?;
    value
        .as_object_mut()
        .ok_or("Decision record is invalid")?
        .remove("hash");
    Ok(hash(
        &sentinel_audit::canonical(&value).map_err(|_| "Decision serialization failed")?,
    ))
}
fn records(root: &Path) -> Result<Vec<Record>> {
    let path = directory(root)?.join("decisions.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = read(&path, 8 * 1024 * 1024)?;
    let mut records = Vec::new();
    let mut previous = "0".repeat(64);
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.len() > 16 * 1024 || !line.ends_with(b"\n") {
            return Err("Decision journal contains interrupted or oversized record");
        }
        let r: Record =
            serde_json::from_slice(line).map_err(|_| "Decision journal record is malformed")?;
        if !matches!(
            r.actor.as_str(),
            "claude" | "codex" | "copilot" | "operator"
        ) || r.schema_version != 2
            || r.sequence != records.len() as u64 + 1
            || r.previous_hash != previous
            || r.risk_score != sentinel_policy::risk_score(&r.risk_evidence)
            || r.timestamp > now() + 5
            || r.matched_rules.len() > 1000
            || digest(&r)? != r.hash
        {
            return Err("Decision journal verification failed");
        }
        previous = r.hash.clone();
        records.push(r);
    }
    Ok(records)
}
pub(crate) fn verify_locked(root: &Path) -> Result<u64> {
    let records = records(root)?;
    let heads = sentinel_audit::Store::new(root)
        .attachment_heads()
        .map_err(|_| "Decision audit attachments are unavailable")?;
    if records
        .iter()
        .map(|r| r.hash.as_str())
        .ne(heads.iter().map(String::as_str))
    {
        return Err("Detailed decisions do not match the command audit chain");
    }
    Ok(records.len() as u64)
}
pub fn verify_audit(
    root: &Path,
    checkpoint: Option<&Path>,
) -> Result<(sentinel_audit::Verification, u64)> {
    let _lock = locked(root)?;
    let report = sentinel_audit::Store::new(root)
        .verify(checkpoint)
        .map_err(|_| "Command audit chain or checkpoint verification failed")?;
    let count = verify_locked(root)?;
    Ok((report, count))
}
pub fn checkpoint(root: &Path, path: &Path) -> Result<sentinel_audit::Checkpoint> {
    let _lock = locked(root)?;
    verify_locked(root)?;
    sentinel_audit::Store::new(root)
        .checkpoint(path)
        .map_err(|_| "Unable to write independent checkpoint")
}
pub(crate) fn append(
    root: &Path,
    action: &ActionContext,
    binding: &str,
    decision: Decision,
    code: &str,
    evidence: &sentinel_policy::RiskEvidence,
    rules: &[String],
) -> Result<String> {
    let current = records(root)?;
    let mut record = Record {
        schema_version: 2,
        actor: action.agent_id.into(),
        sequence: current.len() as u64 + 1,
        previous_hash: current
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| "0".repeat(64)),
        hash: String::new(),
        action_id_hash: hash(action.action_id.as_bytes()),
        session_id_hash: if action.agent_id == "operator" {
            action.session_id.clone()
        } else {
            hash(action.session_id.as_bytes())
        },
        binding: binding.into(),
        decision,
        code: code.into(),
        risk_score: sentinel_policy::risk_score(evidence),
        risk_evidence: evidence.clone(),
        timestamp: now(),
        matched_rules: rules.iter().map(|r| hash(r.as_bytes())).collect(),
    };
    record.hash = digest(&record)?;
    let bytes = serde_json::to_vec(&record).map_err(|_| "Decision serialization failed")?;
    if bytes.len() > 16 * 1024 - 1 {
        return Err("Decision record exceeds audit bound");
    }
    let path = directory(root)?.join("decisions.jsonl");
    let size = path.metadata().map(|m| m.len()).unwrap_or(0);
    if size + bytes.len() as u64 + 1 > 8 * 1024 * 1024 {
        return Err("Decision journal is full");
    }
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|_| "Decision journal unavailable")?;
    f.write_all(&bytes)
        .and_then(|_| f.write_all(b"\n"))
        .and_then(|_| f.sync_data())
        .map_err(|_| "Decision journal persistence failed")?;
    Ok(record.hash)
}
