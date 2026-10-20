//! Optional v2 sidecar; v1 event bytes and readers are unchanged.
use super::*;
use sha2::{Digest, Sha256};
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Link {
    schema_version: u32,
    sequence: u64,
    event_id: Uuid,
    previous: String,
    hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachment: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema_version: u32,
    pub project: String,
    pub records: u64,
    pub head: String,
}
#[derive(Debug, Serialize)]
pub struct Verification {
    pub schema_version: u32,
    pub complete: bool,
    pub records: u64,
    pub head: String,
    pub checkpoint_status: &'static str,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn links(bytes: &[u8], attachments: &[Option<String>]) -> Result<Vec<Link>, AuditError> {
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(AuditError("Audit exceeds verification bound"));
    }
    let mut result = Vec::new();
    let mut previous = "0".repeat(64);
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.len() > MAX_RECORD_BYTES || !line.ends_with(b"\n") {
            return Err(AuditError("Audit contains incomplete or oversized record"));
        }
        let event: Event = serde_json::from_slice(line)
            .map_err(|_| AuditError("Audit contains malformed record"))?;
        if !event.valid() {
            return Err(AuditError("Audit contains invalid event"));
        }
        let canonical = super::canonical(&event)?;
        let sequence = result.len() as u64 + 1;
        let mut material = format!("sentinel-audit-v2\n{sequence}\n{previous}\n").into_bytes();
        material.extend(canonical);
        let attachment = attachments.get(result.len()).cloned().flatten();
        if let Some(a) = &attachment {
            if a.len() != 64 || !a.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(AuditError("Invalid audit attachment"));
            }
            material.extend(format!("\nattachment-sha256\n{a}\n").as_bytes());
        }
        let current = hash(&material);
        result.push(Link {
            schema_version: 2,
            sequence,
            event_id: event.event_id,
            previous,
            hash: current.clone(),
            attachment,
        });
        previous = current;
    }
    Ok(result)
}
fn read(path: &Path) -> Result<Vec<u8>, AuditError> {
    if !regular(path)? {
        return Err(AuditError("Audit chain or checkpoint is missing"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| AuditError("Unable to read integrity data"))?;
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(AuditError("Integrity data exceeds bound"));
    }
    Ok(bytes)
}
fn recorded(bytes: &[u8]) -> Result<Vec<Link>, AuditError> {
    bytes
        .split_inclusive(|b| *b == b'\n')
        .map(|line| {
            if line.len() > MAX_RECORD_BYTES || !line.ends_with(b"\n") {
                return Err(AuditError("Incomplete integrity record"));
            }
            serde_json::from_slice(line).map_err(|_| AuditError("Malformed integrity record"))
        })
        .collect()
}
fn serialize(values: &[Link]) -> Result<Vec<u8>, AuditError> {
    let mut bytes = Vec::new();
    for v in values {
        bytes.extend(
            serde_json::to_vec(v).map_err(|_| AuditError("Integrity serialization failed"))?,
        );
        bytes.push(b'\n')
    }
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(AuditError("Integrity chain exceeds limit"));
    }
    Ok(bytes)
}
/// Caller holds the exclusive v1 log lock. Prefixes are verified, never repaired.
pub(super) fn update(
    root: &Path,
    file: &mut File,
    create: bool,
    attachment: Option<&str>,
) -> Result<(), AuditError> {
    let path = root.join(".sentinel/audit-chain-v2.jsonl");
    let exists = regular(&path)?;
    if !exists && !create {
        if attachment.is_some() {
            return Err(AuditError(
                "Attached events require integrity initialization",
            ));
        }
        return Ok(());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AuditError("Unable to inspect audit snapshot"))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuditError("Unable to read audit snapshot"))?;
    let current = if exists {
        recorded(&read(&path)?)?
    } else {
        Vec::new()
    };
    let count = bytes.split_inclusive(|b| *b == b'\n').count();
    let mut attachments: Vec<_> = current.iter().map(|l| l.attachment.clone()).collect();
    attachments.resize(count, attachment.map(str::to_owned));
    let expected = links(&bytes, &attachments)?;
    if current.len() > expected.len() || current != expected[..current.len()] {
        return Err(AuditError(
            "Audit chain verification failed; data was modified or truncated",
        ));
    }
    if create && exists && current.len() != expected.len() {
        return Err(AuditError(
            "Existing integrity chain is incomplete; refusing repair",
        ));
    }
    let mut options = OpenOptions::new();
    options.append(true).write(true);
    if !exists {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(path)
        .map_err(|_| AuditError("Unable to open integrity chain"))?;
    let added = serialize(&expected[current.len()..])?;
    if output
        .metadata()
        .map_err(|_| AuditError("Unable to inspect integrity chain"))?
        .len()
        + added.len() as u64
        > MAX_LOG_BYTES
    {
        return Err(AuditError("Integrity chain exceeds limit"));
    }
    output
        .write_all(&added)
        .and_then(|_| output.sync_data())
        .map_err(|_| AuditError("Unable to persist integrity chain"))
}
impl Store {
    pub fn enable_integrity(&self) -> Result<(), AuditError> {
        let path = self.existing_path()?.ok_or(AuditError(
            "Create an audited command before enabling integrity",
        ))?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .map_err(|_| AuditError("Unable to open audit log"))?;
        lock(&file, false)?;
        update(&self.root, &mut file, true, None)
    }
    pub fn verify(&self, checkpoint: Option<&Path>) -> Result<Verification, AuditError> {
        let path = self
            .existing_path()?
            .ok_or(AuditError("Audit log is missing"))?;
        let mut file = File::open(path).map_err(|_| AuditError("Unable to open audit log"))?;
        lock(&file, true)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_LOG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuditError("Unable to read audit log"))?;
        let stored = recorded(&read(&self.root.join(".sentinel/audit-chain-v2.jsonl"))?)?;
        let attachments: Vec<_> = stored.iter().map(|l| l.attachment.clone()).collect();
        let expected = links(&bytes, &attachments)?;
        if expected != stored {
            return Err(AuditError("Audit chain verification failed"));
        }
        let head = expected
            .last()
            .map(|l| l.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let status = if let Some(path) = checkpoint {
            let cp: Checkpoint = serde_json::from_slice(&read(path)?)
                .map_err(|_| AuditError("Invalid checkpoint"))?;
            let previous = if cp.records == 0 {
                Some("0".repeat(64))
            } else {
                expected
                    .get(cp.records.saturating_sub(1) as usize)
                    .map(|l| l.hash.clone())
            };
            if cp.schema_version != 2
                || cp.project != hash(self.root.to_string_lossy().as_bytes())
                || previous.as_deref() != Some(cp.head.as_str())
            {
                return Err(AuditError(
                    "Independent checkpoint mismatch or log truncation",
                ));
            }
            "matched_independent_snapshot_not_authenticated"
        } else {
            "not_supplied_truncation_not_proven"
        };
        Ok(Verification {
            schema_version: 2,
            complete: true,
            records: expected.len() as u64,
            head,
            checkpoint_status: status,
        })
    }
    /// Call verify before trusting these references. Each is bound into the chain hash.
    pub fn attachment_heads(&self) -> Result<Vec<String>, AuditError> {
        self.verify(None)?;
        let path = self
            .existing_path()?
            .ok_or(AuditError("Audit log missing"))?;
        let file = File::open(path).map_err(|_| AuditError("Unable to open audit log"))?;
        lock(&file, true)?;
        Ok(
            recorded(&read(&self.root.join(".sentinel/audit-chain-v2.jsonl"))?)?
                .into_iter()
                .filter_map(|l| l.attachment)
                .collect(),
        )
    }
    pub fn checkpoint(&self, path: &Path) -> Result<Checkpoint, AuditError> {
        let parent = path
            .parent()
            .ok_or(AuditError("Checkpoint needs a parent directory"))?
            .canonicalize()
            .map_err(|_| AuditError("Checkpoint directory must exist"))?;
        let root = self
            .root
            .canonicalize()
            .map_err(|_| AuditError("Project is unavailable"))?;
        if parent.starts_with(root) {
            return Err(AuditError("Checkpoint must be stored outside the project"));
        }
        let report = self.verify(None)?;
        let checkpoint = Checkpoint {
            schema_version: 2,
            project: hash(self.root.to_string_lossy().as_bytes()),
            records: report.records,
            head: report.head,
        };
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| AuditError("Unable to create checkpoint"))?;
        serde_json::to_writer(temp.as_file_mut(), &checkpoint)
            .map_err(|_| AuditError("Unable to serialize checkpoint"))?;
        temp.as_file()
            .sync_all()
            .map_err(|_| AuditError("Unable to sync checkpoint"))?;
        temp.persist_noclobber(path)
            .map_err(|_| AuditError("Checkpoint already exists or cannot be written"))?;
        Ok(checkpoint)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modified_and_truncated_logs_and_independent_checkpoint() {
        let t = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let s = Store::new(t.path());
        let e = command_events(Command::Init, 0, None, None).unwrap();
        s.append(&e).unwrap();
        s.enable_integrity().unwrap();
        let cp = outside.path().join("checkpoint.json");
        s.checkpoint(&cp).unwrap();
        s.append(&command_events(Command::Doctor, 0, None, None).unwrap())
            .unwrap();
        assert!(s.verify(Some(&cp)).is_ok());
        let log = t.path().join(".sentinel/audit.jsonl");
        let saved = fs::read(&log).unwrap();
        fs::write(&log, b"{}\n").unwrap();
        assert!(s.verify(None).is_err());
        fs::write(&log, &saved).unwrap();
        fs::write(&log, b"").unwrap();
        fs::write(t.path().join(".sentinel/audit-chain-v2.jsonl"), b"").unwrap();
        assert!(s.verify(None).is_ok());
        assert!(s.verify(Some(&cp)).is_err());
    }
}
