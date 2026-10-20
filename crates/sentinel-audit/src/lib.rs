//! Bounded, cooperatively locked local events. No integrity guarantees.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

pub const MAX_LOG_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024;
#[derive(Debug, Error)]
#[error("{0}")]
pub struct AuditError(pub &'static str);
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Command {
    #[serde(rename = "init")]
    Init,
    #[serde(rename = "policy.check")]
    PolicyCheck,
    #[serde(rename = "scan")]
    Scan,
    #[serde(rename = "audit")]
    Audit,
    #[serde(rename = "doctor")]
    Doctor,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    #[serde(rename = "command.completed")]
    CommandCompleted,
    #[serde(rename = "policy.validated")]
    PolicyValidated,
    #[serde(rename = "scan.completed")]
    ScanCompleted,
}
impl EventType {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "command.completed" => Some(Self::CommandCompleted),
            "policy.validated" => Some(Self::PolicyValidated),
            "scan.completed" => Some(Self::ScanCompleted),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Findings,
    Incomplete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: Uuid,
    pub session_id: Uuid,
    pub timestamp: String,
    pub event_type: EventType,
    pub command: Command,
    pub outcome: Outcome,
    pub exit_code: u8,
    pub packages_checked: Option<u64>,
    pub findings_count: Option<u64>,
}
impl Event {
    fn valid(&self) -> bool {
        self.schema_version == 1
            && self.exit_code <= 8
            && !self.event_id.is_nil()
            && !self.session_id.is_nil()
            && self.timestamp.len() <= 40
            && OffsetDateTime::parse(&self.timestamp, &Rfc3339).is_ok()
            && matches!(
                (self.event_type, self.command),
                (EventType::CommandCompleted, _)
                    | (EventType::PolicyValidated, Command::PolicyCheck)
                    | (EventType::ScanCompleted, Command::Scan)
            )
            && self.outcome == outcome(self.exit_code)
    }
}
fn outcome(code: u8) -> Outcome {
    match code {
        0 => Outcome::Success,
        4 => Outcome::Findings,
        7 => Outcome::Incomplete,
        _ => Outcome::Failure,
    }
}
/// Only allowlisted enums and numeric summaries enter the log: never arguments,
/// paths, errors, YAML values, findings, environment variables or credentials.
pub fn command_events(
    command: Command,
    exit_code: u8,
    packages_checked: Option<u64>,
    findings_count: Option<u64>,
) -> Result<Vec<Event>, AuditError> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| AuditError("Unable to format audit timestamp"))?;
    let session_id = Uuid::new_v4();
    let mut types = vec![EventType::CommandCompleted];
    match command {
        Command::PolicyCheck => types.push(EventType::PolicyValidated),
        Command::Scan => types.push(EventType::ScanCompleted),
        _ => {}
    }
    Ok(types
        .into_iter()
        .map(|event_type| Event {
            schema_version: 1,
            event_id: Uuid::new_v4(),
            session_id,
            timestamp: timestamp.clone(),
            event_type,
            command,
            outcome: outcome(exit_code),
            exit_code,
            packages_checked,
            findings_count,
        })
        .collect())
}
fn regular(path: &Path) -> Result<bool, AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(AuditError(
                    "Audit log must be a regular file; symlinks are rejected",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(AuditError("Hard-linked audit logs are rejected"));
                }
            }
            if metadata.len() > MAX_LOG_BYTES {
                return Err(AuditError(
                    "Audit log exceeds 32 MiB; archive it before continuing",
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AuditError("Unable to inspect audit log")),
    }
}
/// Creates only known storage directories and rejects symlink/file ancestors.
pub fn storage_directory(root: &Path, components: &[&str]) -> Result<PathBuf, AuditError> {
    let mut path = root.to_path_buf();
    for part in components {
        if !matches!(*part, ".sentinel" | "cache" | "osv-v1") {
            return Err(AuditError("Invalid storage directory component"));
        }
        path.push(part);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(AuditError("Unable to create local storage directory")),
        }
        if !fs::symlink_metadata(&path)
            .map_err(|_| AuditError("Unable to inspect local storage directory"))?
            .file_type()
            .is_dir()
        {
            return Err(AuditError(
                "Storage directories must not be symlinks or files",
            ));
        }
    }
    Ok(path)
}
pub fn probe_directory(root: &Path, components: &[&str]) -> Result<(), AuditError> {
    let directory = storage_directory(root, components)?;
    let mut probe = tempfile::NamedTempFile::new_in(directory)
        .map_err(|_| AuditError("Local storage is not writable"))?;
    probe
        .write_all(b"sentinel storage probe\n")
        .and_then(|_| probe.as_file().sync_all())
        .map_err(|_| AuditError("Unable to write local storage probe"))?;
    probe
        .close()
        .map_err(|_| AuditError("Unable to remove local storage probe"))
}
fn lock(file: &File, shared: bool) -> Result<(), AuditError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let result = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match result {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(TryLockError::WouldBlock) => {
                return Err(AuditError("Audit log is busy; lock timeout reached"))
            }
            Err(TryLockError::Error(_)) => return Err(AuditError("Unable to lock audit log")),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct History {
    pub schema_version: u32,
    pub events: Vec<Event>,
    pub malformed_records: usize,
    pub complete: bool,
}
pub struct Store {
    root: PathBuf,
}
impl Store {
    pub fn new(root: &Path) -> Self {
        Self { root: root.into() }
    }
    fn existing_path(&self) -> Result<Option<PathBuf>, AuditError> {
        let directory = self.root.join(".sentinel");
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(metadata) if metadata.file_type().is_dir() => {}
            _ => return Err(AuditError("Audit storage is unavailable or is a symlink")),
        }
        let path = directory.join("audit.jsonl");
        Ok(if regular(&path)? { Some(path) } else { None })
    }
    pub fn probe(&self) -> Result<(), AuditError> {
        probe_directory(&self.root, &[".sentinel"])?;
        if let Some(path) = self.existing_path()? {
            let file = OpenOptions::new()
                .read(true)
                .append(true)
                .open(path)
                .map_err(|_| AuditError("Existing audit log is not writable"))?;
            lock(&file, false)?;
        }
        Ok(())
    }
    pub fn append(&self, events: &[Event]) -> Result<(), AuditError> {
        if events.len() > 16 {
            return Err(AuditError("Audit event batch exceeds size limit"));
        }
        let mut bytes = Vec::new();
        for event in events {
            if !event.valid() {
                return Err(AuditError("Invalid audit event"));
            }
            let record = serde_json::to_vec(event)
                .map_err(|_| AuditError("Unable to serialize audit event"))?;
            if record.len() > MAX_RECORD_BYTES {
                return Err(AuditError("Audit event exceeds record size limit"));
            }
            bytes.extend_from_slice(&record);
            bytes.push(b'\n');
        }
        let directory = storage_directory(&self.root, &[".sentinel"])?;
        let path = directory.join("audit.jsonl");
        regular(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| AuditError("Unable to open audit log for append"))?;
        lock(&file, false)?;
        if !file
            .metadata()
            .map_err(|_| AuditError("Unable to inspect open audit log"))?
            .is_file()
        {
            return Err(AuditError("Audit log must be a regular file"));
        }
        let size = file
            .metadata()
            .map_err(|_| AuditError("Unable to inspect audit log size"))?
            .len();
        if size.saturating_add(bytes.len() as u64).saturating_add(1) > MAX_LOG_BYTES {
            return Err(AuditError(
                "Audit log size limit reached; archive it before continuing",
            ));
        }
        if size > 0 {
            file.seek(SeekFrom::End(-1))
                .map_err(|_| AuditError("Unable to inspect audit log tail"))?;
            let mut last = [0];
            file.read_exact(&mut last)
                .map_err(|_| AuditError("Unable to read audit log tail"))?;
            if last[0] != b'\n' {
                file.write_all(b"\n")
                    .map_err(|_| AuditError("Unable to separate incomplete audit record"))?;
            }
        }
        file.write_all(&bytes)
            .and_then(|_| file.sync_data())
            .map_err(|_| AuditError("Unable to append audit events"))
    }
    pub fn read(&self, limit: usize, filter: Option<EventType>) -> Result<History, AuditError> {
        if !(1..=10_000).contains(&limit) {
            return Err(AuditError("Audit limit must be between 1 and 10000"));
        }
        let mut history = History {
            schema_version: 1,
            events: vec![],
            malformed_records: 0,
            complete: true,
        };
        let Some(path) = self.existing_path()? else {
            return Ok(history);
        };
        let file = File::open(path).map_err(|_| AuditError("Unable to read audit log"))?;
        lock(&file, true)?;
        let mut bytes = Vec::new();
        (&file)
            .take(MAX_LOG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuditError("Unable to read audit log"))?;
        if bytes.len() as u64 > MAX_LOG_BYTES {
            return Err(AuditError("Audit log exceeds read limit"));
        }
        let mut records = Vec::new();
        for (index, line) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
            let record = if line.len() <= MAX_RECORD_BYTES && line.ends_with(b"\n") {
                serde_json::from_slice::<Event>(line)
                    .ok()
                    .filter(Event::valid)
            } else {
                None
            };
            match record {
                Some(event) if filter.is_none_or(|kind| kind == event.event_type) => {
                    records.push((index, event))
                }
                Some(_) => {}
                None => history.malformed_records += 1,
            }
        }
        // Canonical RFC3339 parsing makes timezone offsets comparable without echoing input.
        records.sort_by(|a, b| {
            let a_time = OffsetDateTime::parse(&a.1.timestamp, &Rfc3339).ok();
            let b_time = OffsetDateTime::parse(&b.1.timestamp, &Rfc3339).ok();
            b_time.cmp(&a_time).then(b.0.cmp(&a.0))
        });
        records.truncate(limit);
        history.complete = history.malformed_records == 0;
        Ok(History {
            events: records.into_iter().map(|(_, event)| event).collect(),
            ..history
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn append_filter_limits_and_partial_records() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::new(root.path());
        assert!(store.read(50, None).unwrap().events.is_empty());
        assert!(!root.path().join(".sentinel").exists());
        store
            .append(&command_events(Command::Scan, 7, Some(2), Some(1)).unwrap())
            .unwrap();
        store
            .append(&command_events(Command::PolicyCheck, 3, None, None).unwrap())
            .unwrap();
        assert_eq!(store.read(50, None).unwrap().events.len(), 4);
        let events = store
            .read(1, Some(EventType::ScanCompleted))
            .unwrap()
            .events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Incomplete);
        let path = root.path().join(".sentinel/audit.jsonl");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"SYNTHETIC_PRIVATE_VALUE")
            .unwrap();
        store
            .append(&command_events(Command::Audit, 0, None, None).unwrap())
            .unwrap();
        let report = store.read(50, None).unwrap();
        assert_eq!(report.malformed_records, 1);
        assert!(!report.complete);
        assert_eq!(report.events.len(), 5);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("SYNTHETIC_PRIVATE_VALUE"));
        assert!(store.read(0, None).is_err());
        assert!(store.read(10001, None).is_err());
    }
    #[test]
    fn concurrent_appends_remain_whole_and_unique() {
        let root = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let path = root.path();
                scope.spawn(move || {
                    for _ in 0..10 {
                        Store::new(path)
                            .append(&command_events(Command::Init, 0, None, None).unwrap())
                            .unwrap();
                    }
                });
            }
        });
        let history = Store::new(root.path()).read(100, None).unwrap();
        assert_eq!(history.events.len(), 80);
        assert!(history.complete);
        let ids: std::collections::HashSet<_> = history.events.iter().map(|e| e.event_id).collect();
        assert_eq!(ids.len(), 80);
    }
    #[test]
    fn unknown_fields_and_invalid_events_never_escape() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::new(root.path());
        store.probe().unwrap();
        let event = command_events(Command::Init, 0, None, None)
            .unwrap()
            .remove(0);
        let mut value = serde_json::to_value(&event).unwrap();
        value["secret"] = serde_json::json!("SYNTHETIC_PRIVATE_VALUE");
        fs::write(
            root.path().join(".sentinel/audit.jsonl"),
            format!("{value}\n"),
        )
        .unwrap();
        let history = store.read(50, None).unwrap();
        assert_eq!(history.malformed_records, 1);
        assert!(history.events.is_empty());
        let mut bad = event.clone();
        bad.timestamp = "SYNTHETIC_PRIVATE_VALUE".into();
        assert!(store.append(&[bad]).is_err());
        let mut bad = event;
        bad.schema_version = 9;
        assert!(store.append(&[bad]).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join(".sentinel")).unwrap();
        let store = Store::new(root.path());
        assert!(store.read(1, None).is_err());
        assert!(store
            .append(&command_events(Command::Init, 0, None, None).unwrap())
            .is_err());
        fs::remove_file(root.path().join(".sentinel")).unwrap();
        fs::create_dir(root.path().join(".sentinel")).unwrap();
        fs::write(outside.path().join("other"), b"do not change").unwrap();
        fs::hard_link(
            outside.path().join("other"),
            root.path().join(".sentinel/audit.jsonl"),
        )
        .unwrap();
        assert!(store.probe().is_err());
        assert_eq!(
            fs::read(outside.path().join("other")).unwrap(),
            b"do not change"
        );
    }
    #[test]
    fn oversized_logs_and_lock_contention_are_explicit_errors() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::new(root.path());
        store
            .append(&command_events(Command::Init, 0, None, None).unwrap())
            .unwrap();
        let path = root.path().join(".sentinel/audit.jsonl");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.lock().unwrap();
        let error = store
            .append(&command_events(Command::Audit, 0, None, None).unwrap())
            .unwrap_err();
        assert!(error.0.contains("timeout"));
        file.unlock().unwrap();
        file.set_len(MAX_LOG_BYTES + 1).unwrap();
        assert!(store.read(50, None).is_err());
        assert!(store
            .append(&command_events(Command::Init, 0, None, None).unwrap())
            .is_err());
    }
}
