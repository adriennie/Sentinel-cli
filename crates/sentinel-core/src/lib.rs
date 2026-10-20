mod doctor;
pub use doctor::{doctor_at, CheckStatus, DoctorReport};
// Project selection and configuration operations.
use sentinel_policy::{Level, Policy, PolicyError, MAX_POLICY_BYTES};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Arguments(&'static str),
    #[error("{0}")]
    Configuration(String),
    #[error("{0}")]
    Policy(#[from] PolicyError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Audit(#[from] sentinel_audit::AuditError),
}
impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Arguments(_) => 2,
            Self::Configuration(_) | Self::Policy(_) => 3,
            Self::Io(_) | Self::Audit(_) => 1,
        }
    }
}

pub struct Project {
    pub root: PathBuf,
    pub config: PathBuf,
}
impl Project {
    pub fn resolve(root: &Path, config: &Path) -> Result<Self, Error> {
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(Error::Configuration("Project must be a directory".into()));
        }
        let config = if config.is_absolute() {
            config.to_path_buf()
        } else {
            root.join(config)
        };
        Ok(Self { root, config })
    }
    pub fn initialize(&self, level: Level, force: bool) -> Result<(), Error> {
        if !force && self.config.symlink_metadata().is_ok() {
            return Err(Error::Configuration(
                "Configuration already exists; use --force to replace it".into(),
            ));
        }
        let name = self
            .root
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "project".into());
        let policy = Policy::new(name, level);
        policy.validate()?;
        let yaml =
            serde_saphyr::to_string(&policy).map_err(|e| Error::Configuration(e.to_string()))?;
        let parent = self
            .config
            .parent()
            .ok_or_else(|| Error::Configuration("Configuration needs a parent directory".into()))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(yaml.as_bytes())?;
        file.as_file().sync_all()?;
        if force {
            file.persist(&self.config).map_err(|e| e.error)?;
        } else {
            file.persist_noclobber(&self.config).map_err(|e| {
                if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Configuration(
                        "Configuration already exists; use --force to replace it".into(),
                    )
                } else {
                    Error::Io(e.error)
                }
            })?;
        }
        Ok(())
    }
    pub fn check(&self) -> Result<Policy, Error> {
        let file = fs::File::open(&self.config).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::Configuration(
                    "Policy not found; run sentinel init or select an existing configuration"
                        .into(),
                )
            } else {
                Error::Io(std::io::Error::new(
                    error.kind(),
                    "Unable to open policy file",
                ))
            }
        })?;
        if !file.metadata()?.is_file() {
            return Err(Error::Configuration("Policy must be a regular file".into()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_POLICY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                Error::Io(std::io::Error::new(
                    error.kind(),
                    "Unable to read policy file",
                ))
            })?;
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(Error::Configuration(
                "Policy exceeds the 1 MiB size limit".into(),
            ));
        }
        let input = String::from_utf8(bytes)
            .map_err(|_| Error::Configuration("Policy must be valid UTF-8".into()))?;
        Ok(Policy::parse(&input)?)
    }
}

// Expose scan application types through core so the CLI does not own security logic.
pub use sentinel_scanner::{ScanOptions, ScanReport, Severity};
impl Project {
    pub fn scan_dependencies(&self, mut options: ScanOptions) -> Result<ScanReport, Error> {
        let policy = self.check()?;
        if !policy.scanning.dependencies {
            return Err(Error::Configuration(
                "Dependency scanning is disabled by policy".into(),
            ));
        }
        options.offline |= policy.scanning.offline;
        // Offline mode deliberately never initializes an HTTP client.
        if options.offline {
            struct Offline;
            impl sentinel_scanner::OsvClient for Offline {
                fn query(
                    &self,
                    _: &sentinel_scanner::Package,
                ) -> Result<Vec<sentinel_scanner::Advisory>, sentinel_scanner::ScanError>
                {
                    Err(sentinel_scanner::ScanError("Network access disabled"))
                }
            }
            Ok(sentinel_scanner::scan(&self.root, &options, &Offline))
        } else {
            let client = sentinel_scanner::HttpOsv::new()
                .map_err(|error| Error::Io(std::io::Error::other(error)))?;
            Ok(sentinel_scanner::scan(&self.root, &options, &client))
        }
    }
}

pub use sentinel_audit::{
    Command as AuditCommand, EventType as AuditEventType, History as AuditHistory,
};
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggingState {
    Recorded,
    Disabled,
}
impl Project {
    pub fn audit_history(
        &self,
        limit: usize,
        event: Option<AuditEventType>,
    ) -> Result<AuditHistory, Error> {
        Ok(sentinel_audit::Store::new(&self.root).read(limit, event)?)
    }
    pub fn record_command(
        &self,
        command: AuditCommand,
        exit_code: u8,
        packages_checked: Option<u64>,
        findings_count: Option<u64>,
    ) -> Result<LoggingState, Error> {
        // Invalid policy never silently disables logging. Reading history remains
        // available even if configuration is broken.
        if self.check().is_ok_and(|policy| !policy.audit.enabled) {
            return Ok(LoggingState::Disabled);
        }
        let events =
            sentinel_audit::command_events(command, exit_code, packages_checked, findings_count)?;
        sentinel_audit::Store::new(&self.root).append(&events)?;
        Ok(LoggingState::Recorded)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ScanSelection {
    Dependencies,
    Secrets,
}
#[derive(Default)]
pub struct ProjectScanOptions {
    pub selection: Option<ScanSelection>,
    pub offline: bool,
    pub sbom: Option<PathBuf>,
    pub include_ignored: bool,
}
impl Project {
    pub fn scan(&self, options: ProjectScanOptions) -> Result<ScanReport, Error> {
        let policy = self.check()?;
        let dependencies = match options.selection {
            Some(ScanSelection::Secrets) => false,
            Some(ScanSelection::Dependencies) => true,
            None => policy.scanning.dependencies,
        };
        let secrets = match options.selection {
            Some(ScanSelection::Dependencies) => false,
            Some(ScanSelection::Secrets) => true,
            None => policy.scanning.secrets,
        };
        if dependencies && !policy.scanning.dependencies
            || secrets && !policy.scanning.secrets
            || !dependencies && !secrets
        {
            return Err(Error::Configuration(
                "Requested scanners are disabled by policy".into(),
            ));
        }
        let mut report = if secrets {
            sentinel_scanner::scan_secrets(&self.root, options.include_ignored)
        } else {
            ScanReport::empty("supported_registry_dependencies")
        };
        if dependencies {
            let dependency_report = self.scan_dependencies(ScanOptions {
                offline: options.offline,
                sbom: options.sbom,
            })?;
            if secrets {
                report.merge(dependency_report);
            } else {
                report = dependency_report;
            }
        }
        Ok(report)
    }
}
