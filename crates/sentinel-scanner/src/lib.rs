//! Dependency inventory, bounded OSV queries and timestamped local intelligence.
mod inventory;
mod osv;
mod scan;
mod secrets;
pub use inventory::{discover, parse_cargo, parse_npm, parse_sbom, Inventory};
pub use osv::{inspect_cache, CacheInspection, HttpOsv, Intelligence, OsvClient};
pub use scan::{scan, ScanOptions};
pub use secrets::scan_secrets;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};
use thiserror::Error;

pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PACKAGES: usize = 10_000;
pub const CACHE_TTL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ScanError(pub &'static str);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn exceeds(self, threshold: Self) -> bool {
        self == Self::Unknown || self >= threshold
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "unknown" => Some(Self::Unknown),
            "low" => Some(Self::Low),
            "moderate" | "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}
impl Package {
    pub fn validate(&self) -> Result<(), ScanError> {
        for value in [&self.ecosystem, &self.name, &self.version] {
            if value.is_empty()
                || value.len() > 256
                || value.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(ScanError("Invalid dependency identity"));
            }
        }
        if self.version.contains([
            '/', '\\', ':', '@', '?', '#', '*', '^', '~', '<', '>', '=', '|',
        ]) || self.name.contains(['\\', '?', '#'])
            || (self.ecosystem != "Maven" && self.name.contains(':'))
        {
            return Err(ScanError("Unresolved or unsafe dependency identity"));
        }
        if matches!(self.ecosystem.as_str(), "npm" | "crates.io")
            && semver::Version::parse(&self.version).is_err()
        {
            return Err(ScanError(
                "Dependency version must be an exact semantic version",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryKind {
    Vulnerability,
    Maintenance,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    #[serde(default)]
    pub kind: AdvisoryKind,
    pub id: String,
    pub severity: Severity,
}
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub schema_version: u32,
    pub id: String,
    pub rule_id: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    pub files: Vec<String>,
    pub evidence: Evidence,
    pub remediation: &'static str,
    pub reachability: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_kind: Option<AdvisoryKind>,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<&'static str>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub package: Option<Package>,
    pub code: &'static str,
    pub file: Option<String>,
    pub message: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub struct CacheUsage {
    pub package: Package,
    pub age_seconds: u64,
    pub stale: bool,
}
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub coverage: &'static str,
    pub inputs: Vec<String>,
    pub schema_version: u32,
    pub status: &'static str,
    pub complete: bool,
    pub packages_discovered: usize,
    pub packages_checked: usize,
    pub files_checked: usize,
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<Diagnostic>,
    pub cache: Vec<CacheUsage>,
}
impl ScanReport {
    pub fn empty(coverage: &'static str) -> Self {
        Self {
            coverage,
            inputs: vec![],
            schema_version: 1,
            status: "complete",
            complete: true,
            packages_discovered: 0,
            packages_checked: 0,
            files_checked: 0,
            findings: vec![],
            diagnostics: vec![],
            cache: vec![],
        }
    }
    pub fn finish(&mut self) {
        self.status = if self.complete {
            "complete"
        } else {
            "incomplete"
        };
    }
    pub fn merge(&mut self, other: Self) {
        self.coverage = "configured_scanners";
        self.complete &= other.complete;
        self.packages_discovered += other.packages_discovered;
        self.packages_checked += other.packages_checked;
        self.files_checked += other.files_checked;
        self.inputs.extend(other.inputs);
        self.inputs.sort();
        self.inputs.dedup();
        self.diagnostics.extend(other.diagnostics);
        self.cache.extend(other.cache);
        if self.findings.len() + other.findings.len() > 100_000 {
            self.complete = false;
            self.diagnostics.push(Diagnostic {
                package: None,
                file: None,
                code: "finding_limit",
                message: "Combined scan exceeded the finding limit",
            });
        }
        let remaining = 100_000_usize.saturating_sub(self.findings.len());
        self.findings
            .extend(other.findings.into_iter().take(remaining));
        self.findings.sort_by(|a, b| a.id.cmp(&b.id));
        self.finish();
    }

    pub fn exit_code(&self, threshold: Severity) -> u8 {
        if !self.complete {
            7
        } else if self.findings.iter().any(|f| f.severity.exceeds(threshold)) {
            4
        } else {
            0
        }
    }
}
pub(crate) fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, ScanError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ScanError("Unable to inspect scan input"))?;
    if !metadata.file_type().is_file() {
        return Err(ScanError(
            "Scan input must be a regular file; symlinks are not followed",
        ));
    }
    let file = std::fs::File::open(path).map_err(|_| ScanError("Unable to open scan input"))?;
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| ScanError("Unable to read scan input"))?;
    if data.len() as u64 > limit {
        return Err(ScanError("Scan input exceeds size limit"));
    }
    Ok(data)
}
pub(crate) fn digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}
