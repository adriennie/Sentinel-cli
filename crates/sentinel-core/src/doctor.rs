use crate::Project;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}
#[derive(Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: CheckStatus,
    pub message: String,
    pub remediation: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub dependency_scanning: bool,
    pub secrets_scanning: bool,
    pub audit_logging: bool,
    pub agent_enforcement: bool,
}
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub binary_version: &'static str,
    pub policy_schema_version: u32,
    pub status: &'static str,
    pub checks: Vec<Check>,
    pub capabilities: Capabilities,
    pub dependency_cache: Option<sentinel_scanner::CacheInspection>,
    pub exit_code: u8,
}
impl DoctorReport {
    fn new() -> Self {
        Self {
            schema_version: 1,
            binary_version: env!("CARGO_PKG_VERSION"),
            policy_schema_version: 1,
            status: "pass",
            checks: vec![],
            capabilities: Capabilities {
                dependency_scanning: true,
                secrets_scanning: true,
                audit_logging: true,
                agent_enforcement: false,
            },
            dependency_cache: None,
            exit_code: 0,
        }
    }
    fn add(
        &mut self,
        id: &'static str,
        status: CheckStatus,
        message: &'static str,
        remediation: &'static str,
    ) {
        self.checks.push(Check {
            id,
            status,
            message: message.into(),
            remediation,
        });
    }
    fn finish(mut self) -> Self {
        self.status = if self.checks.iter().any(|c| c.status == CheckStatus::Fail) {
            "fail"
        } else if self.checks.iter().any(|c| c.status == CheckStatus::Warn) {
            "warn"
        } else {
            "pass"
        };
        if self.status == "fail" && self.exit_code == 0 {
            self.exit_code = 1;
        }
        self
    }
}
/// Diagnoses even an invalid project selector; never invokes external tools or OSV.
pub fn doctor_at(root: &Path, config: &Path) -> DoctorReport {
    let mut report = DoctorReport::new();
    report.add(
        "binary.version",
        CheckStatus::Pass,
        "Sentinel binary version is available",
        "None",
    );
    let project = match Project::resolve(root, config) {
        Ok(project) => {
            report.add(
                "project.discovery",
                CheckStatus::Pass,
                "Project directory resolved",
                "None",
            );
            project
        }
        Err(_) => {
            report.add(
                "project.discovery",
                CheckStatus::Fail,
                "Project directory cannot be resolved",
                "Select an existing directory with --project",
            );
            return report.finish();
        }
    };
    let policy = match project.check() {
        Ok(policy) => {
            report.add(
                "policy.configuration",
                CheckStatus::Pass,
                "Policy schema and rules are valid",
                "None",
            );
            Some(policy)
        }
        Err(_) => {
            report.add(
                "policy.configuration",
                CheckStatus::Fail,
                "Policy is missing, unreadable, or invalid",
                "Run sentinel policy check; initialize missing configuration with sentinel init",
            );
            report.exit_code = 3;
            None
        }
    };
    if policy.as_ref().is_some_and(|p| !p.audit.enabled) {
        report.add(
            "audit.storage",
            CheckStatus::Warn,
            "Audit logging is disabled by policy",
            "Set audit.enabled to true to record local events",
        );
    } else {
        match sentinel_audit::Store::new(&project.root).probe() {
            Ok(()) => report.add(
                "audit.storage",
                CheckStatus::Pass,
                "Audit directory and existing log are writable",
                "None",
            ),
            Err(_) => report.add(
                "audit.storage",
                CheckStatus::Fail,
                "Audit storage is unavailable, busy, unsafe, or full",
                "Check .sentinel permissions, reject symlinks, and archive oversized logs",
            ),
        }
    }
    match sentinel_audit::Store::new(&project.root).read(1, None) {
        Ok(history) if history.complete => report.add("audit.history", CheckStatus::Pass, "Existing audit history is readable", "None"),
        Ok(_) => report.add("audit.history", CheckStatus::Warn, "Audit history contains malformed or incomplete records", "Inspect sentinel audit; archive the log if needed without treating it as verified evidence"),
        Err(_) => report.add("audit.history", CheckStatus::Fail, "Audit history cannot be safely read", "Check the local audit log permissions, size, file type, and lock availability"),
    }
    if policy.as_ref().is_some_and(|p| !p.scanning.dependencies) {
        report.add(
            "scanner.dependencies",
            CheckStatus::Warn,
            "Dependency scanning is disabled by policy",
            "Enable scanning.dependencies when dependency checks are needed",
        );
    } else {
        let inventory = sentinel_scanner::discover(&project.root, None);
        if inventory.diagnostics.is_empty() {
            report.add(
                "scanner.dependencies",
                CheckStatus::Pass,
                "Discovered Cargo, npm, uv or Poetry lockfile inventories are supported; freshness and installed-environment equivalence are not verified",
                "None",
            );
        } else {
            let categories = [
                ("python_lock_conflict", "conflicting Python lockfiles"),
                (
                    "python_manifest_unresolved",
                    "unresolved Python manifest or workspace",
                ),
                ("python_version_unresolved", "unresolved Python versions"),
                (
                    "python_constraint_conflict",
                    "conflicting Python constraints",
                ),
                (
                    "python_source_uncovered",
                    "private or unsupported Python sources/includes",
                ),
                (
                    "python_inventory_partial",
                    "requirements inventory has unproven transitive coverage",
                ),
                (
                    "unsupported_dependency",
                    "missing, unsupported, or unreadable dependency inputs",
                ),
            ];
            let gaps: Vec<_> = categories
                .iter()
                .filter(|(code, _)| inventory.diagnostics.iter().any(|d| d.code == *code))
                .map(|(_, label)| *label)
                .collect();
            let message = format!("Dependency discovery is incomplete: {}", gaps.join("; "));
            report.checks.push(Check {
                id: "scanner.dependencies",
                status: CheckStatus::Warn,
                message,
                remediation: "Run sentinel scan --type dependencies for file-level diagnostics; reconcile lockfiles and exact pins; private sources are not queried as PyPI",
            });
        }
        match sentinel_audit::probe_directory(&project.root, &[".sentinel", "cache", "osv-v1"]) {
            Ok(()) => report.add(
                "cache.storage",
                CheckStatus::Pass,
                "OSV cache directory is writable",
                "None",
            ),
            Err(_) => report.add(
                "cache.storage",
                CheckStatus::Fail,
                "OSV cache storage is unavailable or unsafe",
                "Check cache permissions and remove symlink storage directories",
            ),
        }
        let cache = sentinel_scanner::inspect_cache(&project.root, &inventory);
        if cache.missing_or_invalid > 0
            || cache.stale > 0
            || cache.packages_inspected < cache.packages_total
        {
            report.add("cache.intelligence", CheckStatus::Warn, "Offline intelligence is missing, invalid, stale, or only partially inspected", "Run an online dependency scan to refresh the cache; doctor inspects up to 1000 package entries");
        } else {
            report.add(
                "cache.intelligence",
                CheckStatus::Pass,
                "Inspected package cache entries are current or no registry packages were found",
                "None",
            );
        }
        report.dependency_cache = Some(cache);
    }
    report.add(
        "scanner.secrets",
        if policy.as_ref().is_some_and(|p| !p.scanning.secrets) {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        },
        "Local pattern-based secrets scanning is available",
        "Use sentinel scan --type secrets; ignored files require --include-ignored",
    );
    if project
        .root
        .join(".sentinel/agent/installation.json")
        .symlink_metadata()
        .is_ok()
    {
        match sentinel_agent::status(&project.root,&project.config){
            Ok(health) if health.healthy=>{report.capabilities.agent_enforcement=true;report.add("integrations",CheckStatus::Pass,"Claude hook installation verified; enforcement applies only inside a verified sentinel guard session", "Use sentinel agent status for coverage; hooks are not an OS sandbox");}
            _=>report.add("integrations",CheckStatus::Fail,"Claude hook installation is missing, changed, or unsafe","Reconcile settings and reinstall the verified gate before starting a guarded session"),
        }
    } else {
        report.add("integrations",CheckStatus::Pass,"No active agent gate is claimed; Claude integration is available through explicit setup and guard","Use sentinel agent setup claude, inspect coverage, then sentinel guard -- claude");
    }
    report.finish()
}
