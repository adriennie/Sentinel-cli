//! Version-2 orchestration. CLI translates commands and formats, not security decisions.
use crate::{Error, Project};
pub use sentinel_agent as agent;
pub use sentinel_scanner::{sarif, AnalysisOptions, AnalysisReport};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
fn agent_error(e: &'static str) -> Error {
    Error::Security(1, e)
}
impl Project {
    pub fn agent_setup(&self, binary: &Path) -> Result<Value, Error> {
        let p = self.check()?;
        if !p.audit.enabled {
            return Err(Error::Security(
                3,
                "Guarded agent sessions require audit.enabled",
            ));
        }
        Ok(json!(
            agent::setup(&self.root, &self.config, binary).map_err(agent_error)?
        ))
    }
    pub fn agent_status(&self) -> Result<Value, Error> {
        Ok(json!(
            agent::status(&self.root, &self.config).map_err(agent_error)?
        ))
    }
    pub fn guard(&self, program: &[String], scope: Vec<String>) -> Result<u8, Error> {
        self.check()?;
        Ok(
            if agent::guarded(&self.root, &self.config, program, scope)
                .map_err(agent_error)?
                .success()
            {
                0
            } else {
                1
            },
        )
    }
    pub fn hook(&self, input: &Value, nonce: &str) -> Result<agent::GateResult, Error> {
        let result = (|| {
            let policy = self.check()?;
            if !policy.audit.enabled {
                return Err(Error::Security(5, "Agent audit logging is required"));
            }
            agent::gate(&self.root, &self.config, &policy, input, nonce).map_err(agent_error)
        })();
        if result.is_err() {
            let _ = self.record_command(crate::AuditCommand::Audit, 5, None, None);
        }
        result
    }

    pub fn analysis(
        &self,
        report: &sentinel_scanner::ScanReport,
        mut options: AnalysisOptions,
    ) -> Result<AnalysisReport, Error> {
        options.offline |= self.check()?.scanning.offline;
        struct Offline;
        impl sentinel_scanner::ExploitClient for Offline {
            fn aliases(&self, _: &str) -> Result<Vec<String>, sentinel_scanner::ScanError> {
                Err(sentinel_scanner::ScanError("Network disabled"))
            }
            fn epss(&self, _: &str) -> Result<sentinel_scanner::Epss, sentinel_scanner::ScanError> {
                Err(sentinel_scanner::ScanError("Network disabled"))
            }
            fn kev(&self) -> Result<sentinel_scanner::Kev, sentinel_scanner::ScanError> {
                Err(sentinel_scanner::ScanError("Network disabled"))
            }
        }
        let mut analysis = if options.offline || !options.exploit_aware {
            sentinel_scanner::analyze(&self.root, report, &options, &Offline)
        } else {
            let client = sentinel_scanner::HttpExploit::new()
                .map_err(|_| Error::Security(1, "Unable to initialize exploit intelligence"))?;
            sentinel_scanner::analyze(&self.root, report, &options, &client)
        };
        let mut entries = Vec::new();
        for entrypoint in &options.entrypoints {
            if let Some(path) = entrypoint
                .to_str()
                .and_then(|p| agent::normalize_path(&self.root, p).ok())
            {
                if let Ok(mut file) = std::fs::File::open(self.root.join(&path)) {
                    let mut bytes = Vec::new();
                    if (&mut file)
                        .take(1024 * 1024 + 1)
                        .read_to_end(&mut bytes)
                        .is_ok()
                        && bytes.len() <= 1024 * 1024
                    {
                        entries.push(agent::RiskEntry {
                            path,
                            source_hash: agent::hash(&bytes),
                            reachable: analysis
                                .findings
                                .iter()
                                .any(|f| f.reachability == "reachable"),
                            kev: analysis.findings.iter().any(|f| f.kev == Some(true)),
                            high_epss: analysis
                                .findings
                                .iter()
                                .any(|f| f.epss.is_some_and(|p| p >= 0.5)),
                            uncertain: !analysis.complete,
                        });
                    }
                }
            }
        }
        if !entries.is_empty() && agent::store_risk(&self.root, entries).is_err() {
            analysis.complete = false;
            analysis.diagnostics.push(
                "Risk snapshot could not be stored; guarded actions will not consume this analysis",
            );
        }
        Ok(analysis)
    }
    pub fn audit_verify(&self, checkpoint: Option<&Path>) -> Result<Value, Error> {
        let (report, count) = agent::verify_audit(&self.root, checkpoint).map_err(|_| {
            Error::Security(
                8,
                "Audit verification failed or integrity evidence is unavailable",
            )
        })?;
        let mut value = json!(report);
        value["agent_decisions_verified"] = json!(count);
        Ok(value)
    }
    pub fn audit_checkpoint(&self, path: &Path) -> Result<Value, Error> {
        sentinel_audit::Store::new(&self.root).enable_integrity()?;
        Ok(json!(
            agent::audit_checkpoint(&self.root, path).map_err(agent_error)?
        ))
    }

    pub fn approvals(&self) -> Result<Value, Error> {
        Ok(json!(
            agent::list_approvals(&self.root).map_err(agent_error)?
        ))
    }
    pub fn approve(&self, id: &str, binding: &str) -> Result<Value, Error> {
        agent::grant_approval(&self.root, id, binding).map_err(|_|Error::Security(6,"Approval changed, expired, consumed, or unavailable; inspect pending requests and audit health"))?;
        Ok(json!({"granted":true,"expires":"original five-minute action expiry remains in effect"}))
    }
    pub fn policy_test(&self, path: Option<&Path>, changes: Option<&Path>) -> Result<Value, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fixture {
            action: sentinel_policy::ActionContext,
            expected: sentinel_policy::Decision,
        }
        let policy = self.check()?;
        let mut tests = Vec::new();
        let scope = if let Some(path) = changes {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                self.root.join(path)
            };
            if !path.symlink_metadata()?.is_file() {
                return Err(Error::Arguments(
                    "Proposed changes must be a regular JSON file",
                ));
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error::Arguments("Proposed change inventory exceeds 1 MiB"));
            }
            let paths: Vec<String> = serde_json::from_slice(&bytes)
                .map_err(|_| Error::Arguments("Proposed changes must be a JSON array of paths"))?;
            if paths.len() > 10000 {
                return Err(Error::Arguments("Proposed change count exceeds 10000"));
            }
            for (index, path) in paths.into_iter().enumerate() {
                let actual = policy
                    .evaluate(&sentinel_policy::ActionContext {
                        action_type: sentinel_policy::ActionType::FileWrite,
                        target_paths: vec![path],
                    })?
                    .decision;
                tests.push(json!({"index":index,"passed":matches!(actual,sentinel_policy::Decision::Allow|sentinel_policy::Decision::LogOnly),"actual":actual,"expected":sentinel_policy::Decision::Allow}));
            }
            "proposed_project_changes"
        } else if let Some(path) = path {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                self.root.join(path)
            };
            let m = path.symlink_metadata()?;
            if !m.is_file() || m.len() > 1024 * 1024 {
                return Err(Error::Arguments(
                    "Policy fixtures must be a regular JSON file at most 1 MiB",
                ));
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error::Arguments("Policy fixtures exceed limit"));
            }
            let fixtures: Vec<Fixture> = serde_json::from_slice(&bytes)
                .map_err(|_| Error::Arguments("Malformed policy fixture JSON"))?;
            if fixtures.len() > 1000 {
                return Err(Error::Arguments("Policy fixture count exceeds 1000"));
            }
            for (index, f) in fixtures.into_iter().enumerate() {
                let result = policy.evaluate(&f.action)?;
                tests.push(json!({"index":index,"passed":result.decision==f.expected,"actual":result.decision,"expected":f.expected}));
            }
            "selected_project_policy"
        } else {
            for (level, expected) in [
                (
                    sentinel_policy::Level::L0,
                    sentinel_policy::Decision::LogOnly,
                ),
                (
                    sentinel_policy::Level::L1,
                    sentinel_policy::Decision::RequireApproval,
                ),
                (
                    sentinel_policy::Level::L2,
                    sentinel_policy::Decision::RequireApproval,
                ),
                (sentinel_policy::Level::L3, sentinel_policy::Decision::Deny),
            ] {
                let p = sentinel_policy::Policy::new("synthetic".into(), level);
                let actual = p
                    .evaluate(&sentinel_policy::ActionContext {
                        action_type: sentinel_policy::ActionType::FileWrite,
                        target_paths: vec!["src/auth/fixture.rs".into()],
                    })?
                    .decision;
                tests.push(json!({"index":tests.len(),"passed":actual==expected,"expected":expected,"actual":actual}));
            }
            "built_in_level_invariants"
        };
        let sample = sentinel_policy::ActionContext {
            action_type: sentinel_policy::ActionType::FileRead,
            target_paths: vec!["synthetic.txt".into()],
        };
        let start = std::time::Instant::now();
        let iterations = (10000usize
            / (policy.policy.rules.len() + policy.policy.protected_paths.len()).max(1))
        .clamp(1, 1000);
        for _ in 0..iterations {
            std::hint::black_box(policy.evaluate(&sample)?);
        }
        Ok(
            json!({"scope":scope,"passed":tests.iter().all(|v|v["passed"]==true),"tests":tests,"benchmark":{"iterations":iterations,"total_nanoseconds":start.elapsed().as_nanos().min(u64::MAX as u128)as u64}}),
        )
    }
    pub fn redteam(&self, binary: &Path) -> Result<Value, Error> {
        self.check()?;
        let temp = tempfile::Builder::new()
            .prefix("sentinel-redteam-")
            .tempdir_in(std::env::temp_dir().canonicalize()?)?;
        let root = temp.path();
        let config = root.join("sentinel.yml");
        let policy = sentinel_policy::Policy::new("synthetic".into(), sentinel_policy::Level::L2);
        agent::setup(root, &config, binary).map_err(agent_error)?;
        let session = agent::begin_session(root, vec!["src/**".into()]).map_err(agent_error)?;
        let cases = [
            ("protected_policy", "Write", "sentinel.yml"),
            ("protected_hooks", "Write", ".claude/settings.json"),
            ("protected_audit", "Write", ".sentinel/audit.jsonl"),
            ("out_of_scope", "Write", "outside.txt"),
            ("shell_side_effects", "Bash", "unused"),
            ("traversal", "Write", "../escape.txt"),
            ("unknown_tool", "UnknownTool", "src/file.rs"),
        ];
        let mut results = Vec::new();
        for (name, tool, path) in cases {
            let input = json!({"hook_event_name":"PreToolUse","session_id":"redteam-synthetic","tool_use_id":name,"cwd":root,"tool_name":tool,"tool_input":{"file_path":root.join(path),"command":"SYNTHETIC NEVER EXECUTED"}});
            let denied = agent::gate(root, &config, &policy, &input, &session.nonce)
                .map_or(true, |r| r.decision == sentinel_policy::Decision::Deny);
            results.push(json!({"name":name,"passed":denied}));
        }
        Ok(
            json!({"passed":results.iter().all(|v|v["passed"]==true),"scope":"Synthetic hook requests only; no attack commands were executed","tests":results}),
        )
    }
}
pub fn v2(command: &str, result: Value) -> Value {
    json!({"schema_version":2,"command":command,"result":result})
}
pub fn enriched_exit(base: u8, analysis: &AnalysisReport) -> u8 {
    if base == 1 || base == 2 || base == 3 {
        base
    } else if !analysis.complete {
        7
    } else {
        base
    }
}
pub fn parse_imports(
    values: &[String],
) -> Result<std::collections::BTreeMap<String, String>, Error> {
    let mut map = std::collections::BTreeMap::new();
    for v in values {
        let Some((package, module)) = v.split_once('=') else {
            return Err(Error::Arguments(
                "--python-import expects distribution=module",
            ));
        };
        let package = sentinel_scanner::normalize_python_name(package)
            .map_err(|_| Error::Arguments("Invalid Python distribution name in import mapping"))?;
        if module.is_empty()
            || !module.split('.').all(|p| {
                p.bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                    && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        {
            return Err(Error::Arguments(
                "Python import mapping requires a dotted module identifier",
            ));
        }
        if map.insert(package, module.into()).is_some() {
            return Err(Error::Arguments("Duplicate Python import mapping"));
        }
    }
    Ok(map)
}

pub fn checkpoint_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.into()
    } else {
        root.join(path)
    }
}
