//! Strict policy parsing and deterministic evaluation; no agent enforcement.
use globset::Glob;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct PolicyError(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    L0,
    L1,
    L2,
    L3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "shell.execute")]
    ShellExecute,
    #[serde(rename = "network.access")]
    NetworkAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    LogOnly,
    RequireApproval,
    Deny,
}
impl Decision {
    fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::LogOnly => 1,
            Self::RequireApproval => 2,
            Self::Deny => 3,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub project: Project,
    pub policy: Rules,
    pub scanning: Scanning,
    pub audit: Audit,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    pub level: Level,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub default_action: Decision,
    pub protected_paths: Vec<String>,
    pub rules: Vec<Rule>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub action: ActionType,
    pub paths: Vec<String>,
    pub decision: Decision,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scanning {
    pub dependencies: bool,
    pub secrets: bool,
    pub offline: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub enabled: bool,
    pub redact_secrets: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionContext {
    pub action_type: ActionType,
    pub target_paths: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct PolicyResult {
    pub decision: Decision,
    pub code: String,
    pub matched_rules: Vec<String>,
    pub reason: String,
}

/// Maximum UTF-8 policy document size (1 MiB), also enforced by file loading.
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;

fn normalize_relative(value: &str) -> Result<String, PolicyError> {
    if value.starts_with('/')
        || value.contains(['\\', ':', '\0'])
        || value.split('/').any(|part| part == "..")
    {
        return Err(PolicyError("Paths must be project-relative without parent traversal, backslashes, colons, or NUL bytes".into()));
    }
    let normalized = value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        return Err(PolicyError(
            "Paths must identify a project-relative target".into(),
        ));
    }
    Ok(normalized)
}
fn compile_pattern(pattern: &str) -> Result<globset::GlobMatcher, PolicyError> {
    let normalized = normalize_relative(pattern)?;
    Glob::new(&normalized)
        .map(|glob| glob.compile_matcher())
        .map_err(|_| PolicyError("Invalid policy glob syntax".into()))
}
fn matches_any(patterns: &[String], paths: &[String]) -> Result<bool, PolicyError> {
    for pattern in patterns {
        let matcher = compile_pattern(pattern)?;
        if paths.iter().any(|path| matcher.is_match(path)) {
            return Ok(true);
        }
    }
    Ok(false)
}
impl Policy {
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        if input.len() > MAX_POLICY_BYTES {
            return Err(PolicyError("Policy exceeds the 1 MiB size limit".into()));
        }
        let options = serde_saphyr::options! {
            budget: serde_saphyr::budget! {
                max_documents: 1, max_depth: 64, max_nodes: 100_000, max_events: 200_000,
                max_aliases: 64, max_anchors: 64, max_total_scalar_bytes: MAX_POLICY_BYTES,
                max_recorded_anchor_events: 100_000, max_recorded_anchor_bytes: MAX_POLICY_BYTES,
            },
            duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
            merge_keys: serde_saphyr::MergeKeyPolicy::Error,
            reject_unsupported_tags: true, strict_booleans: true, with_snippet: false,
        };
        let policy: Self = serde_saphyr::from_str_with_options(input, options).map_err(|error| {
            let location = error.location().map(|location| format!(" at line {}, column {}", location.line(), location.column())).unwrap_or_default();
            PolicyError(format!("Invalid policy YAML or schema{location}; check required fields, types, and supported values"))
        })?;
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != 1 {
            return Err(PolicyError("Unsupported schema_version; expected 1".into()));
        }
        if self.project.name.trim().is_empty() {
            return Err(PolicyError("Project name cannot be empty".into()));
        }
        let mut ids = HashSet::new();
        for pattern in &self.policy.protected_paths {
            compile_pattern(pattern)?;
        }
        for rule in &self.policy.rules {
            if rule.id.trim().is_empty() || !ids.insert(&rule.id) {
                return Err(PolicyError("Empty or duplicate rule ID".into()));
            }
            if matches!(rule.action, ActionType::FileRead | ActionType::FileWrite)
                && rule.paths.is_empty()
            {
                return Err(PolicyError("File rules require paths".into()));
            }
            if matches!(
                rule.action,
                ActionType::ShellExecute | ActionType::NetworkAccess
            ) && !rule.paths.is_empty()
            {
                return Err(PolicyError("Non-file rules cannot have paths".into()));
            }
            for pattern in &rule.paths {
                compile_pattern(pattern)?;
            }
        }
        if !self.audit.redact_secrets {
            return Err(PolicyError("audit.redact_secrets must be true".into()));
        }
        Ok(())
    }
    pub fn new(name: String, level: Level) -> Self {
        Self {
            schema_version: 1,
            project: Project { name, level },
            policy: Rules {
                default_action: Decision::Allow,
                protected_paths: vec![
                    "src/auth/**".into(),
                    "src/payments/**".into(),
                    ".github/workflows/**".into(),
                    ".env*".into(),
                    "sentinel.yml".into(),
                ],
                rules: vec![],
            },
            scanning: Scanning {
                dependencies: true,
                secrets: true,
                offline: false,
            },
            audit: Audit {
                enabled: true,
                redact_secrets: true,
            },
        }
    }
    pub fn evaluate(&self, action: &ActionContext) -> Result<PolicyResult, PolicyError> {
        self.validate()?;
        let paths = action
            .target_paths
            .iter()
            .map(|path| normalize_relative(path))
            .collect::<Result<Vec<_>, _>>()?;
        if matches!(
            action.action_type,
            ActionType::FileRead | ActionType::FileWrite
        ) && action.target_paths.is_empty()
        {
            return Err(PolicyError("File actions require target paths".into()));
        }
        let mut matched = Vec::new();
        for rule in &self.policy.rules {
            if rule.action == action.action_type
                && (rule.paths.is_empty() || matches_any(&rule.paths, &paths)?)
            {
                matched.push(rule);
            }
        }
        let mut decision = matched
            .iter()
            .map(|r| r.decision)
            .max_by_key(|d| d.rank())
            .unwrap_or(self.policy.default_action);
        let protected = matches_any(&self.policy.protected_paths, &paths)?;
        let floor = match (self.project.level, action.action_type) {
            (Level::L3, ActionType::FileWrite) => Decision::Deny,
            (Level::L2 | Level::L3, ActionType::ShellExecute | ActionType::NetworkAccess) => {
                Decision::Deny
            }
            (Level::L0, ActionType::FileWrite) if protected => Decision::LogOnly,
            (Level::L1 | Level::L2, ActionType::FileWrite) if protected => {
                Decision::RequireApproval
            }
            _ => Decision::Allow,
        };
        if floor.rank() > decision.rank() {
            decision = floor;
        }
        Ok(PolicyResult {
            decision,
            code: format!(
                "POLICY_{}",
                match decision {
                    Decision::Allow => "ALLOW",
                    Decision::LogOnly => "LOG_ONLY",
                    Decision::RequireApproval => "REQUIRE_APPROVAL",
                    Decision::Deny => "DENY",
                }
            ),
            matched_rules: matched.iter().map(|r| r.id.clone()).collect(),
            reason: format!(
                "Decision {decision:?}; matched rules: {}; level {:?} restriction: {floor:?}",
                matched
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                self.project.level
            ),
        })
    }
}

/// Deterministic additive evidence, independent from permission precedence.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskEvidence {
    pub protected_path: bool,
    pub destructive_operation: bool,
    pub secret_access: bool,
    pub reachable_dependency: bool,
    pub known_exploitation: bool,
    pub high_epss: bool,
    pub uncertain: bool,
}
pub fn risk_score(e: &RiskEvidence) -> u8 {
    (u8::from(e.protected_path) * 3
        + u8::from(e.destructive_operation) * 4
        + u8::from(e.secret_access) * 4
        + u8::from(e.reachable_dependency) * 2
        + u8::from(e.known_exploitation) * 3
        + u8::from(e.high_epss) * 2
        + u8::from(e.uncertain))
    .min(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn levels() {
        for (level, expected) in [
            (Level::L0, Decision::LogOnly),
            (Level::L1, Decision::RequireApproval),
            (Level::L2, Decision::RequireApproval),
            (Level::L3, Decision::Deny),
        ] {
            let p = Policy::new("test".into(), level);
            assert_eq!(
                p.evaluate(&ActionContext {
                    action_type: ActionType::FileWrite,
                    target_paths: vec!["src/auth/login.rs".into()]
                })
                .unwrap()
                .decision,
                expected
            );
            assert!(Policy::parse(&serde_saphyr::to_string(&p).unwrap()).is_ok());
        }
    }
    #[test]
    fn strict_validation() {
        let base = serde_saphyr::to_string(&Policy::new("test".into(), Level::L1)).unwrap();
        for invalid in [
            "[".to_string(),
            base.replace("schema_version: 1", "schema_version: 2"),
            base.replace("L1", "L9"),
            format!("{base}\nunknown: true"),
            base.replace("src/auth/**", "../auth/**"),
            base.replace("src/auth/**", "/auth/**"),
            base.replace("src/auth/**", "[broken"),
        ] {
            assert!(Policy::parse(&invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn precedence_and_duplicate_ids() {
        let mut p = Policy::new("test".into(), Level::L0);
        for (id, decision) in [
            ("allow", Decision::Allow),
            ("approval", Decision::RequireApproval),
            ("deny", Decision::Deny),
        ] {
            p.policy.rules.push(Rule {
                id: id.into(),
                action: ActionType::FileWrite,
                paths: vec!["**".into()],
                decision,
            });
        }
        let action = ActionContext {
            action_type: ActionType::FileWrite,
            target_paths: vec!["file".into()],
        };
        assert_eq!(p.evaluate(&action).unwrap().decision, Decision::Deny);
        p.policy.rules.pop();
        assert_eq!(
            p.evaluate(&action).unwrap().decision,
            Decision::RequireApproval
        );
        p.policy.rules.pop();
        assert_eq!(p.evaluate(&action).unwrap().decision, Decision::Allow);
        p.policy.rules.push(Rule {
            id: "allow".into(),
            action: ActionType::FileWrite,
            paths: vec!["**".into()],
            decision: Decision::Deny,
        });
        assert!(p.validate().is_err());
    }
    #[test]
    fn level_floors_defaults_and_multi_target_rules() {
        for level in [Level::L0, Level::L1, Level::L2, Level::L3] {
            let mut p = Policy::new("test".into(), level);
            for action_type in [ActionType::ShellExecute, ActionType::NetworkAccess] {
                let result = p
                    .evaluate(&ActionContext {
                        action_type,
                        target_paths: vec![],
                    })
                    .unwrap();
                assert_eq!(
                    result.decision,
                    if matches!(level, Level::L2 | Level::L3) {
                        Decision::Deny
                    } else {
                        Decision::Allow
                    }
                );
            }
            let read = ActionContext {
                action_type: ActionType::FileRead,
                target_paths: vec!["src/auth/login.rs".into()],
            };
            assert_eq!(p.evaluate(&read).unwrap().decision, Decision::Allow);
            p.policy.default_action = Decision::Deny;
            assert_eq!(p.evaluate(&read).unwrap().decision, Decision::Deny);
        }
        let mut p = Policy::new("test".into(), Level::L1);
        p.policy.rules.push(Rule {
            id: "deny-private".into(),
            action: ActionType::FileWrite,
            paths: vec!["private/**".into()],
            decision: Decision::Deny,
        });
        let result = p
            .evaluate(&ActionContext {
                action_type: ActionType::FileWrite,
                target_paths: vec!["public/a".into(), "private/key".into()],
            })
            .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.code, "POLICY_DENY");
        assert_eq!(result.matched_rules, vec!["deny-private"]);
        for paths in [
            vec![],
            vec!["../escape".into()],
            vec!["/absolute".into()],
            vec!["C:/drive".into()],
            vec![r"folder\file".into()],
        ] {
            assert!(p
                .evaluate(&ActionContext {
                    action_type: ActionType::FileWrite,
                    target_paths: paths
                })
                .is_err());
        }
    }
    #[test]
    fn invalid_fields_and_rule_semantics() {
        let base = serde_saphyr::to_string(&Policy::new("test".into(), Level::L1)).unwrap();
        for invalid in [
            base.replace("name: test", "name: ''"),
            base.replace("level: L1", "level: L1\n  surprise: true"),
            base.replace("allow", "invalid"),
            base.replace("redact_secrets: true", "redact_secrets: false"),
        ] {
            assert!(Policy::parse(&invalid).is_err(), "{invalid}");
        }
        let mut p = Policy::new("test".into(), Level::L1);
        p.policy.rules.push(Rule {
            id: "test".into(),
            action: ActionType::FileRead,
            paths: vec![],
            decision: Decision::Allow,
        });
        assert!(p.validate().is_err());
        p.policy.rules[0].action = ActionType::ShellExecute;
        assert!(p.validate().is_ok());
        p.policy.rules[0].paths.push("**".into());
        assert!(p.validate().is_err());
        let invalid_action = serde_saphyr::to_string(&p)
            .unwrap()
            .replace("shell.execute", "shell.unknown");
        assert!(Policy::parse(&invalid_action).is_err());
        p.policy.rules[0].action = ActionType::FileWrite;
        p.policy.rules[0].id = " ".into();
        assert!(p.validate().is_err());
    }
    #[test]
    fn normalized_paths_preserve_protection_and_deny_rules() {
        let mut policy = Policy::new("test".into(), Level::L1);
        for path in [
            "src/auth/login.rs",
            "./src/auth/login.rs",
            "src//auth/./login.rs",
            ".//src/auth/login.rs",
        ] {
            assert_eq!(
                policy
                    .evaluate(&ActionContext {
                        action_type: ActionType::FileWrite,
                        target_paths: vec![path.into()]
                    })
                    .unwrap()
                    .decision,
                Decision::RequireApproval
            );
        }
        policy.policy.rules.push(Rule {
            id: "deny".into(),
            action: ActionType::FileWrite,
            paths: vec!["./private//**".into()],
            decision: Decision::Deny,
        });
        assert_eq!(
            policy
                .evaluate(&ActionContext {
                    action_type: ActionType::FileWrite,
                    target_paths: vec!["./private/./key".into()]
                })
                .unwrap()
                .decision,
            Decision::Deny
        );
        for path in [
            "src/auth/../public",
            "./../src/auth/key",
            "//host/share",
            "C:/auth",
            "src/\0key",
            ".",
            "./",
            "",
        ] {
            assert!(policy
                .evaluate(&ActionContext {
                    action_type: ActionType::FileWrite,
                    target_paths: vec![path.into()]
                })
                .is_err());
        }
    }
    #[test]
    fn untrusted_policy_errors_do_not_echo_content() {
        let marker = "SYNTHETIC_PRIVATE_VALUE";
        let base = serde_saphyr::to_string(&Policy::new("test".into(), Level::L1)).unwrap();
        for input in [
            format!("{marker}: ["),
            base.replace("L1", marker),
            base.replace("src/auth/**", &format!("[{marker}")),
        ] {
            let error = Policy::parse(&input).unwrap_err();
            assert!(!error.to_string().contains(marker));
            assert!(!format!("{error:?}").contains(marker));
        }
        let mut policy = Policy::new("test".into(), Level::L1);
        policy.policy.rules.push(Rule {
            id: marker.into(),
            action: ActionType::FileWrite,
            paths: vec![],
            decision: Decision::Deny,
        });
        assert!(!policy.validate().unwrap_err().to_string().contains(marker));
        assert!(policy
            .evaluate(&ActionContext {
                action_type: ActionType::FileWrite,
                target_paths: vec!["file".into()]
            })
            .is_err());
    }
    #[test]
    fn policy_size_limit() {
        let base = serde_saphyr::to_string(&Policy::new("test".into(), Level::L1)).unwrap();
        let exact = format!("{}{}", base, " ".repeat(MAX_POLICY_BYTES - base.len()));
        assert!(Policy::parse(&exact).is_ok());
        assert!(Policy::parse(&(exact + " ")).is_err());
    }
    #[test]
    fn yaml_limits_duplicates_and_extensions_fail_closed() {
        let base = serde_saphyr::to_string(&Policy::new("test".into(), Level::L1)).unwrap();
        for input in [
            format!("schema_version: 1\n{base}"),
            format!("{base}\n---\n{base}"),
            base.replace("name: test", "name: !include /tmp/private"),
            base.replace(
                "name: test",
                &format!("name: {}secret{}", "[".repeat(70), "]".repeat(70)),
            ),
            base.replace(
                "name: test",
                &format!(
                    "name: [{}]",
                    std::iter::repeat_n("&a x, *a", 70)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            ),
        ] {
            let error = Policy::parse(&input).unwrap_err().to_string();
            assert!(!error.contains("/tmp/private"));
            assert!(!error.contains("secret"));
        }
        let literal = base.replace("name: test", "name: '${SENTINEL_TEST_VALUE}'");
        assert_eq!(
            Policy::parse(&literal).unwrap().project.name,
            "${SENTINEL_TEST_VALUE}"
        );
    }
}
