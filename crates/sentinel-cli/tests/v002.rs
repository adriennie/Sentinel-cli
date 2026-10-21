use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;
fn run(root: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(root.path())
        .args(args)
        .output()
        .unwrap()
}
fn init(root: &TempDir) {
    assert!(run(root, &["init"]).status.success());
}
fn validate(output: &Output) -> Value {
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/v002-output.schema.json")).unwrap();
    let v = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    let errors: Vec<_> = v.iter_errors(&value).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}\n{value}");
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/command-output.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    value
}
#[test]
fn policy_fixtures_redteam_approvals_and_integrity_contracts() {
    let root = TempDir::new().unwrap();
    init(&root);
    for args in [
        &["policy", "test", "--format=json"][..],
        &["redteam", "--format=json"][..],
        &["approvals", "list", "--format=json"][..],
    ] {
        let output = run(&root, args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        validate(&output);
    }
    let outside = TempDir::new().unwrap();
    let cp = outside.path().join("checkpoint.json");
    let output = run(
        &root,
        &[
            "audit",
            "checkpoint",
            "--output",
            cp.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert!(output.status.success());
    validate(&output);
    let output = run(
        &root,
        &[
            "audit",
            "verify",
            "--checkpoint",
            cp.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert!(output.status.success());
    let mut value = validate(&output);
    assert!(value["data"]["result"]["records"].as_u64().unwrap() > 0);
    value["data"]["result"]["head"] = json!("invalid");
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/v002-output.schema.json")).unwrap();
    assert!(!jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    fs::write(root.path().join(".sentinel/audit.jsonl"), b"{}\n").unwrap();
    let output = run(&root, &["audit", "verify", "--format=json"]);
    assert_eq!(output.status.code(), Some(8));
    assert!(serde_json::from_slice::<Value>(&output.stdout).is_ok());
}
#[test]
fn custom_policy_fixture_failure_is_deny_and_does_not_execute_actions() {
    let root = TempDir::new().unwrap();
    init(&root);
    fs::write(root.path().join("fixtures.json"),r#"[{"action":{"action_type":"file.write","target_paths":["sentinel.yml"]},"expected":"allow"}]"#).unwrap();
    let output = run(
        &root,
        &[
            "policy",
            "test",
            "--fixtures",
            "fixtures.json",
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(validate(&output)["data"]["result"]["passed"], false);
    assert!(run(&root, &["policy", "check"]).status.success());
}
#[test]
fn agent_installation_and_malformed_callback_fail_closed() {
    let root = TempDir::new().unwrap();
    init(&root);
    let output = run(&root, &["agent", "setup", "claude", "--format=json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(validate(&output)["data"]["result"]["healthy"], true);
    let output = run(&root, &["agent", "status", "--format=json"]);
    validate(&output);
    for input in [b"{}".as_slice(), b"not JSON".as_slice()] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(root.path())
            .args(["agent", "hook"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(result.stderr.is_empty());
    }
    let doctor = run(&root, &["doctor", "--format=json"]);
    let d: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(d["data"]["capabilities"]["agent_enforcement"], true);
}
#[test]
fn sarif_is_official_schema_valid_and_contains_no_secret() {
    let root = TempDir::new().unwrap();
    init(&root);
    let secret = format!("ghp_{}", "A".repeat(36));
    fs::write(root.path().join("secret file.txt"), &secret).unwrap();
    let output = run(&root, &["scan", "--type", "secrets", "--format=sarif"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&secret));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-2.1.0.schema.json")).unwrap();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    let errors: Vec<_> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(
        value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"]
            .as_str()
            .unwrap()
            .contains("%20")
    );
}
#[test]
fn optional_analysis_preserves_v1_findings_and_uses_v2_contract() {
    let root = TempDir::new().unwrap();
    init(&root);
    fs::write(
        root.path().join("Cargo.lock"),
        "version=4\n[[package]]\nname='local'\nversion='1.0.0'\n",
    )
    .unwrap();
    let output = run(
        &root,
        &[
            "scan",
            "--type",
            "dependencies",
            "--offline",
            "--reachability",
            "--exploit-aware",
            "--format=json",
        ],
    );
    assert!(output.status.success());
    let value = validate(&output);
    assert_eq!(value["data"]["command"], "scan.enriched");
    assert_eq!(value["data"]["result"]["scan"]["schema_version"], 1);
}
#[test]
fn guard_rejects_setting_bypass_arguments_and_json_contamination() {
    let root = TempDir::new().unwrap();
    init(&root);
    let output = run(&root, &["guard", "--format=json", "--", "claude"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(serde_json::from_slice::<Value>(&output.stdout).is_ok());
    let _ = Path::new("unused");
}

#[test]
fn proposed_pr_changes_reject_protected_writes_without_executing_them() {
    let root = TempDir::new().unwrap();
    init(&root);
    let list = root.path().join("changes.json");
    fs::write(&list, "[\"src/main.rs\"]").unwrap();
    let allowed = run(
        &root,
        &[
            "policy",
            "test",
            "--changed-files",
            "changes.json",
            "--format=json",
        ],
    );
    assert!(allowed.status.success());
    validate(&allowed);
    fs::write(&list, "[\"sentinel.yml\"]").unwrap();
    let denied = run(
        &root,
        &[
            "policy",
            "test",
            "--changed-files",
            "changes.json",
            "--format=json",
        ],
    );
    assert_eq!(denied.status.code(), Some(5));
    let report = validate(&denied);
    assert_eq!(
        report["data"]["result"]["tests"][0]["actual"],
        "require_approval"
    );
    assert!(!root.path().join("src/main.rs").exists());
}

#[test]
fn codex_and_copilot_cli_lifecycle_and_contracts() {
    let root = TempDir::new().unwrap();
    init(&root);

    // Setup and status for codex
    let setup_cdx = run(&root, &["agent", "setup", "codex", "--format=json"]);
    assert!(setup_cdx.status.success());
    let val_cdx = validate(&setup_cdx);
    assert_eq!(val_cdx["data"]["result"]["healthy"], true);
    assert_eq!(val_cdx["data"]["result"]["provider"], "codex");

    let status_cdx = run(
        &root,
        &["agent", "status", "--provider", "codex", "--format=json"],
    );
    assert!(status_cdx.status.success());
    validate(&status_cdx);

    // Setup and status for copilot
    let setup_cop = run(&root, &["agent", "setup", "copilot", "--format=json"]);
    assert!(setup_cop.status.success());
    let val_cop = validate(&setup_cop);
    assert_eq!(val_cop["data"]["result"]["healthy"], true);
    assert_eq!(val_cop["data"]["result"]["provider"], "copilot");

    let status_cop = run(
        &root,
        &["agent", "status", "--provider", "copilot", "--format=json"],
    );
    assert!(status_cop.status.success());
    validate(&status_cop);

    // Doctor reports both integrations
    let doctor = run(&root, &["doctor", "--format=json"]);
    let doc_val: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    let checks = doc_val["data"]["checks"].as_array().unwrap();
    assert!(checks.iter().any(|c| c["id"] == "integrations.codex"));
    assert!(checks.iter().any(|c| c["id"] == "integrations.copilot"));

    // Guard without --allow-degraded-hooks fails
    let guard_no_flag = run(&root, &["guard", "--provider", "codex", "--", "dummy"]);
    assert_eq!(guard_no_flag.status.code(), Some(1));

    // Hook callbacks fail closed with provider-specific protocols
    for (provider, is_copilot) in [("codex", false), ("copilot", true)] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(root.path())
            .args(["agent", "hook", "--provider", provider])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"{}").unwrap();
        let res = child.wait_with_output().unwrap();
        assert!(res.status.success());
        let val: Value = serde_json::from_slice(&res.stdout).unwrap();
        if is_copilot {
            assert_eq!(val["permissionDecision"], "deny");
        } else {
            assert_eq!(val["hookSpecificOutput"]["permissionDecision"], "deny");
        }
    }
}
