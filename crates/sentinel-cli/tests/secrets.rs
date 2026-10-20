use std::{fs, process::Command};
use tempfile::tempdir;
#[test]
fn scan_002_redaction_across_outputs_and_audit() {
    let root = tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(root.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["init"]).status.success());
    let secret = format!("ghp_{}", "A".repeat(36));
    fs::write(root.path().join("config.txt"), &secret).unwrap();
    for args in [
        &["scan", "--type", "secrets", "--format=json"][..],
        &["scan", "--type", "secrets", "--quiet"],
        &["scan", "--offline", "--format=json"],
    ] {
        let output = run(args);
        assert!(matches!(output.status.code(), Some(4 | 7)));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&secret));
        assert!(String::from_utf8_lossy(&output.stdout).contains("[REDACTED]"));
    }
    let raw = fs::read_to_string(root.path().join(".sentinel/audit.jsonl")).unwrap();
    assert!(!raw.contains(&secret));
    let value: serde_json::Value =
        serde_json::from_slice(&run(&["scan", "--type", "secrets", "--format=json"]).stdout)
            .unwrap();
    assert_eq!(value["data"]["files_checked"], 2);
    assert_eq!(value["data"]["findings"][0]["location"]["line"], 1);
    assert_eq!(
        run(&["scan", "--type", "secrets", "--sbom", "missing.json"])
            .status
            .code(),
        Some(2)
    );
}
#[test]
fn policy_selection_and_doctor_capabilities() {
    let root = tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(root.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["init"]).status.success());
    let config = fs::read_to_string(root.path().join("sentinel.yml")).unwrap();
    fs::write(
        root.path().join("sentinel.yml"),
        config.replace("secrets: true", "secrets: false"),
    )
    .unwrap();
    assert_eq!(run(&["scan", "--type", "secrets"]).status.code(), Some(3));
    fs::write(
        root.path().join("sentinel.yml"),
        config.replace("dependencies: true", "dependencies: false"),
    )
    .unwrap();
    assert_eq!(run(&["scan", "--offline"]).status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&run(&["doctor", "--format=json"]).stdout).unwrap();
    assert_eq!(value["data"]["capabilities"]["secrets_scanning"], true);
}
