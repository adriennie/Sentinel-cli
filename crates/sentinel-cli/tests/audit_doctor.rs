use serde_json::{json, Value};
use std::{
    fs,
    process::{Command, Output},
};
use tempfile::TempDir;
fn run(root: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(root.path())
        .args(args)
        .output()
        .unwrap()
}
fn initialize(root: &TempDir) {
    assert!(run(root, &["init", "--quiet"]).status.success());
    fs::write(
        root.path().join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
}
fn validate(output: &Output, schema: &str) -> Value {
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: Value = serde_json::from_str(schema).unwrap();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    let errors: Vec<_> = validator
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "Schema errors: {errors:?}\n{value}");
    value
}
const AUDIT_SCHEMA: &str = include_str!("../../../schemas/audit-output.schema.json");
const DOCTOR_SCHEMA: &str = include_str!("../../../schemas/doctor-output.schema.json");
#[test]
fn aud_001_redacted_history_and_json_contract() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    assert!(run(&root, &["policy", "check"]).status.success());
    assert!(run(&root, &["scan", "--type", "dependencies", "--offline"])
        .status
        .success());
    let output = run(
        &root,
        &[
            "audit",
            "--event",
            "scan.completed",
            "--limit",
            "1",
            "--format=json",
        ],
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value = validate(&output, AUDIT_SCHEMA);
    assert_eq!(value["data"]["events"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["events"][0]["packages_checked"], 0);
    let raw = fs::read_to_string(root.path().join(".sentinel/audit.jsonl")).unwrap();
    let event_schema: Value =
        serde_json::from_str(include_str!("../../../schemas/audit-event.schema.json")).unwrap();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&event_schema)
        .unwrap();
    for line in raw.lines() {
        assert!(validator.is_valid(&serde_json::from_str::<Value>(line).unwrap()));
    }
    let config = fs::read_to_string(root.path().join("sentinel.yml")).unwrap();
    fs::write(
        root.path().join("sentinel.yml"),
        config.replace("level: L1", "level: SYNTHETIC_PRIVATE_VALUE"),
    )
    .unwrap();
    assert_eq!(run(&root, &["policy", "check"]).status.code(), Some(3));
    let output = run(&root, &["audit", "--format=json"]);
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_PRIVATE_VALUE"));
    assert!(
        !fs::read_to_string(root.path().join(".sentinel/audit.jsonl"))
            .unwrap()
            .contains("SYNTHETIC_PRIVATE_VALUE")
    );
    let value = validate(&output, AUDIT_SCHEMA);
    assert!(value["data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["event_type"] == "policy.validated" && event["outcome"] == "failure"));
}
#[test]
fn malformed_audit_records_are_reported_without_echoing_content() {
    use std::io::Write;
    let root = TempDir::new().unwrap();
    initialize(&root);
    fs::OpenOptions::new()
        .append(true)
        .open(root.path().join(".sentinel/audit.jsonl"))
        .unwrap()
        .write_all(b"SYNTHETIC_PRIVATE_VALUE\n")
        .unwrap();
    let output = run(&root, &["audit", "--format=json"]);
    assert_eq!(output.status.code(), Some(1));
    let value = validate(&output, AUDIT_SCHEMA);
    assert_eq!(value["data"]["malformed_records"], 1);
    assert_eq!(value["data"]["complete"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_PRIVATE_VALUE"));
    let output = run(&root, &["doctor", "--format=json"]);
    let value = validate(&output, DOCTOR_SCHEMA);
    assert!(value["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["id"] == "audit.history" && check["status"] == "warn"));
}
#[test]
fn logging_can_be_disabled_only_by_a_valid_policy() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    let config = fs::read_to_string(root.path().join("sentinel.yml")).unwrap();
    fs::write(
        root.path().join("sentinel.yml"),
        config.replace("enabled: true", "enabled: false"),
    )
    .unwrap();
    let before = fs::read(root.path().join(".sentinel/audit.jsonl")).unwrap();
    let output = run(&root, &["policy", "check", "--format=json"]);
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["audit_logging"], "disabled");
    assert_eq!(
        before,
        fs::read(root.path().join(".sentinel/audit.jsonl")).unwrap()
    );
}
#[test]
fn doctor_offline_checks_and_failures_have_valid_json() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    let output = run(&root, &["doctor", "--format=json", "--verbose"]);
    assert!(output.status.success());
    let value = validate(&output, DOCTOR_SCHEMA);
    assert_eq!(value["data"]["status"], "pass");
    assert_eq!(value["data"]["capabilities"]["secrets_scanning"], true);
    assert_eq!(value["data"]["dependency_cache"]["packages_total"], 0);
    fs::write(
        root.path().join("sentinel.yml"),
        "invalid: SYNTHETIC_PRIVATE_VALUE",
    )
    .unwrap();
    let output = run(&root, &["doctor", "--format=json"]);
    assert_eq!(output.status.code(), Some(3));
    validate(&output, DOCTOR_SCHEMA);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_PRIVATE_VALUE"));
    let output = run(&root, &["doctor", "--project", "missing", "--format=json"]);
    assert_eq!(output.status.code(), Some(1));
    validate(&output, DOCTOR_SCHEMA);
}
#[test]
fn storage_failure_does_not_erase_scan_results() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    fs::remove_file(root.path().join(".sentinel/audit.jsonl")).unwrap();
    fs::create_dir(root.path().join(".sentinel/audit.jsonl")).unwrap();
    let output = run(
        &root,
        &[
            "scan",
            "--type",
            "dependencies",
            "--offline",
            "--format=json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["complete"], true);
    assert_eq!(value["data"]["audit_logging"], "failed");
    assert!(!output.stderr.is_empty());
    let output = run(&root, &["doctor", "--format=json"]);
    assert_eq!(output.status.code(), Some(1));
    validate(&output, DOCTOR_SCHEMA);
    let output = run(&root, &["audit", "--format=json"]);
    assert_eq!(output.status.code(), Some(1));
    validate(&output, AUDIT_SCHEMA);
}
#[test]
fn audit_flags_help_and_negative_schema_validation() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    for args in [
        &["audit", "--limit", "0"][..],
        &["audit", "--limit", "10001"],
        &["audit", "--event", "unknown"],
    ] {
        assert_eq!(run(&root, args).status.code(), Some(2));
    }
    for command in ["audit", "doctor"] {
        assert!(run(&root, &[command, "--help"]).status.success());
    }
    let schema: Value = serde_json::from_str(DOCTOR_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(!validator.is_valid(&json!({"status":"ok","data":{}})));
    let output = run(&root, &["doctor", "--format=json"]);
    let mut value = validate(&output, DOCTOR_SCHEMA);
    value["data"]["checks"][0]["status"] = json!("unknown");
    assert!(!validator.is_valid(&value));
}
#[test]
fn process_concurrency_preserves_jsonl_records() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    let mut children: Vec<_> = (0..8)
        .map(|_| {
            Command::new(env!("CARGO_BIN_EXE_sentinel"))
                .current_dir(root.path())
                .args(["policy", "check", "--quiet"])
                .spawn()
                .unwrap()
        })
        .collect();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let output = run(
        &root,
        &["audit", "--event", "policy.validated", "--format=json"],
    );
    assert!(output.status.success());
    let value = validate(&output, AUDIT_SCHEMA);
    assert_eq!(value["data"]["events"].as_array().unwrap().len(), 8);
    assert_eq!(value["data"]["malformed_records"], 0);
}

#[test]
fn doctor_reports_missing_cache_and_unsafe_cache_storage() {
    let root = TempDir::new().unwrap();
    initialize(&root);
    fs::write(root.path().join("Cargo.lock"), "version = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n").unwrap();
    let output = run(&root, &["doctor", "--format=json"]);
    assert!(output.status.success());
    let value = validate(&output, DOCTOR_SCHEMA);
    assert_eq!(value["data"]["dependency_cache"]["missing_or_invalid"], 1);
    assert!(value["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["id"] == "cache.intelligence" && check["status"] == "warn"));
    fs::remove_dir(root.path().join(".sentinel/cache/osv-v1")).unwrap();
    fs::remove_dir(root.path().join(".sentinel/cache")).unwrap();
    fs::write(root.path().join(".sentinel/cache"), "not a directory").unwrap();
    let output = run(&root, &["doctor", "--format=json"]);
    assert_eq!(output.status.code(), Some(1));
    let value = validate(&output, DOCTOR_SCHEMA);
    assert!(value["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["id"] == "cache.storage" && check["status"] == "fail"));
}
