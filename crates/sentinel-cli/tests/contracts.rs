use serde_json::Value;
use std::{fs, process::Command};
use tempfile::tempdir;
#[test]
fn out_001_all_commands_and_errors_validate_against_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/command-output.schema.json")).unwrap();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    let root = tempdir().unwrap();
    let commands: &[&[&str]] = &[
        &["init"],
        &["policy", "check"],
        &["scan", "--type", "secrets"],
        &["doctor"],
        &["audit"],
        &["unknown"],
        &["scan", "--type", "invalid"],
    ];
    for args in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(root.path())
            .arg("--format=json")
            .args(*args)
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let errors: Vec<_> = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "{args:?}: {errors:?}");
        assert_eq!(
            output.status.code(),
            Some(if args[0] == "unknown" || args.contains(&"invalid") {
                2
            } else {
                0
            })
        );
    }
    fs::write(
        root.path().join("secret.txt"),
        format!("ghp_{}", "A".repeat(36)),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(root.path())
        .args(["scan", "--type", "secrets", "--format=json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let mut value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(validator.is_valid(&value));
    value["data"]["findings"][0]["evidence"]["redacted"] = serde_json::json!("raw value");
    assert!(!validator.is_valid(&value));
}
