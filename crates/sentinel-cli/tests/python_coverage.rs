//! Offline end-to-end coverage, JSON compatibility and audit redaction contracts.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

fn run(root: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(root.path())
        .args(args)
        .output()
        .unwrap()
}
fn valid(output: &Output, schema: &str) -> Value {
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: Value = serde_json::from_str(schema).unwrap();
    assert!(
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap()
            .is_valid(&value),
        "{value}"
    );
    value
}
fn seed(root: &TempDir, advisory: bool) {
    let cache = root.path().join(".sentinel/cache/osv-v1");
    fs::create_dir_all(&cache).unwrap();
    let identity = br#"{"ecosystem":"PyPI","name":"example","version":"1.0"}"#;
    let key = format!("{:x}", Sha256::digest(identity));
    let value = json!({"schema_version":1,"package":serde_json::from_slice::<Value>(identity).unwrap(),"fetched_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),"advisories":if advisory {vec![json!({"id":"TEST-PY-COVERAGE","severity":"high","kind":"vulnerability"})]}else{vec![]}});
    fs::write(
        cache.join(format!("{key}.json")),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
}
const DOCTOR: &str = include_str!("../../../schemas/doctor-output.schema.json");
const SCAN: &str = include_str!("../../../schemas/scan-output.schema.json");
const AUDIT: &str = include_str!("../../../schemas/audit-output.schema.json");
const ENVELOPE: &str = include_str!("../../../schemas/command-output.schema.json");

#[test]
fn conflicting_unresolved_and_private_inputs_have_actionable_offline_contracts() {
    let root = TempDir::new().unwrap();
    assert!(run(&root, &["init"]).status.success());
    let uv = r#"
version = 1
[[package]]
name = "example"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "unresolved"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "private"
version = "2.0"
source = { registry = "https://user:PRIVATE_COVERAGE_TOKEN@example.test/simple" }
"#;
    fs::write(root.path().join("uv.lock"), uv).unwrap();
    fs::write(
        root.path().join("poetry.lock"),
        "[[package]]\nname='example'\nversion='1.0'\n[metadata]\nlock-version='2.1'\n",
    )
    .unwrap();
    fs::write(
        root.path().join("requirements.txt"),
        "example>=1\nunpinned>=1\nconflict==2\n-c constraints.txt\n",
    )
    .unwrap();
    fs::write(
        root.path().join("constraints.txt"),
        "example==1.0\nconflict<2\n",
    )
    .unwrap();
    seed(&root, true);
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
    assert_eq!(output.status.code(), Some(7));
    let scan = valid(&output, SCAN);
    valid(&output, ENVELOPE);
    assert_eq!(scan["data"]["complete"], false);
    assert_eq!(scan["data"]["packages_checked"], 1);
    assert_eq!(
        scan["data"]["findings"][0]["evidence"]["advisory_id"],
        "TEST-PY-COVERAGE"
    );
    let files = scan["data"]["findings"][0]["files"].as_array().unwrap();
    for file in [
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
        "constraints.txt",
    ] {
        assert!(files.contains(&json!(file)));
    }
    let codes: Vec<_> = scan["data"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap())
        .collect();
    for code in [
        "python_lock_conflict",
        "python_version_unresolved",
        "python_source_uncovered",
        "python_constraint_conflict",
        "python_inventory_partial",
    ] {
        assert!(codes.contains(&code), "{codes:?}");
    }
    let output = run(&root, &["doctor", "--format=json"]);
    assert_eq!(output.status.code(), Some(0));
    let doctor = valid(&output, DOCTOR);
    valid(&output, ENVELOPE);
    assert_eq!(doctor["data"]["status"], "warn");
    let check = doctor["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "scanner.dependencies")
        .unwrap();
    assert_eq!(check["status"], "warn");
    let message = check["message"].as_str().unwrap();
    for text in [
        "conflicting Python lockfiles",
        "unresolved Python versions",
        "conflicting Python constraints",
        "private or unsupported",
        "transitive coverage",
    ] {
        assert!(message.contains(text), "{message}");
    }
    for args in [
        &["scan", "--type", "dependencies", "--offline"][..],
        &["doctor"][..],
    ] {
        let text = run(&root, args);
        assert!(!text.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&text.stdout).contains("PRIVATE_COVERAGE_TOKEN"));
        assert!(!String::from_utf8_lossy(&text.stderr).contains("PRIVATE_COVERAGE_TOKEN"));
    }
    let output = run(
        &root,
        &["audit", "--event", "scan.completed", "--format=json"],
    );
    let history = valid(&output, AUDIT);
    assert_eq!(history["data"]["complete"], true);
    for event in history["data"]["events"].as_array().unwrap() {
        assert_eq!(event["outcome"], "incomplete");
        assert_eq!(event["exit_code"], 7);
        assert_eq!(event["packages_checked"], 1);
    }
    let raw = fs::read_to_string(root.path().join(".sentinel/audit.jsonl")).unwrap();
    assert!(!raw.contains("PRIVATE_COVERAGE_TOKEN"));
    assert!(!raw.contains("example.test"));
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/audit-event.schema.json")).unwrap();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    for line in raw.lines() {
        assert!(validator.is_valid(&serde_json::from_str::<Value>(line).unwrap()));
    }
    assert_eq!(fs::read_to_string(root.path().join("uv.lock")).unwrap(), uv);
}

#[test]
fn supported_python_inventory_doctor_and_finding_exit_codes() {
    for file in ["uv.lock", "poetry.lock"] {
        let root = TempDir::new().unwrap();
        assert!(run(&root, &["init"]).status.success());
        fs::write(root.path().join(file), if file == "uv.lock" {
            "version=1\n[[package]]\nname='example'\nversion='1.0'\nsource={registry='https://pypi.org/simple'}\n"
        } else { "[[package]]\nname='example'\nversion='1.0'\n[metadata]\nlock-version='2.1'\n" }).unwrap();
        for advisory in [false, true] {
            seed(&root, advisory);
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
            assert_eq!(output.status.code(), Some(if advisory { 4 } else { 0 }));
            assert_eq!(valid(&output, SCAN)["data"]["complete"], true);
        }
        let output = run(&root, &["doctor", "--format=json"]);
        let doctor = valid(&output, DOCTOR);
        assert_eq!(doctor["data"]["status"], "pass");
        assert_eq!(doctor["data"]["dependency_cache"]["available"], 1);
        fs::remove_dir_all(root.path().join(".sentinel/cache/osv-v1")).unwrap();
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
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(valid(&output, SCAN)["data"]["packages_checked"], 0);
        let output = run(&root, &["doctor", "--format=json"]);
        assert_eq!(
            valid(&output, DOCTOR)["data"]["dependency_cache"]["missing_or_invalid"],
            1
        );
    }
}
