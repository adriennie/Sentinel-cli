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
#[test]
fn python_lockfile_discovery_offline_json_reports_missing_intelligence() {
    let root = TempDir::new().unwrap();
    assert!(run(&root, &["init"]).status.success());
    fs::write(
        root.path().join("uv.lock"),
        r#"
version = 1
revision = 5
[[package]]
name = "Example_Package"
version = "1.2"
source = { registry = "https://pypi.org/simple" }
"#,
    )
    .unwrap();
    let output = run(
        &root,
        &[
            "scan",
            "--type",
            "dependencies",
            "--offline",
            "--format",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["data"]["packages_discovered"], 1);
    assert_eq!(value["data"]["complete"], false);
    assert_eq!(value["data"]["inputs"][0], "uv.lock");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("No supported dependency lockfiles"));
}
#[test]
fn initialization_levels_and_preservation() {
    for level in ["L0", "L1", "L2", "L3"] {
        let root = TempDir::new().unwrap();
        assert!(run(&root, &["init", "--level", level]).status.success());
        let original = fs::read(root.path().join("sentinel.yml")).unwrap();
        assert!(run(&root, &["policy", "check"]).status.success());
        assert_eq!(run(&root, &["init"]).status.code(), Some(3));
        assert_eq!(
            fs::read(root.path().join("sentinel.yml")).unwrap(),
            original
        );
        assert!(run(&root, &["init", "--force"]).status.success());
    }
}
#[test]
fn custom_paths_and_filesystem_errors() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("backend")).unwrap();
    assert!(run(
        &root,
        &["init", "--project", "backend", "--config", "custom.yml"]
    )
    .status
    .success());
    assert!(root.path().join("backend/custom.yml").is_file());
    assert!(run(
        &root,
        &[
            "policy",
            "check",
            "--project",
            "backend",
            "--config",
            "custom.yml"
        ]
    )
    .status
    .success());
    let absolute = root.path().join("absolute.yml");
    assert!(
        run(&root, &["init", "--config", absolute.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        run(&root, &["init", "--config", "missing/policy.yml"])
            .status
            .code(),
        Some(1)
    );
    fs::create_dir(root.path().join("directory.yml")).unwrap();
    assert_eq!(
        run(&root, &["init", "--config", "directory.yml", "--force"])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        run(&root, &["init", "--project", "missing"]).status.code(),
        Some(1)
    );
}
#[test]
fn json_and_diagnostics() {
    let root = TempDir::new().unwrap();
    let out = run(&root, &["--format", "json", "init", "--quiet"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["data"]["level"], "L1");
    assert!(out.stderr.is_empty());
    let out = run(&root, &["policy", "check", "--format=json", "--verbose"]);
    assert!(out.status.success());
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stdout).is_ok());
    assert!(!out.stderr.is_empty());
    fs::write(root.path().join("sentinel.yml"), "invalid: true").unwrap();
    let out = run(&root, &["policy", "check", "--format", "json"]);
    assert_eq!(out.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["error"]["code"], 3);
    assert!(!out.stderr.is_empty());
}
#[test]
fn help_version_and_invalid_arguments() {
    let root = TempDir::new().unwrap();
    for args in [
        &["--help"][..],
        &["init", "--help"],
        &["policy", "check", "--help"],
        &["--version"],
    ] {
        let out = run(&root, args);
        assert!(out.status.success());
        assert!(!out.stdout.is_empty());
        assert!(out.stderr.is_empty());
    }
    for args in [
        &["unknown"][..],
        &["init", "--level", "L9"],
        &["init", "--quiet", "--verbose"],
    ] {
        let out = run(&root, args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    let out = run(&root, &["--format=json", "unknown"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stdout).is_ok());
    assert!(run(&root, &["init", "--quiet", "--no-color"])
        .stdout
        .is_empty());
}

#[test]
fn policy_loading_limits_and_redacted_errors() {
    let root = TempDir::new().unwrap();
    assert!(run(&root, &["init"]).status.success());
    let config = root.path().join("sentinel.yml");
    let base = fs::read_to_string(&config).unwrap();
    let marker = "SYNTHETIC_PRIVATE_VALUE";
    for invalid in [
        base.replace("L1", marker).into_bytes(),
        vec![b' '; 1024 * 1024 + 1],
        vec![0xff, 0xfe],
    ] {
        fs::write(&config, invalid).unwrap();
        let out = run(&root, &["policy", "check", "--format=json"]);
        assert_eq!(out.status.code(), Some(3));
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["error"]["code"], 3);
        for output in [&out.stdout, &out.stderr] {
            assert!(!String::from_utf8_lossy(output).contains(marker));
        }
    }
    let exact = format!("{}{}", base, " ".repeat(1024 * 1024 - base.len()));
    fs::write(&config, exact).unwrap();
    assert!(run(&root, &["policy", "check"]).status.success());
    fs::remove_file(&config).unwrap();
    let out = run(&root, &["policy", "check", "--format=json"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stdout).is_ok());
}

fn seeded_dependencies(root: &TempDir, severity: Option<&str>) {
    use sha2::{Digest, Sha256};
    fs::write(root.path().join("Cargo.lock"), "version = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n").unwrap();
    let directory = root.path().join(".sentinel/cache/osv-v1");
    fs::create_dir_all(&directory).unwrap();
    let key = format!(
        "{:x}",
        Sha256::digest(br#"{"ecosystem":"crates.io","name":"example","version":"1.0.0"}"#)
    );
    let advisories = severity
        .map(|severity| vec![serde_json::json!({"id":"TEST-VULN-001","severity":severity})])
        .unwrap_or_default();
    let data = serde_json::json!({"schema_version":1,"package":{"ecosystem":"crates.io","name":"example","version":"1.0.0"},"fetched_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),"advisories":advisories});
    fs::write(
        directory.join(format!("{key}.json")),
        serde_json::to_vec(&data).unwrap(),
    )
    .unwrap();
}
#[test]
fn dependency_scan_exit_codes_json_and_quiet_findings() {
    let root = TempDir::new().unwrap();
    assert!(run(&root, &["init"]).status.success());
    seeded_dependencies(&root, Some("high"));
    let result = run(
        &root,
        &[
            "scan",
            "--type",
            "dependencies",
            "--offline",
            "--format=json",
        ],
    );
    assert_eq!(result.status.code(), Some(4));
    assert!(result.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["data"]["complete"], true);
    assert_eq!(
        value["data"]["findings"][0]["evidence"]["advisory_id"],
        "TEST-VULN-001"
    );
    assert_eq!(
        run(
            &root,
            &[
                "scan",
                "--type",
                "dependencies",
                "--offline",
                "--fail-on",
                "critical"
            ]
        )
        .status
        .code(),
        Some(0)
    );
    let result = run(
        &root,
        &["scan", "--type", "dependencies", "--offline", "--quiet"],
    );
    assert_eq!(result.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&result.stdout).contains("TEST-VULN-001"));
    seeded_dependencies(&root, Some("unknown"));
    assert_eq!(
        run(
            &root,
            &[
                "scan",
                "--type",
                "dependencies",
                "--offline",
                "--fail-on",
                "critical"
            ]
        )
        .status
        .code(),
        Some(4)
    );
    seeded_dependencies(&root, None);
    assert_eq!(
        run(&root, &["scan", "--type", "dependencies", "--offline"])
            .status
            .code(),
        Some(0)
    );
    fs::write(root.path().join("poetry.lock"), "unsupported").unwrap();
    let result = run(
        &root,
        &[
            "scan",
            "--type",
            "dependencies",
            "--offline",
            "--format=json",
        ],
    );
    assert_eq!(result.status.code(), Some(7));
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["data"]["status"], "incomplete");
    assert_eq!(
        run(&root, &["scan", "--fail-on", "invalid"]).status.code(),
        Some(2)
    );
    let config = fs::read_to_string(root.path().join("sentinel.yml")).unwrap();
    fs::write(
        root.path().join("sentinel.yml"),
        config.replace("dependencies: true", "dependencies: false"),
    )
    .unwrap();
    assert_eq!(
        run(&root, &["scan", "--type", "dependencies", "--offline"])
            .status
            .code(),
        Some(3)
    );
}
#[test]
fn sbom_and_missing_intelligence_cli() {
    let root = TempDir::new().unwrap();
    assert!(run(&root, &["init"]).status.success());
    fs::write(root.path().join("bom.json"), r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"purl":"pkg:pypi/example@1.0.0"}]}"#).unwrap();
    let result = run(
        &root,
        &[
            "scan",
            "--type",
            "dependencies",
            "--sbom",
            "bom.json",
            "--offline",
            "--format=json",
        ],
    );
    assert_eq!(result.status.code(), Some(7));
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["data"]["packages_discovered"], 1);
    let result = run(
        &root,
        &[
            "scan",
            "--sbom",
            "missing.json",
            "--offline",
            "--format=json",
        ],
    );
    assert_eq!(result.status.code(), Some(7));
    assert!(run(&root, &["scan", "--help"]).status.success());
    assert_eq!(
        run(&root, &["scan", "--type", "secrets"]).status.code(),
        Some(0)
    );
}

#[test]
fn poetry_and_requirements_json_findings_audit_and_exit_contracts() {
    use sha2::{Digest, Sha256};
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/command-output.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for requirements in [false, true] {
        let root = TempDir::new().unwrap();
        assert!(run(&root, &["init"]).status.success());
        if requirements {
            fs::write(
                root.path().join("requirements.txt"),
                "-r base.txt\n-c constraints.txt\n",
            )
            .unwrap();
            fs::write(root.path().join("base.txt"), "example>=1\n").unwrap();
            fs::write(root.path().join("constraints.txt"), "example==1.0\n").unwrap();
        } else {
            fs::write(
                root.path().join("poetry.lock"),
                "[[package]]\nname='example'\nversion='1.0'\n[metadata]\nlock-version='2.1'",
            )
            .unwrap();
        }
        let directory = root.path().join(".sentinel/cache/osv-v1");
        fs::create_dir_all(&directory).unwrap();
        let key = format!(
            "{:x}",
            Sha256::digest(br#"{"ecosystem":"PyPI","name":"example","version":"1.0"}"#)
        );
        let value = serde_json::json!({"schema_version":1,"package":{"ecosystem":"PyPI","name":"example","version":"1.0"},"fetched_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),"advisories":[{"id":"TEST-PY-001","severity":"high"}]});
        fs::write(
            directory.join(format!("{key}.json")),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
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
        assert_eq!(output.status.code(), Some(if requirements { 7 } else { 4 }));
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(validator.is_valid(&value));
        assert_eq!(value["data"]["packages_checked"], 1);
        assert_eq!(
            value["data"]["findings"][0]["evidence"]["advisory_id"],
            "TEST-PY-001"
        );
        let text = run(&root, &["scan", "--type", "dependencies", "--offline"]);
        assert!(String::from_utf8_lossy(&text.stdout).contains("TEST-PY-001"));
        assert!(text.stderr.is_empty());
        if requirements {
            fs::write(
                root.path().join("base.txt"),
                "example==1\n--index-url https://user:PRIVATE_TEST_VALUE@example.test/simple\n",
            )
            .unwrap();
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
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(validator.is_valid(&value));
            assert_eq!(value["data"]["packages_discovered"], 0);
            for bytes in [&output.stdout, &output.stderr] {
                assert!(!String::from_utf8_lossy(bytes).contains("PRIVATE_TEST_VALUE"));
            }
            let audit = fs::read_to_string(root.path().join(".sentinel/audit.jsonl")).unwrap();
            assert!(!audit.contains("PRIVATE_TEST_VALUE"));
        }
    }
}
