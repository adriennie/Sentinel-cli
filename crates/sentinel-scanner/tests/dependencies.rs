use sentinel_scanner::*;
use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
const CARGO: &str = r#"
version = 4
[[package]]
name = "workspace"
version = "0.1.0"
[[package]]
name = "example"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
const NPM: &str = r#"{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/example":{"version":"1.0.0","resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"},"node_modules/nested/node_modules/example":{"version":"1.0.0"},"node_modules/@scope/pkg":{"version":"2.0.0"},"node_modules/alias":{"name":"original","version":"1.0.0"}}}"#;
struct Fake {
    calls: AtomicUsize,
    fail: bool,
    vulnerable: bool,
}
impl Fake {
    fn new(vulnerable: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            fail: false,
            vulnerable,
        }
    }
}
impl OsvClient for Fake {
    fn query(&self, _: &Package) -> Result<Vec<Advisory>, ScanError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(ScanError("Synthetic API failure"));
        }
        Ok(if self.vulnerable {
            vec![Advisory {
                kind: AdvisoryKind::Vulnerability,
                id: "TEST-VULN-001".into(),
                severity: Severity::High,
            }]
        } else {
            vec![]
        })
    }
}
#[test]
fn exact_resolved_packages_and_deduplication() {
    let mut inventory = Inventory::default();
    parse_cargo(CARGO.as_bytes(), "Cargo.lock", &mut inventory).unwrap();
    for version in [2, 3] {
        parse_npm(
            NPM.replace(
                "\"lockfileVersion\":3",
                &format!("\"lockfileVersion\":{version}"),
            )
            .as_bytes(),
            "package-lock.json",
            &mut inventory,
        )
        .unwrap();
    }
    assert_eq!(inventory.packages.len(), 4);
    assert!(inventory
        .packages
        .keys()
        .any(|p| p.name == "@scope/pkg" && p.version == "2.0.0"));
    assert!(inventory.packages.keys().any(|p| p.name == "original"));
    assert!(inventory.diagnostics.is_empty());
}
#[test]
fn malformed_or_unsupported_inputs_are_errors() {
    for input in [
        r#"{"lockfileVersion":1,"packages":{}}"#,
        r#"{"lockfileVersion":3}"#,
        r#"{"lockfileVersion":3,"packages":{"node_modules/a":{}}}"#,
        "not json",
    ] {
        assert!(parse_npm(input.as_bytes(), "file", &mut Inventory::default()).is_err());
    }
    assert!(parse_cargo(
        b"version = 99\npackage = []",
        "file",
        &mut Inventory::default()
    )
    .is_err());
    let mut inventory = Inventory::default();
    parse_cargo(
        CARGO
            .replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                "git+https://example.invalid/repo",
            )
            .as_bytes(),
        "file",
        &mut inventory,
    )
    .unwrap();
    assert_eq!(inventory.diagnostics.len(), 1);
}
#[test]
fn language_independent_sbom_identities() {
    let mut inventory = Inventory::default();
    let bom = serde_json::json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[
        {"purl":"pkg:pypi/django@4.2.0"}, {"purl":"pkg:maven/org.example/library@1.0.0"},
        {"purl":"pkg:golang/example.com/module@v1.2.3"}, {"purl":"pkg:nuget/Example@1.0.0"},
        {"purl":"pkg:npm/%40scope/pkg@2.0.0"}, {"purl":"pkg:gem/rack@2.0.0"},
        {"purl":"pkg:composer/vendor/package@1.0.0"}
    ]});
    parse_sbom(&serde_json::to_vec(&bom).unwrap(), "bom", &mut inventory).unwrap();
    assert_eq!(inventory.packages.len(), 7);
    assert!(inventory
        .packages
        .keys()
        .any(|p| p.ecosystem == "Maven" && p.name == "org.example:library"));
    assert!(inventory
        .packages
        .keys()
        .any(|p| p.ecosystem == "npm" && p.name == "@scope/pkg"));
    assert!(inventory.diagnostics.is_empty());
    for component in [
        serde_json::json!({"purl":"pkg:pypi/django"}),
        serde_json::json!({"name":"missing"}),
        serde_json::json!({"purl":"pkg:generic/thing@1"}),
    ] {
        let bom = serde_json::json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[component]});
        let mut partial = Inventory::default();
        parse_sbom(&serde_json::to_vec(&bom).unwrap(), "bom", &mut partial).unwrap();
        assert!(!partial.diagnostics.is_empty());
    }
}
#[test]
fn vulnerable_clean_offline_and_unavailable_scans() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("Cargo.lock"), CARGO).unwrap();
    let client = Fake::new(true);
    let result = scan(root.path(), &ScanOptions::default(), &client);
    assert!(result.complete);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.exit_code(Severity::High), 4);
    assert_eq!(result.exit_code(Severity::Critical), 0);
    assert_eq!(result.findings[0].reachability, "not_analyzed");
    let offline = scan(
        root.path(),
        &ScanOptions {
            offline: true,
            sbom: None,
        },
        &client,
    );
    assert!(offline.complete);
    assert_eq!(offline.findings[0].id, result.findings[0].id);
    assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    assert_eq!(offline.cache.len(), 1);
    let clean_root = TempDir::new().unwrap();
    fs::write(clean_root.path().join("Cargo.lock"), CARGO).unwrap();
    let clean = scan(
        clean_root.path(),
        &ScanOptions::default(),
        &Fake::new(false),
    );
    assert_eq!(clean.exit_code(Severity::Low), 0);
    assert!(clean.findings.is_empty());
    let missing = TempDir::new().unwrap();
    fs::write(missing.path().join("Cargo.lock"), CARGO).unwrap();
    let result = scan(
        missing.path(),
        &ScanOptions {
            offline: true,
            sbom: None,
        },
        &client,
    );
    assert_eq!(result.exit_code(Severity::High), 7);
    assert_eq!(result.packages_checked, 0);
    let failed = scan(
        missing.path(),
        &ScanOptions::default(),
        &Fake {
            fail: true,
            ..Fake::new(false)
        },
    );
    assert_eq!(failed.exit_code(Severity::High), 7);
}
#[test]
fn stale_corrupt_and_future_cache_never_report_clean() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("Cargo.lock"), CARGO).unwrap();
    let client = Fake::new(true);
    assert!(scan(root.path(), &ScanOptions::default(), &client).complete);
    let path = fs::read_dir(root.path().join(".sentinel/cache/osv-v1"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut stale = original.clone();
    stale["fetched_at"] = serde_json::json!(1);
    fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
    let result = scan(
        root.path(),
        &ScanOptions {
            offline: true,
            sbom: None,
        },
        &client,
    );
    assert_eq!(result.exit_code(Severity::High), 7);
    assert_eq!(result.findings.len(), 1);
    assert!(result.cache[0].stale);
    let result = scan(
        root.path(),
        &ScanOptions::default(),
        &Fake {
            fail: true,
            ..Fake::new(false)
        },
    );
    assert_eq!(result.exit_code(Severity::High), 7);
    assert_eq!(result.findings.len(), 1);
    stale["fetched_at"] = serde_json::json!(u64::MAX);
    fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
    assert_eq!(
        scan(
            root.path(),
            &ScanOptions {
                offline: true,
                sbom: None
            },
            &client
        )
        .packages_checked,
        0
    );
    fs::write(path, b"malformed").unwrap();
    assert!(
        !scan(
            root.path(),
            &ScanOptions {
                offline: true,
                sbom: None
            },
            &client
        )
        .complete
    );
}
#[test]
fn monorepos_exclusions_and_unknown_projects() {
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("services/api")).unwrap();
    fs::create_dir(root.path().join("vendor")).unwrap();
    fs::write(root.path().join("services/api/Cargo.lock"), CARGO).unwrap();
    fs::write(root.path().join("vendor/poetry.lock"), "ignored").unwrap();
    let client = Fake::new(false);
    assert!(scan(root.path(), &ScanOptions::default(), &client).complete);
    fs::write(root.path().join("requirements.txt"), "example==1").unwrap();
    let result = scan(root.path(), &ScanOptions::default(), &client);
    assert_eq!(result.exit_code(Severity::High), 7);
    let empty = TempDir::new().unwrap();
    assert!(!scan(empty.path(), &ScanOptions::default(), &client).complete);
    fs::write(empty.path().join("Cargo.toml"), "[package]").unwrap();
    assert!(!scan(empty.path(), &ScanOptions::default(), &client).complete);
}
#[test]
fn unknown_severity_cannot_evade_thresholds() {
    assert!(Severity::Unknown.exceeds(Severity::Critical));
    assert!(!Severity::Low.exceeds(Severity::High));
}
#[cfg(unix)]
#[test]
fn symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("Cargo.lock"), CARGO).unwrap();
    symlink(
        outside.path().join("Cargo.lock"),
        root.path().join("Cargo.lock"),
    )
    .unwrap();
    assert!(!scan(root.path(), &ScanOptions::default(), &Fake::new(false)).complete);
    fs::remove_file(root.path().join("Cargo.lock")).unwrap();
    fs::write(root.path().join("Cargo.lock"), CARGO).unwrap();
    symlink(outside.path(), root.path().join(".sentinel")).unwrap();
    let result = scan(root.path(), &ScanOptions::default(), &Fake::new(false));
    assert!(!result.complete);
    assert!(!outside.path().join("cache").exists());
}

#[test]
fn npm_workspaces_and_registry_alias_names() {
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(root.path().join("package.json"), "{}").unwrap();
    fs::write(root.path().join("packages/app/package.json"), "{}").unwrap();
    fs::write(root.path().join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"":{},"packages/app":{"name":"app","version":"1.0.0"},"node_modules/alias":{"version":"1.0.0","resolved":"https://registry.npmjs.org/original/-/original-1.0.0.tgz"}}}"#).unwrap();
    let inventory = discover(root.path(), None);
    assert!(inventory.diagnostics.is_empty());
    assert_eq!(inventory.packages.keys().next().unwrap().name, "original");
}
#[test]
fn sbom_children_of_unsupported_components_are_preserved() {
    for version in ["1.4", "1.5", "1.6", "1.7"] {
        let value = serde_json::json!({"bomFormat":"CycloneDX","specVersion":version,"components":[{"purl":"pkg:generic/unsupported@1","components":[{"purl":"pkg:pypi/django@4.2.0"}]}]});
        let mut inventory = Inventory::default();
        parse_sbom(&serde_json::to_vec(&value).unwrap(), "bom", &mut inventory).unwrap();
        assert_eq!(inventory.packages.len(), 1);
        assert_eq!(inventory.diagnostics.len(), 1);
    }
}
#[test]
fn unresolved_versions_and_oversized_inputs_are_rejected() {
    for version in ["1.*", "1.0", "1.0.0 || 2.0.0", "1.0.0-secret\nvalue"] {
        let package = Package {
            ecosystem: "npm".into(),
            name: "example".into(),
            version: version.into(),
        };
        assert!(package.validate().is_err());
    }
    let large = vec![b' '; MAX_INPUT_BYTES as usize + 1];
    assert!(parse_cargo(&large, "file", &mut Inventory::default()).is_err());
    assert!(parse_npm(&large, "file", &mut Inventory::default()).is_err());
    assert!(parse_sbom(&large, "file", &mut Inventory::default()).is_err());
}

#[test]
fn discovery_lockfile_limit_is_reported() {
    let root = TempDir::new().unwrap();
    for index in 0..257 {
        let path = root.path().join(format!("project-{index:03}"));
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{}}"#,
        )
        .unwrap();
    }
    let inventory = discover(root.path(), None);
    assert_eq!(inventory.inputs.len(), 256);
    assert!(inventory
        .diagnostics
        .iter()
        .any(|d| d.message.contains("Lockfile limit")));
}

#[test]
fn external_or_unrepresented_npm_links_are_incomplete() {
    for target in ["../outside", "missing"] {
        let value = serde_json::json!({"lockfileVersion":3,"packages":{"":{},"node_modules/local":{"link":true,"resolved":target}}});
        let mut inventory = Inventory::default();
        parse_npm(&serde_json::to_vec(&value).unwrap(), "lock", &mut inventory).unwrap();
        assert!(!inventory.diagnostics.is_empty());
    }
}
