use sentinel_scanner::discover;
use std::fs;
use tempfile::TempDir;

fn inventory(text: &str) -> sentinel_scanner::Inventory {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("uv.lock"), text).unwrap();
    discover(dir.path(), None)
}

#[test]
fn uv_discovers_normalized_public_identities_and_preserves_python_versions() {
    let result = inventory(
        r#"
version = 1
revision = 5
[[package]]
name = "Example_Package"
version = "1!2.0rc1.post2.dev3+local.1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "example.package"
version = "1!2.0rc1.post2.dev3+local.1"
source = { registry = "https://pypi.org/simple/" }
"#,
    );
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.inputs, ["uv.lock"]);
    assert_eq!(result.packages.len(), 1);
    let package = result.packages.keys().next().unwrap();
    assert_eq!(package.ecosystem, "PyPI");
    assert_eq!(package.name, "example-package");
    assert_eq!(package.version, "1!2.0rc1.post2.dev3+local.1");
}

#[test]
fn uv_rejects_schemas_and_sanitizes_parser_errors() {
    for text in [
        "version = 2\npackage = []",
        "version = 1\nrevision = 6\npackage = []",
        "credential = secret-value",
    ] {
        let result = inventory(text);
        assert!(!result.diagnostics.is_empty());
        assert!(result.packages.is_empty());
        assert!(!format!("{:?}", result.diagnostics).contains("secret-value"));
    }
}

#[test]
fn uv_retains_public_packages_while_reporting_uncovered_sources_and_bad_versions() {
    let result = inventory(
        r#"
version = 1
[[package]]
name = "public"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "private"
version = "1.0"
source = { registry = "https://user:secret@example.test/simple" }
[[package]]
name = "local"
source = { editable = "." }
[[package]]
name = "invalid"
version = "1garbage"
source = { registry = "https://pypi.org/simple" }
"#,
    );
    assert_eq!(result.packages.len(), 1);
    assert_eq!(result.diagnostics.len(), 3);
    assert!(!format!("{:?}", result.diagnostics).contains("secret"));
}

#[test]
fn manifest_reconciliation_is_not_silently_claimed() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("uv.lock"), "version = 1\npackage = []").unwrap();
    fs::write(dir.path().join("pyproject.toml"), "[project]\nname='demo'").unwrap();
    let result = discover(dir.path(), None);
    assert!(!result.diagnostics.is_empty());
}

#[test]
fn poetry_versions_groups_and_platform_alternatives_are_inventoried() {
    for version in ["1.1", "2.0", "2.1"] {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("poetry.lock"),
            format!(
                r#"
[[package]]
name = "Example_Package"
version = "1.0rc1"
groups = ["dev"]
markers = "sys_platform == 'linux'"
[[package]]
name = "example.package"
version = "2.0"
optional = true
[package.source]
type = "legacy"
url = "https://pypi.org/simple/"
reference = "pypi"
[metadata]
lock-version = "{version}"
"#
            ),
        )
        .unwrap();
        let result = discover(dir.path(), None);
        assert!(result.diagnostics.is_empty());
        assert_eq!(result.inputs, ["poetry.lock"]);
        assert_eq!(result.packages.len(), 2);
        assert!(result
            .packages
            .keys()
            .all(|p| p.name == "example-package" && p.ecosystem == "PyPI"));
    }
}

#[test]
fn poetry_sources_fail_closed_and_do_not_leak_credentials() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("poetry.lock"),
        r#"
[[package]]
name = "public"
version = "1.0"
[[package]]
name = "private"
version = "2.0"
source = { type = "legacy", url = "https://user:credential@example.test/simple" }
[[package]]
name = "git"
version = "2.0"
source = { type = "git", url = "https://example.test/repo" }
[[package]]
name = "malformed"
version = "2.0"
source = "credential"
[[package]]
name = "missing"
[[package]]
name = "invalid"
version = "1.*"
[metadata]
lock-version = "2.1"
"#,
    )
    .unwrap();
    let result = discover(dir.path(), None);
    assert_eq!(result.packages.len(), 1);
    assert_eq!(result.diagnostics.len(), 5);
    assert!(!format!("{:?}", result.diagnostics).contains("credential"));
}

#[test]
fn poetry_rejects_unknown_schemas_and_malformed_metadata() {
    for text in [
        "package = []\n[metadata]\nlock-version = '3.0'",
        "package = []\n[metadata]\nlock-version = '2.2'",
        "package = []",
        "credential = '",
    ] {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("poetry.lock"), text).unwrap();
        let result = discover(dir.path(), None);
        assert!(!result.diagnostics.is_empty());
        assert!(result.packages.is_empty());
        assert!(!format!("{:?}", result.diagnostics).contains("credential"));
    }
}

#[test]
fn competing_python_locks_retain_locations_and_report_ambiguity() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("uv.lock"), "version = 1\n[[package]]\nname='example'\nversion='1.0'\nsource={ registry='https://pypi.org/simple' }").unwrap();
    fs::write(
        dir.path().join("poetry.lock"),
        "[[package]]\nname='example'\nversion='1.0'\n[metadata]\nlock-version='2.1'",
    )
    .unwrap();
    let result = discover(dir.path(), None);
    assert_eq!(result.packages.len(), 1);
    assert_eq!(result.packages.values().next().unwrap().len(), 2);
    assert!(result
        .diagnostics
        .iter()
        .any(|d| d.code == "python_lock_conflict"));
}
