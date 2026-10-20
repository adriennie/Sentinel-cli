use sentinel_scanner::discover;
use std::fs;
use tempfile::TempDir;
const LOCK:&str="version=1\n[[package]]\nname='example'\nversion='2.0'\nsource={registry='https://pypi.org/simple'}\n";
#[test]
fn manifest_lock_reconciliation_retains_unresolved_and_source_gaps() {
    let t = TempDir::new().unwrap();
    fs::write(t.path().join("uv.lock"), LOCK).unwrap();
    fs::write(
        t.path().join("pyproject.toml"),
        "[project]\nname='demo'\ndependencies=['example>=1,<3']\n",
    )
    .unwrap();
    assert!(discover(t.path(), None).diagnostics.is_empty());
    fs::write(
        t.path().join("pyproject.toml"),
        "[project]\nname='demo'\ndependencies=['example>=3']\n",
    )
    .unwrap();
    assert!(discover(t.path(), None)
        .diagnostics
        .iter()
        .any(|d| d.code == "python_manifest_unresolved"));
}
#[test]
fn explicit_uv_workspace_local_members_and_nested_dependencies() {
    let t = TempDir::new().unwrap();
    fs::create_dir_all(t.path().join("packages/member")).unwrap();
    fs::write(t.path().join("pyproject.toml"),"[project]\nname='root'\ndependencies=['member']\n[tool.uv.workspace]\nmembers=['packages/*']\n").unwrap();
    fs::write(
        t.path().join("packages/member/pyproject.toml"),
        "[project]\nname='member'\ndependencies=['example==2.0']\n",
    )
    .unwrap();
    fs::write(t.path().join("uv.lock"),format!("{LOCK}[[package]]\nname='root'\nsource={{virtual='.'}}\n[[package]]\nname='member'\nsource={{editable='packages/member'}}\n")).unwrap();
    let r = discover(t.path(), None);
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    assert_eq!(r.packages.len(), 1);
    fs::write(
        t.path().join("packages/member/pyproject.toml"),
        "[project]\nname='member'\ndependencies=['missing']\n",
    )
    .unwrap();
    assert!(discover(t.path(), None)
        .diagnostics
        .iter()
        .any(|d| d.code == "python_manifest_unresolved"));
}
#[test]
fn unrelated_nested_manifest_does_not_inherit_parent_lock() {
    let t = TempDir::new().unwrap();
    fs::create_dir(t.path().join("nested")).unwrap();
    fs::write(t.path().join("uv.lock"), LOCK).unwrap();
    fs::write(
        t.path().join("nested/pyproject.toml"),
        "[project]\nname='nested'\ndependencies=['example>=1']",
    )
    .unwrap();
    assert!(discover(t.path(), None)
        .diagnostics
        .iter()
        .any(|d| d.code == "python_inventory_partial"));
}
#[test]
fn manifest_only_pins_and_poetry_ranges_are_read_without_execution() {
    let t = TempDir::new().unwrap();
    fs::write(
        t.path().join("pyproject.toml"),
        "[project]\nname='demo'\ndependencies=['example==2.0','unresolved>=1']",
    )
    .unwrap();
    let r = discover(t.path(), None);
    assert_eq!(r.packages.len(), 1);
    assert!(r
        .diagnostics
        .iter()
        .any(|d| d.code == "python_version_unresolved"));
    fs::write(
        t.path().join("poetry.lock"),
        "[[package]]\nname='example'\nversion='2.0'\n[metadata]\nlock-version='2.1'",
    )
    .unwrap();
    fs::write(
        t.path().join("pyproject.toml"),
        "[tool.poetry]\nname='demo'\n[tool.poetry.dependencies]\nexample='^2.0'",
    )
    .unwrap();
    assert!(discover(t.path(), None).diagnostics.is_empty());
}

#[test]
fn custom_sources_and_group_cycles_never_silently_claim_reconciliation() {
    let t = TempDir::new().unwrap();
    fs::write(t.path().join("uv.lock"), LOCK).unwrap();
    fs::write(t.path().join("pyproject.toml"),"[project]\nname='demo'\ndependencies=['example>=1']\n[tool.uv.sources]\nexample={git='https://user:PRIVATE_MARKER@example.test/repo'}\n[dependency-groups]\na=[{include-group='b'}]\nb=[{include-group='a'}]\n").unwrap();
    let r = discover(t.path(), None);
    assert!(r
        .diagnostics
        .iter()
        .any(|d| d.code == "python_source_uncovered"));
    assert!(r
        .diagnostics
        .iter()
        .any(|d| d.code == "python_manifest_unresolved"));
    assert!(!format!("{:?}", r.diagnostics).contains("PRIVATE_MARKER"));
}

#[test]
fn explicit_workspace_sources_are_covered_and_excluded_members_are_not() {
    let t = TempDir::new().unwrap();
    fs::create_dir_all(t.path().join("packages/member")).unwrap();
    fs::write(t.path().join("pyproject.toml"),"[project]\nname='root'\ndependencies=['member']\n[tool.uv.workspace]\nmembers=['packages/*']\n[tool.uv.sources]\nmember={workspace=true}\n").unwrap();
    fs::write(
        t.path().join("packages/member/pyproject.toml"),
        "[project]\nname='member'\ndependencies=['example==2.0']\n",
    )
    .unwrap();
    fs::write(
        t.path().join("uv.lock"),
        format!("{LOCK}[[package]]\nname='member'\nsource={{editable='packages/member'}}\n"),
    )
    .unwrap();
    let r = discover(t.path(), None);
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    let p = t.path().join("pyproject.toml");
    let s = fs::read_to_string(&p).unwrap().replace(
        "members=['packages/*']",
        "members=['packages/*']\nexclude=['packages/member']",
    );
    fs::write(p, s).unwrap();
    assert!(!discover(t.path(), None).diagnostics.is_empty());
}
