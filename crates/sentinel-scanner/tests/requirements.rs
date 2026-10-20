use sentinel_scanner::*;
use std::{fs, path::Path};
use tempfile::TempDir;

fn put(root: &Path, name: &str, content: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}
fn names(inventory: &Inventory) -> Vec<(&str, &str)> {
    inventory
        .packages
        .keys()
        .map(|p| (p.name.as_str(), p.version.as_str()))
        .collect()
}

#[test]
fn pins_extras_hashes_continuations_comments_and_markers() {
    let root = TempDir::new().unwrap();
    put(root.path(), "requirements.txt", &format!(
        "# comment\nExample_Package[security] == 1.2 ; python_version >= '3.9' \\\n --hash=sha256:{} # comment\nother==2.0rc1.post2.dev3\n", "a".repeat(64)));
    let inventory = discover(root.path(), None);
    assert_eq!(
        names(&inventory),
        [("example-package", "1.2"), ("other", "2.0rc1.post2.dev3")]
    );
    assert_eq!(inventory.diagnostics.len(), 1); // Transitive coverage is unknown.
    assert_eq!(inventory.inputs, ["requirements.txt"]);
}

#[test]
fn includes_and_constraints_resolve_only_required_packages() {
    let root = TempDir::new().unwrap();
    put(
        root.path(),
        "requirements.txt",
        "--requirement=requirements/base.txt\n-cconstraints.txt\n",
    );
    put(
        root.path(),
        "requirements/base.txt",
        "Example>=1,<3\nother==4.0\n",
    );
    put(
        root.path(),
        "constraints.txt",
        "example==2.0\nother>=3,<5\nunused==9.0\n",
    );
    let inventory = discover(root.path(), None);
    assert_eq!(names(&inventory), [("example", "2.0"), ("other", "4.0")]);
    let files = inventory
        .packages
        .iter()
        .find(|(p, _)| p.name == "example")
        .unwrap()
        .1;
    assert_eq!(files.len(), 2);
    assert!(files.contains("constraints.txt"));
    assert!(files.contains("requirements/base.txt"));
    assert_eq!(inventory.diagnostics.len(), 1);
    assert_eq!(inventory.inputs.len(), 3);
}

#[test]
fn constraints_never_become_requirements_even_with_discoverable_names() {
    let root = TempDir::new().unwrap();
    put(
        root.path(),
        "requirements.txt",
        "example\n--constraint requirements-pins.txt\n",
    );
    put(
        root.path(),
        "requirements-pins.txt",
        "example==2\nunused==3\n",
    );
    let inventory = discover(root.path(), None);
    assert_eq!(names(&inventory), [("example", "2")]);
}

#[test]
fn unresolved_conflicting_and_conditional_constraints_are_explicit() {
    let root = TempDir::new().unwrap();
    put(
        root.path(),
        "requirements.txt",
        "-c constraints.txt\nconflict==2\nunresolved>=1\nconditional==1\nwildcard==1.*\n",
    );
    put(
        root.path(),
        "constraints.txt",
        "conflict<2\nconditional==1; sys_platform == 'linux'\n",
    );
    let inventory = discover(root.path(), None);
    assert!(inventory.packages.is_empty());
    assert!(inventory
        .diagnostics
        .iter()
        .any(|d| d.message.contains("conflicts")));
    assert_eq!(inventory.diagnostics.len(), 5);
}

#[test]
fn include_source_options_apply_to_the_whole_inventory_without_leaking() {
    for option in [
        "--index-url https://user:credential@example.test/simple",
        "--extra-index-url https://user:credential@example.test/simple",
        "--no-index",
        "--find-links ./wheels",
        "--index-url ${PRIVATE_INDEX}",
    ] {
        let root = TempDir::new().unwrap();
        put(
            root.path(),
            "requirements.txt",
            "public==1\n-r options.txt\n",
        );
        put(root.path(), "options.txt", option);
        let inventory = discover(root.path(), None);
        assert!(inventory.packages.is_empty());
        let rendered = format!("{:?}", inventory.diagnostics);
        assert!(!rendered.contains("credential"));
        assert!(!rendered.contains("PRIVATE_INDEX"));
    }
}

#[test]
fn bad_inputs_in_constraints_cannot_silently_disappear() {
    for line in [
        "example @ https://user:credential@example.test/pkg.whl",
        "example==1 --hash=bad",
        "example==1 ; invalid_marker == 'x'",
        "-e ./local",
    ] {
        let root = TempDir::new().unwrap();
        put(
            root.path(),
            "requirements.txt",
            "example==1\n-c constraints.txt\n",
        );
        put(root.path(), "constraints.txt", line);
        let inventory = discover(root.path(), None);
        assert!(inventory.packages.is_empty(), "{line}");
        assert!(!format!("{:?}", inventory.diagnostics).contains("credential"));
    }
}

#[test]
fn cycles_missing_remote_traversal_and_ignored_includes_are_not_read() {
    for include in [
        "requirements.txt",
        "../outside.txt",
        "/tmp/outside.txt",
        "https://user:credential@example.test/req.txt",
        "missing.txt",
        "ignored.txt",
    ] {
        let root = TempDir::new().unwrap();
        put(
            root.path(),
            "requirements.txt",
            &format!("example==1\n-r {include}\n"),
        );
        put(root.path(), ".gitignore", "ignored.txt\n");
        put(root.path(), "ignored.txt", "ignored==1\n");
        let inventory = discover(root.path(), None);
        assert!(inventory.packages.is_empty());
        assert!(!format!("{:?}", inventory.diagnostics).contains("credential"));
        assert!(!inventory.inputs.iter().any(|p| p == "ignored.txt"));
    }
}

#[cfg(unix)]
#[test]
fn file_and_directory_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    put(outside.path(), "base.txt", "outside==1\n");
    symlink(outside.path(), root.path().join("linked")).unwrap();
    symlink(
        outside.path().join("base.txt"),
        root.path().join("link.txt"),
    )
    .unwrap();
    put(
        root.path(),
        "requirements.txt",
        "example==1\n-r linked/base.txt\n-r link.txt\n",
    );
    let inventory = discover(root.path(), None);
    assert!(inventory.packages.is_empty());
    assert_eq!(inventory.inputs, ["requirements.txt"]);
}

#[test]
fn depth_file_and_line_limits_are_explicit() {
    let root = TempDir::new().unwrap();
    put(root.path(), "requirements.txt", "-r part0.txt\n");
    for i in 0..20 {
        put(
            root.path(),
            &format!("part{i}.txt"),
            &format!("-r part{}.txt\n", i + 1),
        );
    }
    let inventory = discover(root.path(), None);
    assert!(inventory
        .diagnostics
        .iter()
        .any(|d| d.message.contains("budget")));
    assert!(inventory.packages.is_empty());
    let root = TempDir::new().unwrap();
    put(root.path(), "requirements.txt", &"a".repeat(16 * 1024 + 1));
    let inventory = discover(root.path(), None);
    assert!(inventory
        .diagnostics
        .iter()
        .any(|d| d.message.contains("line exceeds")));
    let root = TempDir::new().unwrap();
    put(
        root.path(),
        "requirements.txt",
        &(0..260)
            .map(|i| format!("-r part{i}.txt\n"))
            .collect::<String>(),
    );
    for i in 0..260 {
        put(root.path(), &format!("part{i}.txt"), "example==1\n");
    }
    let inventory = discover(root.path(), None);
    assert!(inventory
        .diagnostics
        .iter()
        .any(|d| d.message.contains("budget")));
    assert!(inventory.inputs.len() <= 256);
    assert!(inventory.packages.is_empty());
}

struct Fake;
impl OsvClient for Fake {
    fn query(&self, package: &Package) -> Result<Vec<Advisory>, ScanError> {
        assert_eq!(package.ecosystem, "PyPI");
        assert_eq!(package.name, "example");
        assert_eq!(package.version, "1.0");
        Ok(vec![Advisory {
            kind: AdvisoryKind::Vulnerability,
            id: "TEST-PY-001".into(),
            severity: Severity::High,
        }])
    }
}
#[test]
fn findings_survive_limited_requirements_coverage_and_offline_cache_reuse() {
    let root = TempDir::new().unwrap();
    put(root.path(), "requirements.txt", "example==1.0\n");
    let result = scan(root.path(), &ScanOptions::default(), &Fake);
    assert_eq!(result.packages_checked, 1);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.exit_code(Severity::High), 7);
    let offline = scan(
        root.path(),
        &ScanOptions {
            offline: true,
            sbom: None,
        },
        &Fake,
    );
    assert_eq!(offline.findings[0].id, result.findings[0].id);
    assert_eq!(offline.cache.len(), 1);
    assert_eq!(offline.exit_code(Severity::High), 7);
}

#[test]
fn nested_constraints_and_independent_inventories_do_not_cross_contaminate() {
    let root = TempDir::new().unwrap();
    put(
        root.path(),
        "first/requirements.txt",
        "example>=1\n--constraint=pins.txt\n",
    );
    put(root.path(), "first/pins.txt", "-c nested.txt\nexample<3\n");
    put(root.path(), "first/nested.txt", "example==2\n");
    put(root.path(), "second/requirements.txt", "example==4\n");
    let inventory = discover(root.path(), None);
    assert_eq!(names(&inventory), [("example", "2"), ("example", "4")]);
    let first = inventory
        .packages
        .iter()
        .find(|(p, _)| p.version == "2")
        .unwrap()
        .1;
    assert_eq!(first.len(), 3);
    let second = inventory
        .packages
        .iter()
        .find(|(p, _)| p.version == "4")
        .unwrap()
        .1;
    assert_eq!(second.len(), 1);
}

#[test]
fn invalid_encoding_unterminated_lines_and_expressions_are_reported() {
    for text in [
        vec![255, 254],
        b"example==1\\".to_vec(),
        format!(
            "example==1; {}python_version == '3'{}",
            "(".repeat(33),
            ")".repeat(33)
        )
        .into_bytes(),
    ] {
        let root = TempDir::new().unwrap();
        fs::write(root.path().join("requirements.txt"), text).unwrap();
        let inventory = discover(root.path(), None);
        assert!(inventory.packages.is_empty());
        assert!(!inventory.diagnostics.is_empty());
    }
}

#[test]
fn repeated_includes_are_deduplicated_and_unsupported_sources_do_not_erase_other_inventories() {
    let root = TempDir::new().unwrap();
    put(
        root.path(),
        "requirements.txt",
        "-r base.txt\n-r base.txt\n",
    );
    put(root.path(), "base.txt", "example==1\n");
    put(
        root.path(),
        "other/requirements.txt",
        "private==1\n--extra-index-url https://user:credential@example.test/simple\n",
    );
    let inventory = discover(root.path(), None);
    assert_eq!(names(&inventory), [("example", "1")]);
    assert_eq!(
        inventory
            .inputs
            .iter()
            .filter(|p| p.as_str() == "base.txt")
            .count(),
        1
    );
    assert!(!format!("{:?}", inventory.diagnostics).contains("credential"));
}
