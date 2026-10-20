use sentinel_scanner::{scan_secrets, Severity};
use std::fs;
use tempfile::tempdir;
fn token() -> String {
    format!("ghp_{}", "A".repeat(36))
}
#[test]
fn detects_supported_credentials_without_retaining_values() {
    let root = tempdir().unwrap();
    let values = [
        token(),
        format!("glpat-{}", "B".repeat(20)),
        format!("xoxb-{}", "C".repeat(30)),
        format!("sk_live_{}", "D".repeat(24)),
        format!("aws_secret_access_key = '{}'", "E".repeat(40)),
        ["-----BEGIN ", "PRIVATE KEY-----"].concat(),
    ];
    fs::write(root.path().join("config.txt"), values.join("\n")).unwrap();
    let report = scan_secrets(root.path(), false);
    assert!(report.complete);
    assert_eq!(report.findings.len(), 6);
    assert_eq!(report.exit_code(Severity::High), 4);
    let json = serde_json::to_string(&report).unwrap();
    for value in &values {
        assert!(!json.contains(value));
    }
    for finding in &report.findings {
        assert!(finding.package.is_none());
        assert_eq!(finding.evidence.redacted, Some("[REDACTED]"));
        assert!(finding.location.is_some());
    }
}
#[test]
fn identities_are_location_based_and_columns_are_utf8_bytes() {
    let root = tempdir().unwrap();
    let path = root.path().join("source.txt");
    fs::write(&path, format!("first\nα {}", token())).unwrap();
    let first = scan_secrets(root.path(), false);
    let finding = &first.findings[0];
    assert_eq!(finding.location.as_ref().unwrap().line, 2);
    assert_eq!(finding.location.as_ref().unwrap().column, 4);
    fs::write(&path, format!("first\nα ghp_{}", "Z".repeat(36))).unwrap();
    assert_eq!(finding.id, scan_secrets(root.path(), false).findings[0].id);
}
#[test]
fn respects_ignores_and_hard_exclusions() {
    let root = tempdir().unwrap();
    fs::write(root.path().join(".gitignore"), "hidden.env\n").unwrap();
    fs::write(root.path().join("hidden.env"), token()).unwrap();
    for directory in [
        ".git",
        ".sentinel",
        "node_modules",
        "target",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
    ] {
        fs::create_dir(root.path().join(directory)).unwrap();
        fs::write(root.path().join(directory).join("secret"), token()).unwrap();
    }
    assert!(scan_secrets(root.path(), false).findings.is_empty());
    assert_eq!(scan_secrets(root.path(), true).findings.len(), 1);
}
#[test]
fn encoding_and_size_gaps_are_not_reported_as_clean() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("binary"), [0, 1, 2]).unwrap();
    assert!(scan_secrets(root.path(), false).complete);
    fs::write(root.path().join("large-binary"), vec![0; 2 * 1024 * 1024]).unwrap();
    assert!(scan_secrets(root.path(), false).complete);
    fs::remove_file(root.path().join("large-binary")).unwrap();
    fs::write(root.path().join("invalid"), [255, 254]).unwrap();
    assert!(!scan_secrets(root.path(), false).complete);
    fs::remove_file(root.path().join("invalid")).unwrap();
    fs::write(root.path().join("large"), vec![b'a'; 1024 * 1024 + 1]).unwrap();
    assert_eq!(
        scan_secrets(root.path(), false).exit_code(Severity::High),
        7
    );
}
#[test]
fn ordinary_text_and_short_placeholders_are_not_findings() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("clean"),
        "password = example\nghp_placeholder\naws_secret_access_key = test\npublic information\n",
    )
    .unwrap();
    let report = scan_secrets(root.path(), false);
    assert!(report.complete);
    assert!(report.findings.is_empty());
}
#[cfg(unix)]
#[test]
fn symlinks_are_outside_coverage() {
    use std::os::unix::fs::symlink;
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("secret"), token()).unwrap();
    symlink(outside.path().join("secret"), root.path().join("link")).unwrap();
    assert!(scan_secrets(root.path(), true).findings.is_empty());
}
