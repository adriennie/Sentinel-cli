use crate::{bounded_read, digest, Diagnostic, Evidence, Finding, Location, ScanReport, Severity};
use regex::Regex;
use std::{
    path::Path,
    time::{Duration, Instant},
};
const MAX_FILE: u64 = 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;
struct Rule {
    id: &'static str,
    regex: Regex,
    title: &'static str,
}
fn rules() -> Result<Vec<Rule>, regex::Error> {
    [
        (
            "SEC-GITHUB-001",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b",
            "Exposed GitHub token",
        ),
        (
            "SEC-GITLAB-001",
            r"\bglpat-[A-Za-z0-9_-]{20,255}\b",
            "Exposed GitLab token",
        ),
        (
            "SEC-SLACK-001",
            r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b",
            "Exposed Slack token",
        ),
        (
            "SEC-STRIPE-001",
            r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,255}\b",
            "Exposed Stripe live key",
        ),
        (
            "SEC-AWS-001",
            r#"(?i)\baws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}(?:["'\s]|$)"#,
            "Exposed AWS secret access key",
        ),
        (
            "SEC-PEM-001",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            "Exposed private key header",
        ),
    ]
    .into_iter()
    .map(|(id, pattern, title)| {
        Ok(Rule {
            id,
            regex: Regex::new(pattern)?,
            title,
        })
    })
    .collect()
}
fn incomplete(report: &mut ScanReport, file: Option<String>, message: &'static str) {
    report.complete = false;
    report.diagnostics.push(Diagnostic {
        package: None,
        file,
        code: "secrets_coverage",
        message,
    });
}
/// Local pattern detection only. Values never enter findings, IDs, or diagnostics.
pub fn scan_secrets(root: &Path, include_ignored: bool) -> ScanReport {
    let mut report = ScanReport::empty("supported_text_files");
    let rules = match rules() {
        Ok(rules) => rules,
        Err(_) => {
            incomplete(&mut report, None, "Unable to initialize secret rules");
            report.finish();
            return report;
        }
    };
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .max_depth(Some(64));
    if include_ignored {
        builder
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false);
    }
    builder.filter_entry(|entry| {
        !matches!(
            entry.file_name().to_str(),
            Some(
                ".git"
                    | ".sentinel"
                    | "node_modules"
                    | "target"
                    | "vendor"
                    | "dist"
                    | "build"
                    | ".venv"
                    | "venv"
            )
        )
    });
    let start = Instant::now();
    let mut total = 0;
    let mut files = Vec::new();
    for (index, entry) in builder.build().enumerate() {
        if index >= 100_000 || start.elapsed() >= Duration::from_secs(120) {
            incomplete(&mut report, None, "Secrets discovery budget exceeded");
            break;
        }
        match entry {
            Ok(entry) => {
                if entry.file_type().is_some_and(|kind| kind.is_dir()) && entry.depth() >= 64 {
                    incomplete(&mut report, None, "Secrets discovery depth limit reached");
                }
                if entry.file_type().is_some_and(|kind| kind.is_file()) {
                    files.push(entry.into_path());
                }
            }
            Err(_) => incomplete(&mut report, None, "Unable to inspect a project entry"),
        }
    }
    files.sort();
    if files.len() > 10_000 {
        files.truncate(10_000);
        incomplete(&mut report, None, "Secrets file count limit exceeded");
    }
    'files: for path in files {
        if start.elapsed() >= Duration::from_secs(120) {
            incomplete(&mut report, None, "Secrets scan time budget exceeded");
            break;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let mut safe_file = relative.clone();
        for rule in &rules {
            safe_file = rule
                .regex
                .replace_all(&safe_file, "[REDACTED]")
                .into_owned();
        }
        let safe_file = safe_file
            .chars()
            .flat_map(char::escape_default)
            .collect::<String>();
        let bytes = match bounded_read(&path, MAX_FILE) {
            Ok(bytes) => bytes,
            Err(error) => {
                incomplete(&mut report, Some(safe_file), error.0);
                continue;
            }
        };
        total += bytes.len() as u64;
        if total > MAX_TOTAL {
            incomplete(&mut report, None, "Secrets content budget exceeded");
            break;
        }
        if bytes.iter().take(8192).any(|byte| *byte == 0) {
            continue;
        }
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                incomplete(
                    &mut report,
                    Some(safe_file),
                    "Non-UTF-8 text is not supported",
                );
                continue;
            }
        };
        report.files_checked += 1;
        report.inputs.push(safe_file.clone());
        let lines: Vec<usize> = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        for rule in &rules {
            for matched in rule.regex.find_iter(text) {
                if start.elapsed() >= Duration::from_secs(120) {
                    incomplete(&mut report, None, "Secrets scan time budget exceeded");
                    break 'files;
                }
                if report.findings.len() >= 100_000 {
                    incomplete(&mut report, None, "Secrets finding limit exceeded");
                    break 'files;
                }
                let line_index = lines.partition_point(|offset| *offset <= matched.start()) - 1;
                let line = line_index + 1;
                let column = matched.start() - lines[line_index] + 1;
                // Identity uses only rule and location; no secret contents or hashes.
                let id =
                    digest(format!("{}\0{}\0{}\0{}", rule.id, safe_file, line, column).as_bytes());
                report.findings.push(Finding { schema_version: 1, id, rule_id: rule.id, category: "secret", severity: Severity::High,
                    title: rule.title, package: None, location: Some(Location { file: safe_file.clone(), line, column }), files: vec![safe_file.clone()],
                    evidence: Evidence { source: "Sentinel",
                        advisory_kind: None, advisory_id: None, redacted: Some("[REDACTED]") },
                    remediation: "Revoke or rotate the credential, remove it from source and history, and use a secret store.", reachability: "not_analyzed" });
            }
        }
    }
    report.findings.sort_by(|a, b| a.id.cmp(&b.id));
    report.finish();
    report
}
