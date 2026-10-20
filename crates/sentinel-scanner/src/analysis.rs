//! Version-2 optional analyses. No executable project code, no negative reachability claims.
use crate::{bounded_read, digest, Finding, ScanError, ScanReport};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[derive(Default)]
pub struct AnalysisOptions {
    pub reachability: bool,
    pub exploit_aware: bool,
    pub offline: bool,
    pub entrypoints: Vec<PathBuf>,
    pub python_imports: BTreeMap<String, String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Epss {
    pub probability: f64,
    pub date: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Kev {
    pub date: String,
    pub cves: BTreeSet<String>,
}
pub trait ExploitClient {
    fn aliases(&self, id: &str) -> Result<Vec<String>, ScanError>;
    fn epss(&self, cve: &str) -> Result<Epss, ScanError>;
    fn kev(&self) -> Result<Kev, ScanError>;
}
pub struct HttpExploit {
    client: reqwest::blocking::Client,
}
impl HttpExploit {
    pub fn new() -> Result<Self, ScanError> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| ScanError("Unable to initialize exploit-intelligence client"))?,
        })
    }
    fn get(&self, url: &str) -> Result<serde_json::Value, ScanError> {
        let response = self
            .client
            .get(url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| ScanError("Exploit-intelligence source unavailable"))?;
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ScanError("Unable to read exploit-intelligence response"))?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(ScanError("Exploit-intelligence response exceeds limit"));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| ScanError("Malformed exploit-intelligence response"))
    }
}
pub fn cve(value: &str) -> bool {
    let p: Vec<_> = value.split('-').collect();
    p.len() == 3
        && p[0] == "CVE"
        && p[1].len() == 4
        && p[1].bytes().all(|b| b.is_ascii_digit())
        && p[2].len() >= 4
        && p[2].len() <= 12
        && p[2].bytes().all(|b| b.is_ascii_digit())
}
impl ExploitClient for HttpExploit {
    fn aliases(&self, id: &str) -> Result<Vec<String>, ScanError> {
        if cve(id) {
            return Ok(vec![id.into()]);
        }
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        {
            return Err(ScanError("Invalid advisory identity"));
        }
        let v = self.get(&format!("https://api.osv.dev/v1/vulns/{id}"))?;
        if v.get("id").and_then(serde_json::Value::as_str) != Some(id) {
            return Err(ScanError("Advisory alias identity mismatch"));
        }
        let a = v
            .get("aliases")
            .and_then(serde_json::Value::as_array)
            .ok_or(ScanError("Advisory has no alias inventory"))?;
        if a.len() > 256 {
            return Err(ScanError("Advisory alias limit exceeded"));
        }
        Ok(a.iter()
            .filter_map(|v| v.as_str())
            .filter(|s| cve(s))
            .map(str::to_owned)
            .collect())
    }
    fn epss(&self, id: &str) -> Result<Epss, ScanError> {
        if !cve(id) {
            return Err(ScanError("Invalid CVE identity"));
        }
        let v = self.get(&format!("https://api.first.org/data/v1/epss?cve={id}"))?;
        let a = v
            .get("data")
            .and_then(serde_json::Value::as_array)
            .ok_or(ScanError("Malformed EPSS response"))?;
        if a.len() != 1 || a[0].get("cve").and_then(serde_json::Value::as_str) != Some(id) {
            return Err(ScanError("EPSS identity missing or mismatched"));
        }
        let probability = a[0]
            .get("epss")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
            .ok_or(ScanError("Invalid EPSS score"))?;
        let date = a[0]
            .get("date")
            .and_then(serde_json::Value::as_str)
            .ok_or(ScanError("EPSS source date missing"))?
            .to_owned();
        Ok(Epss { probability, date })
    }
    fn kev(&self) -> Result<Kev, ScanError> {
        let v = self.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )?;
        let date = v
            .get("dateReleased")
            .and_then(serde_json::Value::as_str)
            .ok_or(ScanError("KEV source date missing"))?
            .to_owned();
        let entries = v
            .get("vulnerabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or(ScanError("KEV inventory missing"))?;
        if entries.len() > 50_000
            || v.get("count").and_then(serde_json::Value::as_u64) != Some(entries.len() as u64)
        {
            return Err(ScanError("KEV inventory count invalid"));
        }
        let mut cves = BTreeSet::new();
        for e in entries {
            let s = e
                .get("cveID")
                .and_then(serde_json::Value::as_str)
                .filter(|s| cve(s))
                .ok_or(ScanError("Invalid KEV CVE"))?;
            cves.insert(s.into());
        }
        Ok(Kev { date, cves })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached<T> {
    schema_version: u32,
    key: String,
    fetched_at: u64,
    value: T,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn cache_dir(root: &Path) -> Result<PathBuf, ScanError> {
    let parent = sentinel_audit::storage_directory(root, &[".sentinel", "cache", "osv-v1"])
        .map_err(|_| ScanError("Intelligence cache directory is unsafe"))?;
    let p = parent.join("intelligence-v2");
    match std::fs::create_dir(&p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        _ => return Err(ScanError("Unable to create intelligence cache")),
    };
    if !p.symlink_metadata().is_ok_and(|m| m.is_dir()) {
        return Err(ScanError("Intelligence cache is a symlink or file"));
    }
    Ok(p)
}
fn cached<T: Serialize + serde::de::DeserializeOwned>(
    root: &Path,
    key: &str,
    offline: bool,
    fetch: impl FnOnce() -> Result<T, ScanError>,
) -> (Option<T>, &'static str) {
    let path = match cache_dir(root) {
        Ok(p) => p.join(format!("{}.json", digest(key.as_bytes()))),
        Err(_) => return (None, "unavailable"),
    };
    let old = bounded_read(&path, 16 * 1024 * 1024)
        .ok()
        .and_then(|b| serde_json::from_slice::<Cached<T>>(&b).ok())
        .filter(|c| c.schema_version == 2 && c.key == key && c.fetched_at <= now());
    if old.as_ref().is_some_and(|c| now() - c.fetched_at <= 86400) {
        return (old.map(|c| c.value), "fresh");
    }
    if !offline {
        if let Ok(value) = fetch() {
            let record = Cached {
                schema_version: 2,
                key: key.into(),
                fetched_at: now(),
                value,
            };
            let saved = (|| {
                let mut t =
                    tempfile::NamedTempFile::new_in(path.parent().ok_or(())?).map_err(|_| ())?;
                serde_json::to_writer(t.as_file_mut(), &record).map_err(|_| ())?;
                t.flush().map_err(|_| ())?;
                t.as_file().sync_all().map_err(|_| ())?;
                t.persist(&path).map_err(|_| ())?;
                Ok::<(), ()>(())
            })();
            return (
                Some(record.value),
                if saved.is_ok() {
                    "fresh"
                } else {
                    "cache_write_failed"
                },
            );
        }
    }
    (old.map(|c| c.value), "stale_or_unavailable")
}
fn source_date(date: &str, epss: bool) -> bool {
    let stamp = if epss {
        let Ok(f) = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]") else {
            return false;
        };
        time::Date::parse(date, &f)
            .ok()
            .map(|d| d.midnight().assume_utc().unix_timestamp())
    } else {
        time::OffsetDateTime::parse(date, &time::format_description::well_known::Rfc3339)
            .ok()
            .map(|d| d.unix_timestamp())
    };
    stamp.is_some_and(|s| {
        s >= 0
            && (s as u64) <= now()
            && now() - (s as u64) <= if epss { 2 * 86400 } else { 7 * 86400 }
    })
}
#[derive(Debug, Serialize)]
pub struct AnalysisFinding {
    pub finding_id: String,
    pub reachability: &'static str,
    pub reachability_reason: &'static str,
    pub cves: Vec<String>,
    pub epss: Option<f64>,
    pub epss_source_dates: Vec<String>,
    pub kev: Option<bool>,
    pub kev_source_date: Option<String>,
    pub intelligence_status: &'static str,
    pub risk_score: u8,
}
#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub complete: bool,
    pub scope: &'static str,
    pub findings: Vec<AnalysisFinding>,
    pub diagnostics: Vec<&'static str>,
}
pub fn analyze(
    root: &Path,
    report: &ScanReport,
    options: &AnalysisOptions,
    client: &impl ExploitClient,
) -> AnalysisReport {
    let mut result=AnalysisReport{schema_version:2,complete:true,scope:"Python explicit import mappings and selected entrypoint text; not function-level vulnerability reachability",findings:Vec::new(),diagnostics:Vec::new()};
    let kev = if options.exploit_aware {
        let (data, status) = cached(root, "cisa-kev", options.offline, || client.kev());
        (data, status)
    } else {
        (None, "not_requested")
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    for finding in &report.findings {
        if result.findings.len() >= 1000 {
            result.complete = false;
            result.diagnostics.push("Analysis limited to 1000 findings");
            break;
        }
        let (reachability, reason) = if options.reachability {
            reachability(root, finding, options)
        } else {
            ("not_analyzed", "Reachability was not requested")
        };
        let mut record = AnalysisFinding {
            finding_id: finding.id.clone(),
            reachability,
            reachability_reason: reason,
            cves: Vec::new(),
            epss: None,
            epss_source_dates: Vec::new(),
            kev: None,
            kev_source_date: kev.0.as_ref().map(|k| k.date.clone()),
            intelligence_status: if options.exploit_aware {
                "unavailable"
            } else {
                "not_requested"
            },
            risk_score: if reachability == "reachable" {
                2
            } else if reachability == "unknown" {
                1
            } else {
                0
            },
        };
        if reachability == "unknown" {
            result.complete = false;
        }
        if options.exploit_aware {
            if let Some(id) = &finding.evidence.advisory_id {
                if std::time::Instant::now() >= deadline {
                    result.complete = false;
                    result
                        .diagnostics
                        .push("Exploit intelligence query budget exhausted");
                    result.findings.push(record);
                    continue;
                }
                let (aliases, alias_status) =
                    cached(root, &format!("aliases:{id}"), options.offline, || {
                        client.aliases(id)
                    });
                if let Some(cves) = aliases.filter(|a| a.len() <= 256 && a.iter().all(|s| cve(s))) {
                    record.cves = cves;
                }
                let mut fresh = alias_status == "fresh"
                    && !record.cves.is_empty()
                    && kev.1 == "fresh"
                    && kev.0.as_ref().is_some_and(|k| source_date(&k.date, false));
                if !record.cves.is_empty() {
                    record.kev = kev
                        .0
                        .as_ref()
                        .filter(|k| source_date(&k.date, false))
                        .map(|k| record.cves.iter().any(|c| k.cves.contains(c)));
                }
                for id in record.cves.iter().take(32) {
                    if std::time::Instant::now() >= deadline {
                        fresh = false;
                        break;
                    }
                    let (epss, status) =
                        cached(root, &format!("epss:{id}"), options.offline, || {
                            client.epss(id)
                        });
                    if let Some(value) = epss.filter(|e| {
                        e.probability.is_finite() && (0.0..=1.0).contains(&e.probability)
                    }) {
                        fresh &= status == "fresh" && source_date(&value.date, true);
                        record.epss = Some(record.epss.unwrap_or(0.0).max(value.probability));
                        record.epss_source_dates.push(value.date);
                    } else {
                        fresh = false
                    }
                }
                if record.cves.len() > 32 {
                    fresh = false
                }
                record.intelligence_status = if fresh {
                    "fresh"
                } else {
                    "missing_stale_or_unmapped"
                };
                if !fresh {
                    result.complete = false
                }
                if record.kev == Some(true) {
                    record.risk_score = record.risk_score.saturating_add(3)
                }
                if record.epss.is_some_and(|p| p >= 0.5) {
                    record.risk_score = record.risk_score.saturating_add(2)
                }
            } else {
                record.intelligence_status = "not_applicable_no_advisory"
            }
        }
        record.risk_score = sentinel_policy::risk_score(&sentinel_policy::RiskEvidence {
            secret_access: finding.package.is_none(),
            reachable_dependency: record.reachability == "reachable",
            known_exploitation: record.kev == Some(true),
            high_epss: record.epss.is_some_and(|p| p >= 0.5),
            uncertain: record.reachability == "unknown"
                || (options.exploit_aware
                    && record.intelligence_status != "fresh"
                    && record.intelligence_status != "not_applicable_no_advisory"),
            ..Default::default()
        });
        result.findings.push(record);
    }
    result
}
fn reachability(
    root: &Path,
    finding: &Finding,
    options: &AnalysisOptions,
) -> (&'static str, &'static str) {
    let Some(package) = &finding.package else {
        return (
            "not_analyzed",
            "Secret finding has no dependency import identity",
        );
    };
    if package.ecosystem != "PyPI" {
        return ("unknown", "Reachability prototype supports only Python");
    }
    let Some(module) = options.python_imports.get(&package.name) else {
        return (
            "unknown",
            "An explicit distribution-to-import mapping is required",
        );
    };
    if module.is_empty()
        || !module
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
    {
        return ("unknown", "Python import mapping is invalid");
    }
    if options.entrypoints.is_empty() || options.entrypoints.len() > 32 {
        return (
            "unknown",
            "Select 1–32 Python entrypoints with --entrypoint",
        );
    }
    let mut uncertain = false;
    let mut seen = BTreeSet::new();
    let mut pending = options.entrypoints.clone();
    while let Some(path) = pending.pop() {
        if seen.len() >= 256 {
            return ("unknown", "Python import graph exceeds 256 modules");
        }
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return (
                "unknown",
                "Python entrypoints must be safe project-relative paths",
            );
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        let mut cursor = root.to_path_buf();
        for c in path.components() {
            cursor.push(c);
            if cursor
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                return ("unknown", "Python source symlinks are not followed");
            }
        }
        let Some(text) = bounded_read(&root.join(&path), 1024 * 1024)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        else {
            uncertain = true;
            continue;
        };
        if ["\"\"\"", "'''"].iter().any(|s| text.contains(s)) {
            // Ambiguous multiline strings are intentionally not parsed.
            uncertain = true;
            continue;
        }
        for line in text.lines() {
            let trimmed = line.trim();
            let import = trimmed
                .strip_prefix("import ")
                .map(|s| s.split_whitespace().next().unwrap_or(""))
                .or_else(|| {
                    trimmed
                        .strip_prefix("from ")
                        .and_then(|s| s.split_once(" import ").map(|(m, _)| m))
                });
            if let Some(import) = import {
                if import == module || import.starts_with(&format!("{module}.")) {
                    return("reachable","Potential static import path from a selected entrypoint; vulnerable functions were not analyzed");
                }
                if import.contains(',') || import.starts_with('.') {
                    uncertain = true;
                    continue;
                }
                let relative = PathBuf::from(import.replace('.', "/"));
                let file = relative.with_extension("py");
                let init = relative.join("__init__.py");
                if root.join(&file).is_file() {
                    pending.push(file)
                } else if root.join(&init).is_file() {
                    pending.push(init)
                }
            }
        }
    }
    let _ = uncertain;
    ("unknown","No supported static import path established; dynamic imports and function calls are not proven absent")
}
