use crate::{
    digest, discover,
    osv::{read_cache, write_cache},
    CacheUsage, Diagnostic, Evidence, Finding, Intelligence, OsvClient, Package, ScanReport,
    CACHE_TTL_SECONDS,
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub struct ScanOptions {
    pub offline: bool,
    pub sbom: Option<PathBuf>,
}
struct Lookup {
    package: Package,
    value: Option<Intelligence>,
    cache: Option<CacheUsage>,
    errors: Vec<&'static str>,
}
fn lookup(
    root: &Path,
    package: Package,
    offline: bool,
    now: u64,
    client: &impl OsvClient,
) -> Lookup {
    let cached = read_cache(root, &package, now).ok();
    let mut result = Lookup {
        package: package.clone(),
        value: None,
        cache: None,
        errors: Vec::new(),
    };
    if let Some(cached) = cached
        .as_ref()
        .filter(|v| offline || now - v.fetched_at <= CACHE_TTL_SECONDS)
    {
        let age = now - cached.fetched_at;
        result.cache = Some(CacheUsage {
            package,
            age_seconds: age,
            stale: age > CACHE_TTL_SECONDS,
        });
        if age > CACHE_TTL_SECONDS {
            result
                .errors
                .push("OSV cache is older than 24 hours; refresh online");
        }
        result.value = Some(Intelligence {
            schema_version: 1,
            package: cached.package.clone(),
            fetched_at: cached.fetched_at,
            advisories: cached.advisories.clone(),
        });
        return result;
    }
    if offline {
        result
            .errors
            .push("Required OSV cache data is missing, corrupt, or unavailable");
        return result;
    }
    match client.query(&package) {
        Ok(advisories) => {
            let value = Intelligence {
                schema_version: 1,
                package,
                fetched_at: now,
                advisories,
            };
            if let Err(error) = write_cache(root, &value) {
                result.errors.push(error.0);
            }
            result.value = Some(value);
        }
        Err(error) => {
            result.errors.push(error.0);
            if let Some(cached) = cached {
                result.cache = Some(CacheUsage {
                    package,
                    age_seconds: now - cached.fetched_at,
                    stale: true,
                });
                result.value = Some(cached);
            }
        }
    }
    result
}
pub fn scan(root: &Path, options: &ScanOptions, client: &impl OsvClient) -> ScanReport {
    let inventory = discover(root, options.sbom.as_deref());
    let mut report = ScanReport {
        coverage: if options.sbom.is_some() {
            "provided_sbom_components"
        } else {
            "supported_registry_dependencies"
        },
        inputs: inventory.inputs,
        schema_version: 1,
        status: "complete",
        complete: inventory.diagnostics.is_empty(),
        packages_discovered: inventory.packages.len(),
        packages_checked: 0,
        files_checked: 0,
        findings: vec![],
        diagnostics: inventory.diagnostics,
        cache: vec![],
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_secs(),
        Err(_) => {
            report.complete = false;
            report.status = "incomplete";
            report.diagnostics.push(Diagnostic {
                package: None,
                code: "clock_error",
                file: None,
                message: "System clock predates UNIX epoch",
            });
            return report;
        }
    };
    let start = Instant::now();
    let packages: Vec<_> = inventory.packages.keys().cloned().collect();
    'packages: for chunk in packages.chunks(8) {
        if start.elapsed() > Duration::from_secs(120) {
            report.complete = false;
            report.diagnostics.push(Diagnostic {
                package: None,
                code: "scan_budget",
                file: None,
                message: "Scan time budget exhausted; run again to continue warming the cache",
            });
            break;
        }
        let lookups = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|package| {
                    scope.spawn(move || lookup(root, package.clone(), options.offline, now, client))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join())
                .collect::<Vec<_>>()
        });
        for lookup in lookups {
            let lookup = match lookup {
                Ok(value) => value,
                Err(_) => {
                    report.complete = false;
                    report.diagnostics.push(Diagnostic {
                        package: None,
                        code: "lookup_error",
                        file: None,
                        message: "OSV lookup worker failed",
                    });
                    continue;
                }
            };
            for message in lookup.errors {
                report.complete = false;
                report.diagnostics.push(Diagnostic {
                    package: Some(lookup.package.clone()),
                    code: "intelligence_unavailable",
                    file: None,
                    message,
                });
            }
            if let Some(cache) = lookup.cache {
                report.cache.push(cache);
            }
            if let Some(value) = lookup.value {
                report.packages_checked += 1;
                for advisory in value.advisories {
                    if report.findings.len() >= 100_000 {
                        report.complete = false;
                        report.diagnostics.push(Diagnostic {
                            package: None,
                            code: "finding_limit",
                            file: None,
                            message: "Finding limit exceeded; select a smaller project",
                        });
                        break 'packages;
                    }
                    let key = format!(
                        "{}\0{}\0{}\0{}",
                        lookup.package.ecosystem,
                        lookup.package.name,
                        lookup.package.version,
                        advisory.id
                    );
                    report.findings.push(Finding {
                        schema_version: 1,
                        id: digest(key.as_bytes()),
                        rule_id: "DEP-001",
                        category: match advisory.kind {
                            crate::AdvisoryKind::Vulnerability => "dependency_vulnerability",
                            crate::AdvisoryKind::Maintenance => "dependency_maintenance",
                            crate::AdvisoryKind::Unknown => "dependency_advisory",
                        },
                        severity: advisory.severity,
                        title: match advisory.kind {
                            crate::AdvisoryKind::Vulnerability => "Known vulnerable dependency",
                            crate::AdvisoryKind::Maintenance => "Dependency maintenance advisory",
                            crate::AdvisoryKind::Unknown => "Dependency security advisory",
                        },
                        package: Some(lookup.package.clone()),
                        location: None,
                        files: inventory
                            .packages
                            .get(&lookup.package)
                            .map(|files| files.iter().cloned().collect())
                            .unwrap_or_default(),
                        evidence: Evidence {
                            source: "OSV",
                            advisory_kind: Some(advisory.kind),
                            advisory_id: Some(advisory.id),
                            redacted: None,
                        },
                        remediation:
                            "Review the OSV advisory and upgrade to an appropriate fixed version.",
                        reachability: "not_analyzed",
                    });
                }
            }
        }
    }
    report.findings.sort_by(|a, b| a.id.cmp(&b.id));
    report.findings.dedup_by(|a, b| a.id == b.id);
    report.status = if report.complete {
        "complete"
    } else {
        "incomplete"
    };
    report
}
