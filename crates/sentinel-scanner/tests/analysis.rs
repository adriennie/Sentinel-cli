use sentinel_scanner::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};
struct Fake {
    calls: AtomicUsize,
    fail: bool,
}
impl ExploitClient for Fake {
    fn aliases(&self, _: &str) -> Result<Vec<String>, ScanError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(ScanError("Synthetic unavailable"));
        }
        Ok(vec!["CVE-2025-12345".into()])
    }
    fn epss(&self, _: &str) -> Result<Epss, ScanError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(ScanError("Synthetic unavailable"));
        }
        Ok(Epss {
            probability: 0.7,
            date: time::OffsetDateTime::now_utc().date().to_string(),
        })
    }
    fn kev(&self) -> Result<Kev, ScanError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(ScanError("Synthetic unavailable"));
        }
        Ok(Kev {
            date: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            cves: BTreeSet::from(["CVE-2025-12345".into()]),
        })
    }
}
fn report() -> ScanReport {
    let mut report = ScanReport::empty("fixture");
    report.findings.push(Finding {
        schema_version: 1,
        id: "a".repeat(64),
        rule_id: "DEP-001",
        category: "dependency_vulnerability",
        severity: Severity::High,
        title: "Synthetic advisory",
        package: Some(Package {
            ecosystem: "PyPI".into(),
            name: "example".into(),
            version: "1.0".into(),
        }),
        location: None,
        files: vec!["uv.lock".into()],
        evidence: Evidence {
            source: "OSV",
            advisory_id: Some("TEST-ADVISORY".into()),
            advisory_kind: Some(AdvisoryKind::Vulnerability),
            redacted: None,
        },
        remediation: "Upgrade dependency",
        reachability: "not_analyzed",
    });
    report
}
#[test]
fn explicit_python_import_reachability_is_conservative_and_raises_risk() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("main.py"), "import local\n").unwrap();
    fs::write(
        root.path().join("local.py"),
        "from example.api import run\n",
    )
    .unwrap();
    let options = AnalysisOptions {
        reachability: true,
        entrypoints: vec!["main.py".into()],
        python_imports: BTreeMap::from([("example".into(), "example".into())]),
        ..Default::default()
    };
    let fake = Fake {
        calls: AtomicUsize::new(0),
        fail: true,
    };
    let a = analyze(root.path(), &report(), &options, &fake);
    assert_eq!(a.findings[0].reachability, "reachable");
    assert_eq!(a.findings[0].risk_score, 2);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    fs::write(root.path().join("local.py"), "__import__('example')\n").unwrap();
    let a = analyze(root.path(), &report(), &options, &fake);
    assert_eq!(a.findings[0].reachability, "unknown");
    assert!(!a.complete);
}
#[test]
fn epss_kev_aliases_cache_offline_and_missing_intelligence() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    let a = analyze(
        root.path(),
        &report(),
        &AnalysisOptions {
            exploit_aware: true,
            ..Default::default()
        },
        &fake,
    );
    assert!(a.complete);
    assert_eq!(a.findings[0].epss, Some(0.7));
    assert_eq!(a.findings[0].kev, Some(true));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
    let failure = Fake {
        calls: AtomicUsize::new(0),
        fail: true,
    };
    let a = analyze(
        root.path(),
        &report(),
        &AnalysisOptions {
            exploit_aware: true,
            offline: true,
            ..Default::default()
        },
        &failure,
    );
    assert!(a.complete);
    assert_eq!(failure.calls.load(Ordering::SeqCst), 0);
    let empty = tempfile::tempdir().unwrap();
    let a = analyze(
        empty.path(),
        &report(),
        &AnalysisOptions {
            exploit_aware: true,
            offline: true,
            ..Default::default()
        },
        &failure,
    );
    assert!(!a.complete);
    assert_eq!(a.findings[0].kev, None);
    assert_eq!(a.findings[0].epss, None);
}
#[test]
fn stale_future_and_corrupt_intelligence_never_become_safe() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    analyze(
        root.path(),
        &report(),
        &AnalysisOptions {
            exploit_aware: true,
            ..Default::default()
        },
        &fake,
    );
    for entry in fs::read_dir(root.path().join(".sentinel/cache/osv-v1/intelligence-v2")).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["fetched_at"] = serde_json::json!(u64::MAX);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    }
    let a = analyze(
        root.path(),
        &report(),
        &AnalysisOptions {
            exploit_aware: true,
            offline: true,
            ..Default::default()
        },
        &fake,
    );
    assert!(!a.complete);
    assert_eq!(a.findings[0].kev, None);
}
#[test]
fn unsupported_ecosystems_and_missing_mappings_are_unknown() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake {
        calls: AtomicUsize::new(0),
        fail: true,
    };
    let mut r = report();
    r.findings[0].package.as_mut().unwrap().ecosystem = "npm".into();
    let a = analyze(
        root.path(),
        &r,
        &AnalysisOptions {
            reachability: true,
            ..Default::default()
        },
        &fake,
    );
    assert_eq!(a.findings[0].reachability, "unknown");
    assert!(!a.complete);
}
