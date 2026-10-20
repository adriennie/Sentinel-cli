use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskEntry {
    pub path: String,
    pub source_hash: String,
    pub reachable: bool,
    pub kev: bool,
    pub high_epss: bool,
    pub uncertain: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    created: u64,
    project: String,
    entries: Vec<RiskEntry>,
}
pub fn store(root: &Path, entries: Vec<RiskEntry>) -> Result<()> {
    if entries.len() > 32 {
        return Err("Risk snapshot exceeds entrypoint limit");
    }
    for e in &entries {
        if normalize_path(root, &e.path)? != e.path {
            return Err("Risk path is not normalized");
        }
    }
    let _lock = locked(root)?;
    atomic(
        &directory(root)?.join("risk-snapshot.json"),
        &Snapshot {
            schema_version: 2,
            created: now(),
            project: hash(root.to_string_lossy().as_bytes()),
            entries,
        },
    )
}
pub(crate) fn evidence(root: &Path, paths: &[String]) -> sentinel_policy::RiskEvidence {
    let mut evidence = sentinel_policy::RiskEvidence::default();
    let p = directory(root).map(|p| p.join("risk-snapshot.json"));
    let Ok(path) = p else {
        evidence.uncertain = true;
        return evidence;
    };
    if !path.exists() {
        evidence.uncertain = true;
        return evidence;
    }
    let Some(state) = read(&path, 256 * 1024)
        .ok()
        .and_then(|b| serde_json::from_slice::<Snapshot>(&b).ok())
        .filter(|s| {
            s.schema_version == 2
                && s.created <= now()
                && now() - s.created <= 86400
                && s.project == hash(root.to_string_lossy().as_bytes())
                && s.entries.len() <= 32
        })
    else {
        evidence.uncertain = true;
        return evidence;
    };
    let mut covered = std::collections::BTreeSet::new();
    for entry in state.entries {
        if paths.contains(&entry.path) {
            let valid = normalize_path(root, &entry.path).is_ok_and(|p| p == entry.path)
                && read(&root.join(&entry.path), 1024 * 1024)
                    .is_ok_and(|b| hash(&b) == entry.source_hash);
            if valid {
                covered.insert(entry.path.clone());
                evidence.reachable_dependency |= entry.reachable;
                evidence.known_exploitation |= entry.kev;
                evidence.high_epss |= entry.high_epss;
                evidence.uncertain |= entry.uncertain;
            } else {
                evidence.uncertain = true
            }
        }
    }
    evidence.uncertain |= paths.is_empty() || paths.iter().any(|p| !covered.contains(p));
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_unmatched_and_changed_risk_evidence_remains_unknown() {
        let root = tempfile::Builder::new()
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        let paths = vec!["main.py".into()];
        assert!(evidence(root.path(), &paths).uncertain);
        fs::write(root.path().join("main.py"), "import example\n").unwrap();
        store(
            root.path(),
            vec![RiskEntry {
                path: "main.py".into(),
                source_hash: hash(b"import example\n"),
                reachable: true,
                kev: false,
                high_epss: false,
                uncertain: false,
            }],
        )
        .unwrap();
        let known = evidence(root.path(), &paths);
        assert!(known.reachable_dependency);
        assert!(!known.uncertain);
        assert!(evidence(root.path(), &["other.py".into()]).uncertain);
        fs::write(root.path().join("main.py"), "# changed\n").unwrap();
        let changed = evidence(root.path(), &paths);
        assert!(changed.uncertain);
        assert!(!changed.reachable_dependency);
    }
}
