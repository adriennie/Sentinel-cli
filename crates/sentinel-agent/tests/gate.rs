use sentinel_agent::*;
use sentinel_policy::{Decision, Level, Policy};
use serde_json::{json, Value};
use std::fs;
fn fixture(level: Level) -> (tempfile::TempDir, Policy, Session) {
    let root = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let policy = Policy::new("test".into(), level);
    let config = root.path().join("sentinel.yml");
    setup(root.path(), &config, &std::env::current_exe().unwrap()).unwrap();
    let session = begin_session(root.path(), vec!["src/**".into()]).unwrap();
    (root, policy, session)
}
fn input(root: &std::path::Path, path: &str, tool: &str) -> Value {
    json!({"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_use_id":"action-1","cwd":root,"tool_name":tool,"tool_input":{"file_path":root.join(path),"content":"SYNTHETIC_PRIVATE_CONTENT"}})
}
#[test]
fn permitted_protected_denied_and_self_protection() {
    let (root, policy, s) = fixture(Level::L1);
    let config = root.path().join("sentinel.yml");
    let call = input(root.path(), "src/main.rs", "Write");
    assert_eq!(
        gate(root.path(), &config, &policy, &call, &s.nonce)
            .unwrap()
            .decision,
        Decision::Allow
    );
    for path in [
        "sentinel.yml",
        ".claude/settings.json",
        ".sentinel/audit.jsonl",
    ] {
        assert_eq!(
            gate(
                root.path(),
                &config,
                &policy,
                &input(root.path(), path, "Write"),
                &s.nonce
            )
            .unwrap()
            .decision,
            Decision::Deny
        )
    }
    assert_eq!(
        gate(
            root.path(),
            &config,
            &policy,
            &input(root.path(), "src/auth/key.rs", "Write"),
            &s.nonce
        )
        .unwrap()
        .code,
        "AGENT_APPROVAL_UNAVAILABLE"
    );
    assert!(
        !fs::read_to_string(root.path().join(".sentinel/agent/decisions.jsonl"))
            .unwrap()
            .contains("SYNTHETIC_PRIVATE_CONTENT")
    );
}
#[test]
fn approvals_bind_arguments_and_are_consumed_once() {
    let (root, policy, s) = fixture(Level::L1);
    let c = root.path().join("sentinel.yml");
    let call = input(root.path(), "src/auth/key.rs", "Write");
    let pending = gate(root.path(), &c, &policy, &call, &s.nonce).unwrap();
    let id = pending.approval_id.unwrap();
    let list = list_approvals(root.path()).unwrap();
    assert!(grant_approval(root.path(), &id, "changed-binding").is_err());
    grant_approval(root.path(), &id, &list[0].binding).unwrap();
    let mut changed = call.clone();
    changed["tool_input"]["content"] = json!("CHANGED");
    assert_eq!(
        gate(root.path(), &c, &policy, &changed, &s.nonce)
            .unwrap()
            .decision,
        Decision::Deny
    );
    assert_eq!(
        gate(root.path(), &c, &policy, &call, &s.nonce)
            .unwrap()
            .decision,
        Decision::Allow
    );
    assert_eq!(
        gate(root.path(), &c, &policy, &call, &s.nonce)
            .unwrap()
            .decision,
        Decision::Deny
    );
}
#[test]
fn traversal_scope_shell_unknown_and_expiry_fail_closed() {
    let (root, policy, s) = fixture(Level::L2);
    let c = root.path().join("sentinel.yml");
    assert!(gate(
        root.path(),
        &c,
        &policy,
        &input(root.path(), "../escape", "Write"),
        &s.nonce
    )
    .is_err());
    assert_eq!(
        gate(
            root.path(),
            &c,
            &policy,
            &input(root.path(), "outside.txt", "Write"),
            &s.nonce
        )
        .unwrap()
        .decision,
        Decision::Deny
    );
    assert_eq!(
        gate(
            root.path(),
            &c,
            &policy,
            &input(root.path(), "unused", "Bash"),
            &s.nonce
        )
        .unwrap()
        .decision,
        Decision::Deny
    );
    assert!(gate(
        root.path(),
        &c,
        &policy,
        &input(root.path(), "unused", "UnknownTool"),
        &s.nonce
    )
    .is_err());
    assert!(gate(
        root.path(),
        &c,
        &policy,
        &input(root.path(), "src/main.rs", "Write"),
        "invalid"
    )
    .is_err());
    let p = root.path().join(".sentinel/agent/session.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    state["created"] = json!(0);
    fs::write(p, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(gate(
        root.path(),
        &c,
        &policy,
        &input(root.path(), "src/main.rs", "Write"),
        &s.nonce
    )
    .is_err());
}
#[test]
fn setup_preserves_settings_and_detects_tampering() {
    let root = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    fs::create_dir(root.path().join(".claude")).unwrap();
    let path = root.path().join(".claude/settings.json");
    fs::write(&path, r#"{"env":{"PRESERVED":"yes"}}"#).unwrap();
    let config = root.path().join("sentinel.yml");
    setup(root.path(), &config, &std::env::current_exe().unwrap()).unwrap();
    let first = fs::read(&path).unwrap();
    setup(root.path(), &config, &std::env::current_exe().unwrap()).unwrap();
    assert_eq!(first, fs::read(&path).unwrap());
    let mut state: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(state["env"]["PRESERVED"], "yes");
    state["disableAllHooks"] = json!(true);
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(status(root.path(), &config).is_err());
}
#[cfg(unix)]
#[test]
fn symlink_and_case_bypasses_are_denied() {
    let (root, policy, s) = fixture(Level::L0);
    let out = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    std::os::unix::fs::symlink(out.path(), root.path().join("link")).unwrap();
    assert!(gate(
        root.path(),
        &root.path().join("sentinel.yml"),
        &policy,
        &input(root.path(), "link/file", "Write"),
        &s.nonce
    )
    .is_err());
    assert_eq!(
        gate(
            root.path(),
            &root.path().join("sentinel.yml"),
            &policy,
            &input(root.path(), ".ClAuDe/settings.json", "Write"),
            &s.nonce
        )
        .unwrap()
        .decision,
        Decision::Deny
    );
}
#[test]
fn deterministic_risk_never_changes_policy_decision() {
    assert_eq!(risk(false, false, false, false, false, true), 1);
    assert_eq!(risk(true, false, false, true, false, false), 5);
    assert_eq!(risk(true, true, true, true, true, true), 10);
}

#[test]
fn approval_accepts_one_identical_retry_but_rejects_target_changes_and_expiry() {
    let (root, policy, s) = fixture(Level::L1);
    let c = root.path().join("sentinel.yml");
    let call = input(root.path(), "src/auth/key.rs", "Write");
    let id = gate(root.path(), &c, &policy, &call, &s.nonce)
        .unwrap()
        .approval_id
        .unwrap();
    let list = list_approvals(root.path()).unwrap();
    grant_approval(root.path(), &id, &list[0].binding).unwrap();
    let mut retry = call.clone();
    retry["tool_use_id"] = json!("different-provider-request-id");
    assert_eq!(
        gate(root.path(), &c, &policy, &retry, &s.nonce)
            .unwrap()
            .decision,
        Decision::Allow
    );
    let path = root.path().join("src/auth/key.rs");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "old file state").unwrap();
    let pending = gate(root.path(), &c, &policy, &call, &s.nonce)
        .unwrap()
        .approval_id
        .unwrap();
    let list = list_approvals(root.path()).unwrap();
    let request = list.iter().find(|r| r.id == pending).unwrap();
    grant_approval(root.path(), &pending, &request.binding).unwrap();
    fs::write(&path, "changed file state").unwrap();
    assert_eq!(
        gate(root.path(), &c, &policy, &call, &s.nonce)
            .unwrap()
            .decision,
        Decision::Deny
    );
    let state = root.path().join(".sentinel/agent/approvals.json");
    let mut values: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for v in values.as_array_mut().unwrap() {
        v["expires_at"] = json!(0);
    }
    fs::write(state, serde_json::to_vec(&values).unwrap()).unwrap();
    assert!(gate(root.path(), &c, &policy, &call, &s.nonce).is_err());
}
#[test]
fn decision_journal_tampering_is_detected_and_risk_evidence_strengthens_scores() {
    let (root, policy, s) = fixture(Level::L1);
    let c = root.path().join("sentinel.yml");
    let path = root.path().join("src/main.py");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "import example\n").unwrap();
    store_risk(
        root.path(),
        vec![RiskEntry {
            path: "src/main.py".into(),
            source_hash: hash(&fs::read(&path).unwrap()),
            reachable: true,
            kev: true,
            high_epss: false,
            uncertain: false,
        }],
    )
    .unwrap();
    let call = input(root.path(), "src/main.py", "Write");
    let result = gate(root.path(), &c, &policy, &call, &s.nonce).unwrap();
    assert_eq!(result.risk_score, 5);
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(verify_audit(root.path(), None).unwrap().1, 1);
    let journal = root.path().join(".sentinel/agent/decisions.jsonl");
    fs::write(&journal, b"").unwrap();
    assert!(verify_audit(root.path(), None).is_err());
    assert!(gate(root.path(), &c, &policy, &call, &s.nonce).is_err());
}
#[test]
fn concurrent_approval_consumption_allows_only_one_callback() {
    let (root, policy, s) = fixture(Level::L1);
    let c = root.path().join("sentinel.yml");
    let call = input(root.path(), "src/auth/key.rs", "Write");
    let id = gate(root.path(), &c, &policy, &call, &s.nonce)
        .unwrap()
        .approval_id
        .unwrap();
    let list = list_approvals(root.path()).unwrap();
    grant_approval(root.path(), &id, &list[0].binding).unwrap();
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| gate(root.path(), &c, &policy, &call, &s.nonce));
        let b = scope.spawn(|| gate(root.path(), &c, &policy, &call, &s.nonce));
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(
        outcomes
            .into_iter()
            .filter(|r| r.as_ref().is_ok_and(|v| v.decision == Decision::Allow))
            .count(),
        1
    );
}

#[test]
fn unicode_normalization_and_custom_policy_aliases_cannot_weaken_denials() {
    let (root, mut policy, s) = fixture(Level::L1);
    policy.policy.protected_paths = vec!["src/café/**".into()];
    let config = root.path().join("sentinel.yml");
    let result = gate(
        root.path(),
        &config,
        &policy,
        &input(root.path(), "src/cafe\u{301}/key.rs", "Write"),
        &s.nonce,
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
    let bidi = input(root.path(), "src/\u{202e}misleading.rs", "Write");
    assert!(gate(root.path(), &config, &policy, &bidi, &s.nonce).is_err());
}
