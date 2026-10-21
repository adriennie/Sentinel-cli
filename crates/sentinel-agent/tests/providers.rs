use sentinel_agent::*;
use sentinel_policy::{Decision, Level, Policy};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn fixture(level: Level, provider: Provider) -> (tempfile::TempDir, Policy, Session, PathBuf) {
    let root = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let policy = Policy::new("test".into(), level);
    let config = root.path().join("sentinel.yml");
    setup_for(
        root.path(),
        &config,
        &std::env::current_exe().unwrap(),
        provider,
    )
    .unwrap();
    let session = begin_session_for(root.path(), vec!["src/**".into()], provider).unwrap();
    (root, policy, session, config)
}

fn codex_patch_input(root: &Path, tool_use_id: &str, patch: &str) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "session_id": "synthetic-codex-session",
        "tool_use_id": tool_use_id,
        "cwd": root,
        "tool_name": "apply_patch",
        "tool_input": {
            "command": patch
        }
    })
}

fn copilot_input(root: &Path, tool_name: &str, tool_args: Value) -> Value {
    json!({
        "sessionId": "synthetic-copilot-session",
        "cwd": root.to_str().unwrap(),
        "toolName": tool_name,
        "toolArgs": tool_args
    })
}

#[test]
fn test_codex_apply_patch_allowed_and_denied() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Codex);

    let allowed_patch = "\
*** Begin Patch
*** Update File: src/main.rs
+fn new_fn() {}
*** End Patch";
    let input = codex_patch_input(root.path(), "patch-1", allowed_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // Protected file denial: sentinel.yml
    let protected_patch = "\
*** Begin Patch
*** Update File: sentinel.yml
+extra: bad
*** End Patch";
    let input = codex_patch_input(root.path(), "patch-2", protected_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_SELF_PROTECTION");

    // Protected file denial: .codex/hooks.json
    let hooks_patch = "\
*** Begin Patch
*** Update File: .codex/hooks.json
+{}
*** End Patch";
    let input = codex_patch_input(root.path(), "patch-3", hooks_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_SELF_PROTECTION");

    // Secrets denial: .env
    let env_patch = "\
*** Begin Patch
*** Update File: .env
+SECRET=leak
*** End Patch";
    let input = codex_patch_input(root.path(), "patch-4", env_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);

    // Approval requirement on auth path
    let auth_patch = "\
*** Begin Patch
*** Update File: src/auth/token.rs
+fn auth() {}
*** End Patch";
    let input = codex_patch_input(root.path(), "patch-5", auth_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_APPROVAL_UNAVAILABLE");
    assert!(res.approval_id.is_some());
}

#[test]
fn test_codex_patch_with_add_delete_move_and_newline_escape() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Codex);

    let multi_patch = "\
*** Begin Patch
*** Add File: src/new_module.rs
+pub fn test() {}
\\ No newline at end of file
*** Update File: src/existing.rs
-old line
+new line
*** Move to: src/renamed.rs
*** Delete File: src/old.rs
*** End Patch";

    let input = codex_patch_input(root.path(), "patch-multi", multi_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // If one target touches protected policy, the whole action is denied
    let poisoned_patch = "\
*** Begin Patch
*** Add File: src/helper.rs
+fn helper() {}
*** Update File: sentinel.yml
+# malicious addition
*** End Patch";
    let input = codex_patch_input(root.path(), "patch-poisoned", poisoned_patch);
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_SELF_PROTECTION");
}

#[test]
fn test_codex_patch_syntax_and_traversal_fail_closed() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Codex);

    // Missing framing
    let unframed = "*** Update File: src/main.rs\n+fn fail() {}\n";
    let input = codex_patch_input(root.path(), "bad-1", unframed);
    assert!(gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex
    )
    .is_err());

    // Path traversal attempt
    let traversal = "\
*** Begin Patch
*** Update File: ../escape.rs
+fn escape() {}
*** End Patch";
    let input = codex_patch_input(root.path(), "bad-2", traversal);
    assert!(gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex
    )
    .is_err());

    // Empty targets
    let empty = "*** Begin Patch\n*** End Patch";
    let input = codex_patch_input(root.path(), "bad-3", empty);
    assert!(gate_for(
        root.path(),
        &config,
        &policy,
        &input,
        &s.nonce,
        Provider::Codex
    )
    .is_err());
}

#[test]
fn test_codex_bash_and_unknown_tools_denied() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Codex);

    let bash_input = json!({
        "hook_event_name": "PreToolUse",
        "session_id": "synthetic-codex-session",
        "tool_use_id": "bash-1",
        "cwd": root.path(),
        "tool_name": "Bash",
        "tool_input": {
            "command": "cat /etc/passwd"
        }
    });
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &bash_input,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_INDIRECT_SHELL_DENIED");

    let unknown_input = json!({
        "hook_event_name": "PreToolUse",
        "session_id": "synthetic-codex-session",
        "tool_use_id": "unknown-1",
        "cwd": root.path(),
        "tool_name": "ArbitraryTool",
        "tool_input": {}
    });
    assert!(gate_for(
        root.path(),
        &config,
        &policy,
        &unknown_input,
        &s.nonce,
        Provider::Codex
    )
    .is_err());
}

#[test]
fn test_codex_setup_status_and_tampering() {
    let root = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let config = root.path().join("sentinel.yml");
    let binary = std::env::current_exe().unwrap();

    let setup_val = setup_for(root.path(), &config, &binary, Provider::Codex).unwrap();
    assert_eq!(setup_val["healthy"], true);
    assert_eq!(setup_val["provider"], "codex");

    let status_val = status_for(root.path(), &config, Provider::Codex).unwrap();
    assert_eq!(status_val["healthy"], true);
    assert_eq!(status_val["adapter"], "codex-pretooluse-v2");

    // Tampering: edit .codex/hooks.json to disable hooks
    let hooks_file = root.path().join(".codex/hooks.json");
    assert!(hooks_file.exists());
    let mut data: Value = serde_json::from_slice(&fs::read(&hooks_file).unwrap()).unwrap();
    data["disableAllHooks"] = json!(true);
    fs::write(&hooks_file, serde_json::to_vec(&data).unwrap()).unwrap();

    assert!(status_for(root.path(), &config, Provider::Codex).is_err());
}

#[test]
fn test_codex_approval_workflow() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Codex);

    let auth_patch = "\
*** Begin Patch
*** Update File: src/auth/key.rs
+fn secret_key() -> &'static str { \"test\" }
*** End Patch";
    let call = codex_patch_input(root.path(), "call-1", auth_patch);
    let pending = gate_for(
        root.path(),
        &config,
        &policy,
        &call,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(pending.decision, Decision::Deny);
    assert_eq!(pending.code, "AGENT_APPROVAL_UNAVAILABLE");
    let id = pending.approval_id.unwrap();

    let list = list_approvals(root.path()).unwrap();
    let req = list.iter().find(|r| r.id == id).unwrap();
    assert_eq!(req.actor, "codex");

    grant_approval(root.path(), &id, &req.binding).unwrap();

    // Retrying the exact action allows it and consumes approval
    let retry = gate_for(
        root.path(),
        &config,
        &policy,
        &call,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(retry.decision, Decision::Allow);
    assert_eq!(retry.code, "AGENT_APPROVAL_CONSUMED");

    // Submitting again fails because approval was consumed once
    let second_retry = gate_for(
        root.path(),
        &config,
        &policy,
        &call,
        &s.nonce,
        Provider::Codex,
    )
    .unwrap();
    assert_eq!(second_retry.decision, Decision::Deny);
    assert_eq!(second_retry.code, "AGENT_APPROVAL_UNAVAILABLE");
}

#[test]
fn test_copilot_view_create_edit_and_protections() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Copilot);

    // view (FileRead)
    let view_call = copilot_input(root.path(), "view", json!({"path": "src/main.rs"}));
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &view_call,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // create (FileWrite)
    let create_call = copilot_input(
        root.path(),
        "create",
        json!({"path": "src/new_file.rs", "content": "hello"}),
    );
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &create_call,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // edit (FileWrite) on protected sentinel.yml -> denied
    let edit_policy = copilot_input(
        root.path(),
        "edit",
        json!({"path": "sentinel.yml", "content": "changed"}),
    );
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &edit_policy,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_SELF_PROTECTION");

    // edit on .github/hooks/sentinel.json -> denied
    let edit_hooks = copilot_input(
        root.path(),
        "edit",
        json!({"path": ".github/hooks/sentinel.json", "content": "{}"}),
    );
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &edit_hooks,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_SELF_PROTECTION");

    // view on .env -> denied
    let view_env = copilot_input(root.path(), "view", json!({"path": ".env"}));
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &view_env,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
}

#[test]
fn test_copilot_argument_aliases_and_stringified_json() {
    let (root, policy, s, config) = fixture(Level::L1, Provider::Copilot);

    // filePath alias
    let call_filepath = copilot_input(root.path(), "create", json!({"filePath": "src/alias1.rs"}));
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &call_filepath,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // file alias
    let call_file = copilot_input(root.path(), "create", json!({"file": "src/alias2.rs"}));
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &call_file,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // stringified toolArgs
    let call_stringified = json!({
        "sessionId": "synthetic-copilot-session",
        "cwd": root.path().to_str().unwrap(),
        "toolName": "create",
        "toolArgs": "{\"path\": \"src/stringified.rs\"}"
    });
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &call_stringified,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Allow);

    // bash denied
    let call_bash = copilot_input(root.path(), "bash", json!({"command": "ls -la"}));
    let res = gate_for(
        root.path(),
        &config,
        &policy,
        &call_bash,
        &s.nonce,
        Provider::Copilot,
    )
    .unwrap();
    assert_eq!(res.decision, Decision::Deny);
    assert_eq!(res.code, "AGENT_INDIRECT_SHELL_DENIED");
}

#[test]
fn test_copilot_setup_status_and_tampering() {
    let root = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let config = root.path().join("sentinel.yml");
    let binary = std::env::current_exe().unwrap();

    let setup_val = setup_for(root.path(), &config, &binary, Provider::Copilot).unwrap();
    assert_eq!(setup_val["healthy"], true);
    assert_eq!(setup_val["provider"], "copilot");

    let status_val = status_for(root.path(), &config, Provider::Copilot).unwrap();
    assert_eq!(status_val["healthy"], true);
    assert_eq!(status_val["adapter"], "copilot-pretooluse-v2");

    let hooks_file = root.path().join(".github/hooks/sentinel.json");
    assert!(hooks_file.exists());
    let mut data: Value = serde_json::from_slice(&fs::read(&hooks_file).unwrap()).unwrap();
    data["disableAllHooks"] = json!(true);
    fs::write(&hooks_file, serde_json::to_vec(&data).unwrap()).unwrap();

    assert!(status_for(root.path(), &config, Provider::Copilot).is_err());
}

#[test]
fn test_foreign_session_abstains_safely() {
    let (root, _policy, s, _config) = fixture(Level::L1, Provider::Claude);

    // While claude is the active guarded session, copilot hook should identify it as foreign session
    assert!(foreign_session(
        root.path(),
        Provider::Copilot,
        "claude",
        &s.nonce
    ));
    assert!(foreign_session(
        root.path(),
        Provider::Codex,
        "claude",
        &s.nonce
    ));

    // But claude's own hook does NOT abstain from claude session
    assert!(!foreign_session(
        root.path(),
        Provider::Claude,
        "claude",
        &s.nonce
    ));

    // Invalid or wrong nonce does not match
    assert!(!foreign_session(
        root.path(),
        Provider::Copilot,
        "claude",
        "invalid-nonce"
    ));
}
