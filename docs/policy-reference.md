# Version-1 policy reference

`sentinel init` generates this structure, with the project name derived from the selected directory:

```yaml
schema_version: 1
project:
  name: my-project
  level: L1
policy:
  default_action: allow
  protected_paths:
    - src/auth/**
    - src/payments/**
    - .github/workflows/**
    - .env*
    - sentinel.yml
  rules: []
scanning:
  dependencies: true
  secrets: true
  offline: false
audit:
  enabled: true
  redact_secrets: true
```

Policy documents must be valid UTF-8 and at most 1 MiB (1,048,576 bytes). Oversized files are rejected using bounded reads, and parser diagnostics report locations without echoing YAML values.

All fields are required and unknown fields are rejected at every level. Only schema version 1 and levels L0–L3 are accepted. Project names and rule IDs cannot be blank; rule IDs must be unique. Audit redaction must remain enabled, even while audit storage is deferred.

Rules contain `id`, `action`, `paths`, and `decision`. Supported actions are `file.read`, `file.write`, `shell.execute`, and `network.access`. Decisions are `allow`, `log_only`, `require_approval`, and `deny`. File rules require one or more glob paths; shell/network rules require an empty paths list and apply to the whole action. Invalid action/decision names are errors.

Patterns and evaluator target paths use forward slashes and are project-relative. Absolute paths, drive/colon syntax, backslashes, and `..` components are rejected. NUL bytes and empty/root-only targets are also rejected. Leading `./`, internal `.` components, and repeated separators are normalized in both patterns and action targets before matching. Invalid globs are rejected. Matching uses globset semantics: `*` can match path separators and `**` supports recursive patterns. All matching rules participate, including rules matching different targets of a multi-path action. Deny overrides approval, approval overrides log-only, and log-only overrides allow. If no rule matches, `default_action` applies. Overlapping rules are valid.

Level restrictions can strengthen any decision: protected writes are log-only at L0, require approval at L1/L2, and all writes are denied at L3. Shell and network actions are denied at L2/L3. Other actions retain their rule/default decision. The evaluator returns a stable `POLICY_ALLOW`, `POLICY_LOG_ONLY`, `POLICY_REQUIRE_APPROVAL`, or `POLICY_DENY` code, matched rule IDs, and a reason.

The typed evaluator validates policies before use. Callers must provide nonempty target paths for file actions. It evaluates normalized lexical paths only: it does not resolve symlinks, intercept operations, or provide a filesystem sandbox. Runtime path canonicalization and enforcement belong to future agent adapters.

Dependency scanning uses `scanning.dependencies` and `scanning.offline`. Auditing honors `audit.enabled`; `audit.redact_secrets` must remain true. Secrets scanning remains deferred. Stronger security levels likewise describe evaluation decisions, not active workstation permissions.
