— Technical Specification

Architecture, module design, command contracts, security requirements, and release acceptance criteria

`Rust` `CLI-first` `Local-first` `Security engineering`

## 1. Executive summary

Sentinel is a local - first security CLI that combines traditional software vulnerability analysis with

security controls for autonomous AI coding agents.

The project will have two initial releases:

!image.png

The architecture must support future integrations with Codex and other agents without coupling the security engine to one provider.

### Design principles

1. Deterministic enforcement: Explicit policy rules determine whether an action is permitted. AI-generated advice cannot silently override those rules.
2. Fail closed at sensitive boundaries: If an enforced hook cannot validate an action, it must reject it rather than assume it is safe.
3. Least privilege: Agents should receive only the filesystem, shell, and network permissions necessary for a task.
4. Offline-first: Core policy enforcement, local auditing, and configured offline scanning should not require cloud services.
5. Explainability: Every finding and blocked action should include a rule identifier, reason, severity, and remediation guidance.
6. Compatibility: Keep agent-specific integration code separate from policy evaluation.
7. Measurable security: Every release must have automated tests for both intended behavior and known bypass attempts.

!image.png

The CLI invokes application services through `sentinel-core`. The core coordinates policy evaluation, scanning, auditing, and agent adapters. Modules should communicate using typed Rust interfaces rather than executing one another's CLI commands.

For v0.0.1, the agent adapter remains a reserved extension point. In v0.0.2, the first implementation targets Claude Code.

## 3. Rust workspace structure

```bash
sentinel/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
│
├── crates/
│   ├── sentinel-cli/
│   │   └── src/
│   │       ├── main.rs
│   │       ├── commands/
│   │       └── output/
│   │
│   ├── sentinel-core/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs
│   │       ├── project.rs
│   │       └── error.rs
│   │
│   ├── sentinel-policy/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── model.rs
│   │       ├── parser.rs
│   │       ├── evaluator.rs
│   │       └── paths.rs
│   │
│   ├── sentinel-scanner/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── dependencies.rs
│   │       ├── osv.rs
│   │       ├── secrets.rs
│   │       └── findings.rs
│   │
│   ├── sentinel-audit/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── event.rs
│   │       └── store.rs
│   │
│   └── sentinel-agent/
│       └── src/
│           ├── lib.rs
│           ├── adapter.rs
│           ├── agent-like-claude.rs
│           ├── approval.rs
│           └── risk.rs
│
├── configs/
│   └── default-policy.yml
├── schemas/
│   ├── policy.schema.json
│   └── finding.schema.json
├── tests/
│   ├── fixtures/
│   ├── integration/
│   └── security/
├── docs/
│   ├── architecture.md
│   ├── cli-reference.md
│   ├── policy-reference.md
│   └── threat-model.md
└── .github/
    └── workflows/
        ├── ci.yml
        └── release.yml
```

## 4. Module responsibilities

| Module | Responsibilities | First release |
| --- | --- | --- |
| `sentinel-cli` | Commands, flags, terminal UX, output, exit codes | v0.0.1 |
| `sentinel-core` | Application orchestration, config loading, project detection, shared errors | v0.0.1 |
| `sentinel-policy` | Policy schema, criticality levels, protected zones, decision evaluation | v0.0.1 |
| `sentinel-scanner` | Lockfile parsing, OSV queries, secret detection, normalized findings | v0.0.1 |
| `sentinel-audit` | Local event records, filtering, persistence, integrity verification | v0.0.1; extended v0.0.2 |
| `sentinel-agent` | Agent adapters, hook processing, approval workflow, action risk evaluation | v0.0.2 |

### Module boundaries

The policy engine must not depend on Claude Code/ codex, terminal prompts, or network APIs.

 It receives a normalized action and policy context, then returns a decision.

The scanner must return structured findings without deciding whether an agent action is allowed. The policy engine may consume those findings as risk evidence.

The audit engine must accept normalized events from all other modules. It must never store raw credentials or sensitive prompt content by default.

## 5. Security policy specification

A project stores its policy in `sentinel.yml`.

The policy format is versioned independently of the CLI binary.

```yaml

schema_version: 1

project:
  name: my-project
  level: L1

policy:
  default_action: allow

  protected_paths:
    - "src/auth/**"
    - "src/payments/**"
    - ".github/workflows/**"
    - ".env*"
    - "sentinel.yml"

  rules:
    - id: SEC-001
      action: file.write
      paths:
        - "src/auth/**"
      decision: require_approval

    - id: SEC-002
      action: file.write
      paths:
        - ".env*"
      decision: deny

scanning:
  dependencies: true
  secrets: true
  offline: false

audit:
  enabled: true
  redact_secrets: true
```

### Criticality-level behavior

| Capability | L0 | L1 | L2 | L3 |
| --- | --- | --- | --- | --- |
| Basic scanning | Yes | Yes | Yes | Yes |
| Protected path approval | Log | Require | Require | Deny direct edits |
| Out-of-scope writes | Log | Configurable | Deny | Deny |
| Shell and network | Log | Policy-based | Deny by default | Deny by default |
| Direct agent writes | Allowed | Controlled | Controlled | Read-only |
| Audit trail | Basic | Standard | Integrity-checked | Integrity-checked |

In v0.0.1, these levels define and validate policy. They do not yet enforce AI agent permissions. Runtime enforcement begins in v0.0.2 for explicitly supported actions.

### Policy evaluation rules

The policy engine should apply the following precedence:

1. Invalid or untrusted policy configuration results in an error, never a silent downgrade.
2. Explicit `deny` rules override approvals and allows.
3. Explicit `require_approval` rules override allows.
4. Task scope and project criticality may strengthen restrictions.
5. If no rule matches, use the level's documented default behavior.

Every evaluation should return a stable decision code and matched rule IDs.

## 6. CLI command specification

### Global CLI contract

All commands should support predictable flags and consistent behavior.

```bash
sentinel [GLOBAL_OPTIONS] <COMMAND> [OPTIONS]
```

| Global option | Purpose |
| --- | --- |
| `--help`, `-h` | Display command help |
| `--version`, `-V` | Display Sentinel version |
| `--config <PATH>` | Override policy file location |
| `--project <PATH>` | Select project root |
| `--format text\|json` | Select output format |
| `--quiet`, `-q` | Suppress nonessential output |
| `--verbose`, `-v` | Enable diagnostic messages |
| `--no-color` | Disable terminal colors |

Use `stdout` for normal results and `stderr` for errors and diagnostics. JSON mode must output exactly one valid JSON document without banners or terminal escape sequences.

### v0.0.1 commands

| Command | Behavior | Expected result |
| --- | --- | --- |
| `sentinel init` | Initialize project configuration | Creates `sentinel.yml` |
| `sentinel scan` | Run configured dependency and secret checks | Findings and summary |
| `sentinel policy check` | Validate configuration and rule semantics | Errors or validation success |
| `sentinel doctor` | Check Sentinel installation and environment | Diagnostic report |
| `sentinel audit` | Read local audit events | Filterable event history |
| `sentinel --version` | Display build version | Version string |

`sentinel init`

```bash
sentinel init --level L1
sentinel init --level L2 --project ./backend
sentinel init --level L0 --force
```

Requirements: generate a valid policy file, select one of four security levels, avoid overwriting existing configurations without explicit confirmation, and use atomic writes to avoid incomplete files.

`sentinel scan`

```bash
sentinel scan
sentinel scan --type dependencies
sentinel scan --type secrets
sentinel scan --format json
sentinel scan --offline
sentinel scan --fail-on high
```

For the first release, support Rust `Cargo.lock` and JavaScript `package-lock.json` (lockfile v2/v3) as the initial dependency formats. The scanner must identify exact resolved package versions and query known vulnerability data. Other ecosystems must be explicitly reported as unsupported, not silently treated as safe.

Offline scans should use previously cached vulnerability data and report its age. If the cache is missing, return an incomplete-scan status.

`sentinel policy check`

Validate YAML syntax, schema version, security levels, duplicate rule IDs, action names, path patterns, contradictory configurations, and unsupported policy fields.

`sentinel doctor`

Check binary and policy versions, project discovery, storage permissions, cache availability, and scanner compatibility. In v0.0.2, extend it to verify agent hook installation.

`sentinel audit`

```bash
sentinel audit
sentinel audit --limit 50
sentinel audit --event scan.completed
sentinel audit --format json
```

Return timestamped local events, sorted by newest first, with optional filters.

### v0.0.2 commands

| Command | Behavior |
| --- | --- |
| `sentinel agent setup claude` | Install supported Claude Code hook configuration |
| `sentinel agent status` | Show installed adapters and their protection status |
| `sentinel guard -- claude` | Start a guarded session using verified integration |
| `sentinel approvals list` | Show pending approval requests |
| `sentinel scan --reachability` | Analyze supported reachable vulnerable paths |
| `sentinel scan --exploit-aware` | Enrich findings with exploit intelligence |
| `sentinel policy test` | Run policy test fixtures |
| `sentinel redteam` | Execute controlled security scenarios |
| `sentinel audit verify` | Verify local audit hash-chain integrity |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Operation successful; no threshold violation |
| `1` | Internal or unexpected error |
| `2` | Invalid CLI arguments |
| `3` | Invalid configuration |
| `4` | Security findings exceed configured threshold |
| `5` | Policy denied an action |
| `6` | Approval required or unavailable |
| `7` | Scan incomplete or required intelligence unavailable |
| `8` | Audit integrity verification failed |

For native agent hooks, translate these internal outcomes into the integration's documented response protocol. Do not assume ordinary CLI exit codes are sufficient to block an agent action.

## 7. Internal interfaces and data models

### Policy engine

The policy engine must expose a typed interface similar to:

```rust

pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
    LogOnly,
}

pub struct ActionContext {
    pub action_id: String,
    pub agent_id: Option<String>,
    pub action_type: ActionType,
    pub project_root: PathBuf,
    pub target_paths: Vec<PathBuf>,
    pub command: Option<String>,
    pub task_scope: Vec<PathBuf>,
}

pub struct PolicyResult {
    pub decision: Decision,
    pub matched_rules: Vec<String>,
    pub reason: String,
    pub risk_score: Option<u8>,
}

pub trait PolicyEvaluator {
    fn evaluate(
        &self,
        action: &ActionContext,
        policy: &Policy,
    ) -> Result<PolicyResult, PolicyError>;
}
```

Risk scoring must not weaken an explicit deny. A low risk score does not automatically make a prohibited action permissible.

### Finding model

Every scanner should produce the same normalized finding structure.

```json

{
  "schema_version": 1,
  "id": "finding-001",
  "rule_id": "DEP-001",
  "category": "dependency_vulnerability",
  "severity": "high",
  "title": "Known vulnerable dependency",
  "package": {
    "name": "example-package",
    "version": "1.2.3",
    "ecosystem": "npm"
  },
  "location": {
    "file": "package-lock.json"
  },
  "evidence": {
    "source": "OSV",
    "advisory_id": "EXAMPLE-ADVISORY"
  },
  "reachability": "not_analyzed",
  "remediation": "Review the advisory and upgrade to a fixed version."
}
```

This is a schema example, not a real vulnerability finding.

Reachability should use explicit states: `reachable`, `not_reachable`, `unknown`, `not_analyzed`. An unsupported or inconclusive analysis must never be reported as proof that a vulnerability is unreachable.

### Audit event model

```json

{
  "schema_version": 1,
  "event_id": "evt-001",
  "timestamp": "2026-10-20T10:00:00Z",
  "session_id": "session-001",
  "event_type": "policy.decision",
  "actor": "agent:claude, codex etc",
  "action": "file.write",
  "target": "src/auth/session.rs",
  "decision": "deny",
  "rule_ids": ["SEC-001"],
  "previous_hash": "previous-record-hash",
  "hash": "current-record-hash"
}
```

The actual hash must be calculated over a canonical serialization of the event, excluding its own hash field. Store hash algorithm and chain version as metadata.

A hash chain can reveal changes within an intact chain, but it cannot independently prevent an attacker from rewriting the entire log. Stronger assurance requires a separately protected or signed checkpoint.

## 8. v0.0.2 agent enforcement architecture

The agent adapter converts provider-specific events into normalized `ActionContext` objects.

!image.png

### Approval requirements

An approval request must include the proposed action, affected files, matched rules, risk explanation, and available diff when supported.

An approval grant must be bound to the exact action parameters or content hash. It must not be reusable for a modified command or file write. Approvals should expire and be consumed once.

If a session is noninteractive, approval-required actions must be denied unless a separately authorized approval mechanism exists.

### Protected filesystem operations

Policy matching must account for canonical paths, symlinks, path traversal, repository boundaries, case sensitivity, and platform-specific path behavior.

A hook-based path check alone cannot guarantee safety against race conditions or commands that indirectly modify files. For high-security projects, OS-level sandboxing is required.

### Risk scoring

Use a deterministic, explainable score from 0–10, based on factors such as protected path access, destructive operations, secret exposure, reachable vulnerabilities, and known exploitation.

Define fixed scoring rules and test fixtures before implementation. Unknown reachability should increase uncertainty, not be treated as zero risk.

## 9. Security threat model

The primary protected assets are source code, credentials, configuration files, dependency integrity, security policies, and audit records.

| Threat | Required mitigation | Release |
| --- | --- | --- |
| Exposed credentials | Secret detection and output redaction | v0.0.1 |
| Vulnerable dependencies | OSV-based vulnerability detection | v0.0.1 |
| Malformed policy | Strict schema and semantic validation | v0.0.1 |
| Unauthorized agent edits | Pre-action policy enforcement | v0.0.2 |
| Destructive shell commands | Command policy and restricted execution | v0.0.2 |
| Prompt-injected repository files | Controlled attack tests and policy boundaries | v0.0.2 |
| Policy tampering | Protected configuration and integrity checks | v0.0.2 |
| Audit manipulation | Hash-chain verification and protected checkpoints | v0.0.2 |
| Hook bypass | CI checks and documented sandbox requirements | v0.0.2 |

The initial threat model assumes an ordinary developer workstation with a potentially unsafe AI agent. A fully compromised operating system or administrator account is outside the security guarantees of these releases.

## 10. Release acceptance tests

These are proposed mandatory tests. Both versions must pass their applicable test suites before a release is tagged.

### v0.0.1 — Foundation acceptance tests

v0.0.1 Test Suite

- [ ]  INIT-001 — Initialize a new project
Expected: Creates valid sentinel.yml
- [ ]  INIT-002 — Initialize an existing project without --force
Expected: Preserves existing configuration
- [ ]  POL-001 — Validate a correct policy
Expected: Returns exit code 0
- [ ]  POL-002 — Validate malformed YAML
Expected: Returns configuration error
- [ ]  POL-003 — Validate duplicate or unknown rules
Expected: Rejects invalid configuration
- [ ]  POL-004 — Test deny/approval/allow precedence
Expected: Returns correct decisions
- [ ]  SCAN-001 — Scan a fixture with a known vulnerable dependency
Expected: Reports matching advisory
- [ ]  SCAN-002 — Scan a fixture with a test secret
Expected: Reports finding without exposing the secret
- [ ]  SCAN-003 — Scan with unavailable vulnerability data
Expected: Reports incomplete status
- [ ]  SCAN-004 — Scan a clean supported fixture
Expected: Returns no findings
- [ ]  OUT-001 — Request JSON output
Expected: Produces schema-valid JSON
- [ ]  AUD-001 — Run a scan and inspect audit history
Expected: Records an event with expected metadata
- [ ]  CLI-001 — Test help, version and invalid arguments
Expected: Returns documented output and exit codes
- [ ]  CI-001 — Run test suite on supported platforms
Expected: All mandatory checks pass

### v0.0.2 — Agent security acceptance tests

v0.0.2 Test Suite

- [ ]  AGT-001 — Install Claude Code / codex etc integration
Expected: Hooks installed and verified
- [ ]  AGT-002 — Agent requests permitted edit
Expected: Action allowed
- [ ]  AGT-003 — Agent requests protected edit
Expected: Approval requested
- [ ]  AGT-004 — Agent requests explicitly denied edit
Expected: Action blocked
- [ ]  AGT-005 — Agent attempts to edit sentinel.yml
Expected: Self-protection rule enforced
- [ ]  AGT-006 — Agent attempts path traversal or symlink bypass
Expected: Violation rejected within documented enforcement boundary
- [ ]  AGT-007 — Agent executes a prohibited shell command
Expected: Hook denies supported action
- [ ]  APR-001 — Approve an action once
Expected: Approval cannot be reused
- [ ]  APR-002 — Modify action after approval
Expected: New approval required
- [ ]  APR-003 — Approval unavailable or expired
Expected: Action denied
- [ ]  RISK-001 — Edit code linked to reachable vulnerable path
Expected: Risk score increases
- [ ]  RISK-002 — Analyze unsupported reachability case
Expected: Returns unknown or not_analyzed
- [ ]  AUD-002 — Modify an existing audit event
Expected: Integrity verification fails
- [ ]  AUD-003 — Attempt audit log truncation
Expected: Protected checkpoint detects truncation
- [ ]  CI-002 — Submit a policy-violating change
Expected: CI check fails
- [ ]  RED-001 — Run seeded attack fixtures
Expected: Reports correct expected outcomes
- [ ]  PERF-001 — Benchmark policy evaluation
Expected: Meets documented performance target

## 11. Quality and performance requirements

| Metric | Proposed release target |
| --- | --- |
| Policy evaluation | p95 under 20 ms for local rule evaluation |
| CLI startup | Under 150 ms on reference development hardware |
| Basic local scan | Under 5 seconds for a small reference fixture, excluding network |
| JSON schema compliance | 100% of tested outputs |
| Policy rule unit tests | 100% of documented decision branches exercised |
| Critical bypass tests | All mandatory security fixtures pass |
| Supported platforms | Linux, macOS, Windows |
| Reproducible tests | No live API dependency in required CI tests |

Performance thresholds must be measured on a documented reference machine and test corpus. They are engineering targets, not existing benchmark results.

### CI pipeline

Every pull request should run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Additional jobs should validate policy schemas, run integration fixtures, check dependencies, and exercise platform-specific behavior.

A release workflow should produce versioned binaries, checksums, release notes, and ideally signed artifacts.

## 12. Dependency and supply-chain strategy

Use a small, audited dependency set.

| Purpose | Suggested Rust library |
| --- | --- |
| CLI parsing | `clap` |
| Serialization | `serde`, `serde_json`, `serde_yaml` or maintained YAML equivalent |
| Error handling | `thiserror`, `anyhow` |
| Async HTTP | `tokio`, `reqwest` |
| Path matching | `globset` |
| Secret patterns | `regex` |
| Hashing | `sha2` |
| Database | `rusqlite` |
| Terminal display | `comfy-table` or `indicatif` |
| Testing | `assert_cmd`, `predicates`, `tempfile` |

Exact versions should be selected and reviewed during implementation. Commit `Cargo.lock` and use dependency auditing in CI.

For v0.0.1, prefer JSONL storage without SQLite unless querying requirements justify a database. Avoid unnecessary complexity in the first release.

## 13. Implementation milestones

!image.png

This is an indicative 16-week solo-development plan, not a fixed delivery commitment. The reachability prototype and cross-platform agent enforcement are the largest schedule risks.

## 14. Definition of done

v0.0.1 is ready when the CLI installs successfully, initializes and validates policies, scans the two selected dependency ecosystems, detects test secrets, produces structured findings, records local audit events, and passes all mandatory foundation tests.

v0.0.2 is ready when the supported Claude Code / codex etc integration can intercept  and enforce documented actions, approvals are safely bound to requests, risk analysis works for the defined prototype scope, audit integrity can be checked, and security bypass fixtures pass.

Both releases require documentation of unsupported operations, limitations, and known risks.

## 15. Scope deliberately postponed

To keep the initial releases achievable, postpone a hosted dashboard, enterprise RBAC/SSO, centralized policy distribution, comprehensive MCP auditing, full static and dynamic analysis, arbitrary-agent support, compliance certification, and autonomous AI remediation.

These can become subsequent milestones without forcing major architectural changes.

## Final engineering decision

Build Sentinel as a Rust workspace with a deterministic security core and pluggable agent  adapters.

The most important implementation order is:

`CLI → Configuration → Policy Engine → Scanner → Audit → Agent Hooks → Approvals → Risk Intelligence`

Do not begin with the AI agent integration. The policy engine must first be independently testable, because every future agent integration will depend on its correctness.

The specification above defines the intended design and release gates; it is not a claim that any  features have already been implemented or tested.
