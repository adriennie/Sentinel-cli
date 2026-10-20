# Sentinel CLI — Codex Instructions (v0.0.1)

## Mission and scope

Build **Sentinel CLI v0.0.1**, a local-first, deterministic Rust security tool. This release includes CLI foundations, project initialization, policy parsing/validation/evaluation, basic dependency vulnerability scanning, secrets scanning, local audit events, doctor checks, JSON output, and automated tests. **Do not implement AI-agent interception, approvals, reachability analysis, EPSS/KEV enrichment, sandboxing, or a dashboard in this release.**

## Working protocol (optimize for correctness and tokens)

- Read this file, then inspect only files relevant to the assigned task. Do not recursively dump the repository.
- Implement **one bounded checklist item at a time**. Before edits, state a short plan only when the task is nontrivial.
- Reuse existing interfaces and dependencies; avoid broad refactors, speculative abstractions, and unrelated edits.
- Never claim a command or test passed unless you actually ran it. Report blockers precisely.
- Keep responses short: changed files, important design decisions, tests run/results, and remaining risks.
- Ask for clarification only when a security-critical ambiguity cannot be resolved safely from this file and existing code.
- Do not silently weaken policies, skip tests, suppress findings, or alter security defaults to make a test pass.

## Architecture and ownership

Rust Cargo workspace (create missing crates only when required):

- `crates/sentinel-cli`: `clap` command parsing, terminal/JSON formatting, exit codes; no security decisions.
- `crates/sentinel-core`: project discovery, configuration orchestration, shared types/errors.
- `crates/sentinel-policy`: versioned YAML schema, L0–L3 policy defaults, protected paths, deterministic evaluator; no network or UI dependency.
- `crates/sentinel-scanner`: lockfile parsing, OSV lookup/cache, secrets scanning, normalized findings.
- `crates/sentinel-audit`: append-only local JSONL events with redaction; no integrity guarantees claimed in v0.0.1.
- `crates/sentinel-agent`: reserved for v0.0.2; do not implement it yet.
Keep dependency direction clear: CLI → core/application services → policy/scanner/audit. Do not call one module's CLI from another module.

## Supported functionality and commands

- `sentinel init --level L0|L1|L2|L3 [--project PATH] [--force]`: create valid `sentinel.yml` atomically; never overwrite without `--force` or explicit confirmation.
- `sentinel scan [--type dependencies|secrets] [--offline] [--fail-on SEVERITY] [--format text|json]`: scan supported dependency lockfiles and secrets.
- `sentinel policy check`: validate YAML, schema version, rule IDs, known actions, glob syntax, and policy semantics.
- `sentinel doctor`: check configuration, project discovery, storage/cache permissions, and scanner support.
- `sentinel audit [--limit N] [--event NAME] [--format text|json]`: display redacted local events.
- `sentinel --version`, `--help`, `--config PATH`, `--project PATH`, `--quiet`, `--verbose`, `--no-color`.

Exit codes: `0` success; `1` internal error; `2` invalid arguments; `3` invalid configuration; `4` findings at/above configured threshold; `5` policy deny; `6` approval unavailable (reserved); `7` incomplete scan; `8` audit verification failure (reserved). JSON mode must emit one valid JSON document on stdout; diagnostics go to stderr.

## Policy semantics

- Policy file: `sentinel.yml`; `schema_version: 1`; project criticality `L0`, `L1`, `L2`, or `L3`.
- Explicit `deny` overrides `require_approval`, which overrides `allow`; default action applies only when no rule matches. Higher criticality may only strengthen restrictions.
- In v0.0.1, policies are **evaluated and validated but do not enforce AI agent actions**. Never imply otherwise.
- Reject malformed, unknown, or incompatible schema versions and unsupported rule/action types; never silently downgrade.
- Treat project files and YAML content as untrusted input. Normalize paths and ensure protected-path matching does not accept obvious traversal bypasses. Full runtime enforcement comes later.
- Policy evaluation must be pure/deterministic and unit-testable independently of CLI and network.

## Scanning contracts

- Initial dependency ecosystems: Rust `Cargo.lock` and npm `package-lock.json` lockfile versions 2/3. Parse resolved versions; query OSV for applicable advisories. Unsupported formats are reported, not silently marked clean.
- Offline scanning uses a timestamped local cache. If required data is absent, return `incomplete`/exit `7`, not "secure".
- Secrets scanner detects common credential patterns and uses test-only synthetic secrets. Redact matches in output, logs, and error messages. Avoid reading ignored/build/vendor directories by default; document exclusions.
- Normalize findings with schema version, stable rule ID, severity, category, file/package evidence, source, remediation, and reachability=`not_analyzed`.
- Never infer that no findings means the project is secure.

## Audit and storage

- Store redacted events as JSONL in a project-local or user-data location chosen consistently and documented.
- Log command execution, scan completion, and policy validation outcomes with timestamps and event IDs. Do not log raw secrets, environment variables, or full prompts.
- Use safe file writes; tolerate/report malformed records. Do not advertise tamper-evidence until v0.0.2.

## Coding and security standards

- Stable Rust; edition and MSRV pinned in workspace metadata. Commit `Cargo.lock`.
- Prefer `clap`, `serde`, `serde_json`, maintained YAML parser, `thiserror`, `reqwest`, `globset`, `regex`, and `sha2` only where needed. Avoid unnecessary dependencies.
- No `unwrap()`/`expect()` on user-controlled paths in production; return contextual typed errors.
- Use timeouts, bounded reads, size limits, and safe HTTP behavior. No arbitrary shell execution in scanning.
- Keep OSV/network behavior mockable; CI must not require live APIs.
- Format with `cargo fmt`, lint with `cargo clippy`, and test with `cargo test`.

## Required release tests

- INIT-001 valid initialization; INIT-002 no overwrite without force.
- POL-001 valid policy; POL-002 malformed YAML; POL-003 duplicate/unknown rules; POL-004 deny > approval > allow.
- SCAN-001 known vulnerable dependency fixture; SCAN-002 synthetic secret with redaction; SCAN-003 unavailable cache/API produces incomplete; SCAN-004 clean supported fixture.
- OUT-001 schema-valid JSON; AUD-001 redacted event; CLI-001 help/version/invalid args; CI-001 supported-platform pipeline.
- Tests must assert both results and exit codes. Include negative cases and avoid live network dependencies.

## Definition of done for each task

1. Implementation stays inside v0.0.1 scope and follows module boundaries.
2. Focused tests added/updated, including failure paths.
3. Run relevant tests, `cargo fmt --all -- --check`, and `cargo clippy --workspace --all-targets -- -D warnings` when feasible; report what actually ran.
4. No new secret leaks, silent fallbacks, policy weakening, or unrelated edits.
5. Summarize changed files, verification, and outstanding limitations in at most a few bullets.
