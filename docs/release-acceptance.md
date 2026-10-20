# v0.0.1 release acceptance

Run from a checkout with the pinned Rust toolchain and Python 3 available:

```sh
python3 scripts/check-release.py
```

This runs formatting, Clippy with warnings denied, all workspace tests (including JSON Schema contracts and local HTTP mocks), and a locked release build. It then installs the CLI into a temporary directory and checks the installed binary's version, initialization, policy validation, offline scanning, doctor diagnostics, and audit history. It uses only synthetic local fixtures; no live vulnerability API is required. The temporary installation and fixture are removed afterward. To inspect an already-built release binary without repeating build/test/install checks:

```sh
python3 scripts/check-release.py --readiness-only
```

The gate exits 1 with explicit blockers if a required implemented capability is missing. This is deliberate: passing tests for available features must not imply a complete release. No command tags, publishes, or uploads a release.

## Acceptance coverage

| Gate | Verification | Current state |
| --- | --- | --- |
| INIT-001/002 | CLI initialization, all levels, preservation and replacement tests | Implemented |
| POL-001–004 | Strict schema, invalid rules, precedence and path hardening tests | Implemented |
| SCAN-001 | Mock OSV findings, exact identities and advisory evidence | Implemented |
| SCAN-002 | Synthetic secret detection and redaction | **Blocked: secrets scanner missing** |
| SCAN-003/004 | Incomplete cache/API behavior and clean supported fixtures | Implemented |
| OUT-001 | Audit/doctor/event JSON Schema tests; existing scan/init/error regressions | Implemented for available features; secrets contract pending |
| AUD-001 | Redacted completion events, failure outcomes, concurrent writers, history filters | Implemented |
| CLI-001 | Help, version, invalid arguments, stdout/stderr and exit codes | Implemented |
| CI-001 | Linux/macOS/Windows formatting, Clippy, tests and release-build workflow | Configured; actual platform runs must be confirmed before tagging |
| Installation | Temporary locked CLI install and installed-binary smoke tests | Included in local gate |
| Dependency review | Review reported advisories and maintenance risks | Open: previously observed RUSTSEC-2024-0449 through the YAML parser |
| Distribution | Release artifacts, checksums and release notes | Pending |

A complete v0.0.1 release is **not ready** while SCAN-002 and its output contract remain unimplemented. Audit logs have no integrity guarantee, agent enforcement is absent, and OSV coverage is limited to documented inputs/ecosystems. Keep those limitations in release notes.

The automated local gate checks available functionality and required capability declarations. Dependency-risk decisions, actual supported-platform CI results, and distribution readiness remain explicit review gates; the script does not manufacture evidence for them.
