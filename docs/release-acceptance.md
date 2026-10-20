# v0.0.1 release acceptance

Run `python3 scripts/check-release.py` with the pinned Rust toolchain and Python 3 available. This checks formatting, Clippy, all Rust tests and command contracts, packaging negative tests, locked release compilation, temporary CLI installation, and installed-binary initialization, policies, scans, actual synthetic-secret detection/redaction, doctor, and audit history. Required test fixtures use no live vulnerability APIs. `--readiness-only` checks an existing binary; `--readiness-only --binary PATH` checks an extracted archive binary.

## Required evidence

| Gate | Evidence |
| --- | --- |
| INIT-001/002 | Initialization, all levels, preservation/replacement, custom paths and filesystem-failure tests |
| POL-001–004 | Valid/invalid schema, rule semantics, precedence, path normalization and YAML resource-budget tests |
| SCAN-001 | Mock OSV findings, exact package identities and advisory evidence |
| SCAN-002 | Synthetic credential families, redaction across text/JSON/stderr/audit, and installed-binary secret smoke test |
| SCAN-003/004 | Missing/stale/corrupt intelligence, API failures, clean supported fixtures and bounded secrets coverage |
| OUT-001 | Actual command/event outputs validated against committed schemas, plus negative contracts |
| AUD-001 | Numeric redacted events, failure outcomes, concurrency, filtering and malformed history tests |
| CLI-001 | Help/version, flags, argument/configuration errors, stdout/stderr and exit codes |
| CI-001 | Exact-commit successful native jobs for Linux x64, Windows x64, Intel Mac and Apple Silicon |
| Dependency review | `docs/dependency-review.json` matching Cargo.lock, current within 24 hours, complete and finding-free |
| Distribution | Four native archives, matching BUILD.json provenance, extracted-binary smoke tests and SHA256SUMS verification |

The YAML migration removes serde_yaml_ng and unsafe-libyaml rather than ignoring their advisory. Explicit maintenance metadata produces maintenance findings; unclassified advisory types retain a generic title and conservative failure behavior. `scripts/verify-dependency-review.py` rejects stale, incomplete or mismatched review evidence. Required CI fixtures remain offline; refreshing dependency review is a separate live OSV action.

## Packaging and draft handoff

`scripts/package-release.py build --target TARGET` collects upstream legal notices, packages the native binary, license, install instructions, changelog and BUILD.json, and generates SHA256SUMS. `verify --smoke --expected-commit SHA --expected-count 1` verifies that runner's archive and exercises its extracted binary. The aggregate job requires all four target jobs, verifies all four archives and their source SHA, and generates `release-evidence.json` with the workflow URL, exact commit, targets, Cargo.lock hash and checksum-file hash.

The CI `release-bundle` artifact contains the four archives, SHA256SUMS and release-evidence.json. A draft release is created only from a successful exact-commit run and those verified assets. An existing conflicting tag or release must never be overwritten. The draft remains unpublished. Local success alone does not satisfy CI-001 or establish that a draft release exists.

Supported targets: x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, x86_64-apple-darwin, and aarch64-apple-darwin. Binaries are unsigned and not notarized; checksums are not independent signatures. Agent enforcement, reachability, audit integrity and universal language/project coverage are not provided.
