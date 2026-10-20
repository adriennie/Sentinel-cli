# v0.0.1 development checklist

## Implemented

- [x] Rust workspace and versioned `sentinel` binary
- [x] Commands, global flags, help, and consistent text/JSON output
- [x] Atomic project initialization and configurable L0–L3 policies
- [x] Strict policy validation and typed deterministic evaluator
- [x] Unit tests and CLI integration/regression tests
- [x] Linux, macOS, and Windows CI configuration
- [x] Foundation hardening: inherited MSRV, bounded policy reads, redacted parser errors, fallible glob compilation, and lexical path normalization
- [x] Cargo/npm dependency scanning and OSV integration, offline cache, and CycloneDX SBOM input
- [x] Dependency-scan JSON output and regression tests
- [x] Local JSONL security audit logging and audit command
- [x] Offline doctor diagnostics and explicit capability reporting
- [x] Audit/doctor JSON Schemas and contract, failure, and concurrency tests
- [x] Local release-check gate, temporary installation smoke tests, and acceptance matrix

## Remaining v0.0.1 work

- [ ] Secrets scanning and redacted findings
- [ ] Secrets JSON contract and tests
- [ ] Complete release acceptance: secrets detection, supported-platform CI evidence, dependency review, and release artifacts

Agent interception, approval workflows, and audit integrity verification belong to v0.0.2. This is not a complete v0.0.1 release.
