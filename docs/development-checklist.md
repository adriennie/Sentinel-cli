# v0.0.1 development checklist

## Implemented

- [x] Rust CLI, initialization, help, version, flags, and documented exit codes
- [x] Strict version-1 policy parsing, deterministic evaluation, and path hardening
- [x] Safe-Rust YAML migration with bounded inputs, nesting, aliases, and sanitized errors
- [x] Cargo/npm OSV dependency scanning, offline cache, and CycloneDX SBOM input
- [x] Secrets detection with location-only redacted evidence and bounded working-tree coverage
- [x] JSONL audit logging, filters, concurrent appends, and malformed-record reporting
- [x] Offline doctor diagnostics and accurate capability reporting
- [x] Command/event JSON Schemas and positive/negative contract tests
- [x] Synthetic acceptance fixtures, redaction tests, and failure-path regressions
- [x] Four-target native CI, installation smoke tests, archive verification, and checksum corruption tests
- [x] MIT license, legal-notice collection, release notes, and draft-release tooling

## Release gates

Implementation checkmarks describe available code, not a claim that a release has been published. For a release-ready draft, require the exact-commit four-target CI run and release-bundle artifact, fresh matching dependency-review evidence, and verified checksums. The pipeline generates `release-evidence.json` only after native validation and all archive checks succeed. See release-acceptance.md and the draft's evidence file for the actual run.

Agent interception, approvals, audit integrity verification, and reachability analysis remain v0.0.2 work.
