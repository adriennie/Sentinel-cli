# Changelog

## 0.0.1 — Initial release candidate

- Rust CLI with atomic policy initialization, strict L0–L3 validation, and deterministic policy evaluation.
- Cargo/npm dependency scanning against OSV, timestamped offline caching, and CycloneDX JSON inventory input for documented ecosystems.
- Local secrets scanning for common token families, AWS secret-key assignments, and private-key headers, with redacted evidence and bounded coverage.
- Concurrent JSONL audit logging and offline doctor diagnostics.
- Versioned JSON contracts, synthetic acceptance fixtures, and native release validation.
- Safe-Rust YAML parser with bounded documents, nesting, and alias handling; removed unsafe-libyaml.

Coverage is limited to documented formats and patterns. This release does not enforce agent permissions, perform reachability analysis, verify credentials, provide audit tamper-evidence, or establish that a project is secure. Binaries are unsigned and not notarized.
