# Changelog

## 0.0.2 — Scoped agent gate and Python inventories

- Automatic uv/Poetry/requirements discovery, manifest reconciliation and explicit uv workspace ownership.
- Fail-closed Claude pre-action gate, restricted launch, exact-action approvals and deterministic risk evidence.
- Optional Python import reachability and timestamped EPSS/KEV enrichment with explicit uncertainty.
- SHA-256 audit sidecar and attached decision journal, with independent checkpoint verification.
- Policy fixtures, proposed-change PR checks, isolated redteam and redacted SARIF 2.1.0.
- Version-2 feature contracts preserve existing version-1 policy/event/command schemas.
- Real-client localhost fixtures join four-platform native build/install/archive acceptance.


## 0.0.1 — Initial release candidate

- Rust CLI with atomic policy initialization, strict L0–L3 validation, and deterministic policy evaluation.
- Cargo/npm dependency scanning against OSV, timestamped offline caching, and CycloneDX JSON inventory input for documented ecosystems.
- Local secrets scanning for common token families, AWS secret-key assignments, and private-key headers, with redacted evidence and bounded coverage.
- Concurrent JSONL audit logging and offline doctor diagnostics.
- Versioned JSON contracts, synthetic acceptance fixtures, and native release validation.
- Safe-Rust YAML parser with bounded documents, nesting, and alias handling; removed unsafe-libyaml.

Coverage is limited to documented formats and patterns. This release does not enforce agent permissions, perform reachability analysis, verify credentials, provide audit tamper-evidence, or establish that a project is secure. Binaries are unsigned and not notarized.
