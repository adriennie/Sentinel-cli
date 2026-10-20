# Sentinel v0.0.1

Initial local-first security CLI release candidate, prepared as an unpublished draft.

- Atomic `sentinel init`, strict version-1 policies and deterministic L0–L3 evaluation.
- `sentinel scan` runs enabled dependency and secrets checks, with selectable scan types, severity thresholds, explicit incomplete results and JSON output.
- Native Cargo/npm OSV scanning plus documented CycloneDX input, timestamped offline intelligence, and explicit advisory classification.
- Local common-credential patterns with redacted location evidence, bounded reads and documented exclusions.
- Concurrent local JSONL auditing and offline `doctor` diagnostics.
- Versioned JSON Schemas, synthetic acceptance tests, four-target native checks and verified archive smoke tests.
- Safe-Rust YAML parsing replaces the unmaintained unsafe-libyaml dependency.

## Download and verify

Choose the archive matching your OS/CPU: Linux x64, Windows x64, macOS Intel, or macOS Apple Silicon. Compare its SHA-256 digest with SHA256SUMS, then extract and place the binary on PATH. Installation instructions, the MIT license, third-party legal notices and build provenance are inside each archive. Exact source and CI evidence are recorded in release-evidence.json.

## Compatibility and limits

Policy schema version remains 1. Unqualified scans now run both enabled scanners; use `--type dependencies` for the earlier dependency-only behavior. Unknown advisory severity still conservatively triggers the configured failure threshold. Maintenance and unclassified advisories remain visible.

Exit 4 means threshold findings; exit 7 means incomplete scanning and takes precedence over findings. An `ok` JSON envelope means command execution completed: inspect scan completeness, doctor check status, audit logging status and the process exit code. Logs have no tamper-evidence or authentication guarantee.

Patterns and supported dependency ecosystems are limited; ignored/build/vendor files, symlinks, binary inputs, Git history, arbitrary credentials and unsupported dependency formats are outside the documented coverage. `--include-ignored` expands secret-file coverage but retains hard exclusions. No provider validation, agent interception, sandboxing, reachability analysis or complete security guarantee is provided.

Binaries are unsigned and not notarized. See the bundled instructions for OS/runtime minimums and source installation. This release is a draft and is not automatically published.
