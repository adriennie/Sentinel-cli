# Sentinel CLI

Sentinel v0.0.2 is a local-first security CLI for policies, dependency advisories, exposed secrets and redacted audit records. Native discovery covers supported Cargo, npm, uv, Poetry and pinned Python requirements inputs; optional CycloneDX input remains available. An explicit Claude Code integration adds a deterministic pre-action policy gate and exact-action approvals. Optional Python import analysis, EPSS/KEV enrichment, audit verification, policy fixtures, synthetic redteam and SARIF have documented scope limits. Hooks are not an operating-system sandbox.

See the [v0.0.2 operating/security guide](docs/v0.0.2-security.md) before enabling the agent gate.

## Installation

Install Rust using [rustup](https://rustup.rs), then run from this directory:

```sh
cargo install --locked --path crates/sentinel-cli
sentinel --version
```

The workspace pins Rust 1.99.1 with rustfmt and Clippy and declares the same minimum supported Rust version in every crate. `Cargo.lock` pins dependencies.

## Commands

```sh
sentinel init                       # default L1
sentinel init --level L2
sentinel init --level L0 --force    # replace existing configuration
sentinel policy check
sentinel --project ./backend --config security.yml policy check
sentinel policy check --format json
sentinel scan --type dependencies --format json
sentinel scan --offline
sentinel scan --sbom ./bom.json
sentinel audit --limit 50 --format json
sentinel doctor --format json
sentinel policy test
sentinel scan --format sarif
sentinel agent setup claude
sentinel agent status
sentinel guard --scope 'src/**' -- claude
sentinel approvals list
sentinel audit checkpoint --output /path/outside/project/checkpoint.json
sentinel audit verify --checkpoint /path/outside/project/checkpoint.json
sentinel redteam
```

`--project` defaults to the current directory; no parent-directory search occurs. Relative `--config` paths resolve against the project root, defaulting to `sentinel.yml`. Absolute config paths are accepted. Parent directories must already exist. Initialization writes through a temporary file in the destination directory, preserving existing files unless `--force` is supplied. A force replacement replaces the destination entry, including a symlink, rather than following it.

Global flags may appear before or after subcommands: `--project`, `--config`, `--format text|json|sarif` (SARIF is scan-only), `--quiet/-q`, `--verbose/-v`, and `--no-color`. Quiet suppresses successful text summaries; scan findings, coverage diagnostics, JSON results, and errors remain visible. Quiet and verbose conflict. Verbose diagnostics go to stderr. All output is currently uncolored; `--no-color` is accepted for script compatibility. `--help/-h` and `--version/-V` use standard Clap output.

JSON execution produces one document on stdout. Old commands retain version-1 data; new commands and enriched scans use version-2 data within this envelope:

```json
{"schema_version":1,"status":"ok","message":"Policy is valid","data":{"config":"/project/sentinel.yml","level":"L1","rules":0}}
```

Errors contain `schema_version`, `status: "error"`, and `error: {code, message}`. Errors are also described on stderr. Exit codes: 0 success, 1 filesystem/unexpected failure, 2 invalid arguments, 3 invalid/missing configuration; 4 findings at the failure threshold; 5 policy-test/proposed-change denial; 6 unavailable approval; 7 incomplete scan/analysis; 8 audit verification failure. Invalid argument responses honor an explicit JSON format flag; help and version always retain normal text output.

## Policy behavior

See [the policy reference](docs/policy-reference.md). Policy evaluation is a library capability; CLI commands initialize, validate and test configuration; the optional guarded integration evaluates supported pre-actions. L0 logs protected writes, L1/L2 require approval, L3 denies all direct writes, and L2/L3 deny shell/network actions. Runtime gating applies only to supported Claude pre-actions inside `sentinel guard`; direct shell sessions and other processes are not contained.

Dependency scanning honors the generated dependency/offline settings. See [dependency scanning](docs/dependency-scanning.md) for native and SBOM ecosystem support, cache behavior, limits, and coverage semantics. See [audit and doctor](docs/audit-and-doctor.md) for event storage, diagnostics, JSON contracts, failure behavior, and limitations. See [secrets scanning](docs/secrets-scanning.md) for supported patterns, redaction, ignore behavior, and coverage limits. Unqualified `scan` now runs both enabled scanners. Agent gating is opt-in and requires a supported Claude client; it is not an OS sandbox. See the v0.0.2 guide for exact coverage, approval bindings, audit migration and analysis uncertainty.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
```

CI is configured to run these checks on Linux, macOS, and Windows. Run `python3 scripts/check-release.py` for local release checks and a temporary installation smoke test; it checks actual synthetic-secret detection and redaction before reporting local readiness. See [release acceptance](docs/release-acceptance.md). Prebuilt release archives include licensing notices and installation instructions; see [INSTALL.md](INSTALL.md). See [the development checklist](docs/development-checklist.md) for milestone status. The four native jobs additionally test a pinned real Claude client against a synthetic localhost API; no paid model calls or live vulnerability APIs are required in acceptance fixtures. Original design documents and diagrams are retained.
