# Sentinel Roadmap: Combined Evolution (v0.0.1 to v0.0.2+)

This document tracks the engineering journey of Sentinel from its initial CLI foundation through the development of its pre-action agent firewall, multi-provider preview support, and cryptographic audit integrity engine.

---

## 1. Why Sentinel Was Built

As autonomous AI coding assistants (such as Anthropic Claude Code, OpenAI Codex, and GitHub Copilot) gained broad adoption, developers granted them unrestricted access to run shell commands and edit source trees. This created the **AI Coding Agent Trust Gap**:

1. **Autonomous Agent Manipulation**: Indirect prompt injections from untrusted repo files, issues, or web lookups could hijack agent control loops, prompting them to execute destructive shell commands (`rm -rf`, curl pipes) or exfiltrate environment secrets (`.env`).
2. **Software Supply Chain Risk**: AI agents frequently propose package additions without verifying advisory databases, introducing typo-squatted or vulnerable dependencies.
3. **The Sandbox Fallacy**: Traditional OS sandboxes (Docker, VMs) provide process isolation but lack semantic awareness of agent intent, tool protocols, and policy rules. SAST tools run after the fact in CI, long after damage has occurred on the developer's workstation.

Sentinel was designed as a **local-first, deterministic, pre-action policy gate and firewall** that intercepts agent actions *before* execution occurs, combines vulnerability intelligence, and records tamper-evident cryptographic audit logs.

---

## 2. Milestone v0.0.1: CLI Foundation & Local Security Engine

The goal of v0.0.1 was to establish a high-performance, rock-solid Rust foundation, deterministic policy validation, local scanning engines, and basic audit logging.

### Architectural Decisions in v0.0.1:
- **Rust Workspace**: Partitioned into `sentinel-cli`, `sentinel-core`, and `sentinel-policy`.
- **Zero Heavy Runtime Dependencies**: Pure Rust parsers, minimal external crates, offline-capable by default.
- **Strict Bounded I/O**: File reads capped at 1 MiB; untrusted input never echoed in raw error messages.

### Completed Checklist (v0.0.1):
- [x] **CLI Framework**: Implemented using Clap 4; subcommands `init`, `policy check`, `scan`, `audit`, `doctor`; global flags (`--project`, `--config`, `--format`, `--quiet`, `--verbose`, `--no-color`).
- [x] **Project Initialization**: `sentinel init --level L0|L1|L2|L3` with atomic file generation and preservation checks.
- [x] **Policy Engine (Schema v1)**: Validation of security levels, protected path globs, action kinds, and deterministic precedence ($\text{Deny} \succ \text{RequireApproval} \succ \text{LogOnly} \succ \text{Allow}$).
- [x] **Dependency Scanning**: Native parsers for `Cargo.lock` and `package-lock.json` (v2 & v3); Google OSV API client with local `.sentinel/cache/` storage and `--offline` support.
- [x] **Secrets Scanning**: High-throughput regex pattern matching for private keys, AWS tokens, GitHub PATs, and credentials; strict redaction across stdout, stderr, and logs.
- [x] **Structured Audit Logging**: Local append-only `.sentinel/audit.jsonl` with structured JSON events and redaction.
- [x] **System Doctor**: Pre-flight validation of binary versions, config syntax, storage permissions, and cache states.
- [x] **Automated CI**: Cross-platform testing on Linux, macOS, and Windows.

---

## 3. Milestone v0.0.2: Agent Firewall, Approvals & Integrity

Milestone v0.0.2 introduced pre-action runtime guarding of AI coding agents, cryptographic integrity, static analysis, and multi-provider support.

### Architectural Decisions in v0.0.2:
- **New Crates**: Added `sentinel-agent`, `sentinel-scanner`, and `sentinel-audit`.
- **Pre-Action Protocol Bridge**: Integration with Claude Code's native `PreToolUse` hook protocol with `onFailure: "block"` in `--restricted` mode.
- **Multi-Provider Preview**: Best-effort interceptors for OpenAI Codex and GitHub Copilot CLI requiring `--allow-degraded-hooks`.
- **Cryptographic Action Binding**: Ephemeral single-use approval tokens bound by multi-attribute SHA-256 digests with 5-minute TTLs.
- **Audit Hash Chaining**: Sidecar `audit-chain-v2.jsonl` with domain-separated SHA-256 hashing and external checkpoints.

### Completed Checklist (v0.0.2):
- [x] **Claude Code Native Gate**: Exec-form `PreToolUse` hook registration in `.claude/settings.json`, restricted launch, self-protection against tampering with `.sentinel` or `sentinel.yml`.
- [x] **OpenAI Codex & GitHub Copilot Preview**: Multi-provider bridge in `crates/sentinel-agent/src/providers.rs` with cross-platform Windows argument escaping and `--allow-degraded-hooks` enforcement.
- [x] **Expanded Dependency Ecosystems**: Native parsers for Python `uv.lock`, `poetry.lock`, and pinned `requirements.txt`.
- [x] **SBOM Ingestion**: CycloneDX 1.4 and 1.5 JSON parser (`sentinel scan --sbom`).
- [x] **Static Import Reachability**: Conservative AST/lexical analyzer mapping active Python imports to vulnerable packages (3-state lattice: `reachable`, `unknown`, `not_analyzed`).
- [x] **Threat Intelligence Enrichment**: Integration of CISA Known Exploited Vulnerabilities (KEV) and EPSS percentiles into the additive risk scoring model.
- [x] **Cryptographic Approval Tokens**: Ephemeral tokens bound to operation, target hashes, nonce, and policy under cooperative advisory locks.
- [x] **Audit Hash Chaining & Checkpointing**: SHA-256 chain verification (`sentinel audit verify`) and external checkpointing (`sentinel audit checkpoint`).
- [x] **Deterministic Policy Test Harness**: `sentinel policy test` executing automated policy test suites.
- [x] **Adversarial Redteam Suite**: `sentinel redteam` executing simulated path traversal, secret theft, and unauthorized shell attacks.
- [x] **OASIS SARIF v2.1.0 Export**: Full SARIF support for GitHub Advanced Security and GitLab SAST.
- [x] **Cross-Platform Release Automation**: Matrix builds across Linux x64, Windows x64, macOS Intel, and macOS Apple Silicon.

---

## 4. Current Verification & Quality Gates

Every commit and pull request must satisfy the following automated quality gates:
1. `cargo fmt --all -- --check`
2. `cargo clippy --locked --workspace --all-targets -- -D warnings`
3. `cargo test --locked --workspace` (122+ native Rust tests passing)
4. `python3 scripts/test-codex-copilot-protocol.py` (synthetic protocol runner verification)
5. `python3 scripts/check-release.py` (end-to-end binary installation, scanning, redaction, and audit verification)

---

## 5. Future Milestones (v0.0.3 and Beyond)

- **v0.0.3**:
  - **OS-Level Cooperating Sandboxes**: Cooperative integration with Linux `bubblewrap` / `landlock` and macOS `sandbox-exec` to enforce kernel-level isolation alongside Sentinel's pre-action gate.
  - **IDE Sidecars**: Real-time VS Code and JetBrains extension bridges displaying Sentinel policy violations and approval prompts directly in editor gutters.
  - **Language Ecosystem Expansion**: Native lockfile parsers for Go (`go.sum`), Maven/Gradle (`pom.xml`, `build.gradle`), and Ruby (`Gemfile.lock`).
- **v0.0.4**:
  - **Decentralized Multi-Signer Approvals**: Support for team-based M-of-N Ed25519 signatures for high-risk policy escalations.
  - **Continuous In-Memory Taint Tracking**: Tracing tainted strings from agent prompt to tool arguments.

