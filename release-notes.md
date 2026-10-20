# Sentinel v0.0.2

Scoped agent protection and automatic Python dependency discovery, prepared as an unpublished draft.

- Native uv/Poetry lockfiles, pinned requirements includes/constraints, Python manifest reconciliation and explicit uv workspace ownership. Unsupported/private/unresolved inputs remain visible.
- Opt-in Claude Code pre-action gate with restricted launch, self-protection and exact-action local approvals. Requires Claude 2.1.304+ within major version 2; hooks are not an OS sandbox.
- Conservative Python import reachability prototype and timestamped EPSS/CISA KEV enrichment; unsupported, stale and unavailable evidence remains unknown/incomplete.
- SHA-256 audit integrity sidecar and attached decision journal; independently retained checkpoints detect truncation below a saved prefix. Checkpoints are not automatically authenticated or protected against same-user rewrites.
- Deterministic policy fixtures, base-policy proposed-change PR gate, isolated synthetic redteam, measured risk/policy tests and redacted SARIF 2.1.0.
- Existing version-1 policies, audit events and old command results remain compatible. New feature data uses version 2 inside the existing envelope; hooks and SARIF use their native protocols.

## Install and verify

Choose Linux x64, Windows x64, Intel Mac or Apple Silicon. Verify the selected archive against SHA256SUMS before extraction. Each archive includes the binary, MIT license, upstream legal notices, installation instructions, changelog and BUILD.json. Exact source and native CI results are in release-evidence.json. See INSTALL.md and docs/v0.0.2-security.md in the source for operating limits.

## Validation and limits

All release gates must pass on the exact implementation commit: formatting, Clippy, tests/contracts, release builds, installed/extracted-binary acceptance, four native targets, legal notices and combined checksum/provenance verification. Each native target tests the real pinned Claude client against a synthetic localhost Messages API; no paid model calls are required. Dependency review must cover the current lockfile and remain within 24 hours.

No universal language coverage, full call-graph/function reachability, arbitrary shell inspection, managed-process containment or tamper-proof same-user storage is claimed. Git/private registries and unsupported lock schemas remain uncovered. Requirements files do not establish transitive closure. Secrets scanning retains its 1 MiB text-file limit and documented patterns/exclusions. Unknown severity and incomplete coverage keep conservative exit behavior. No Codex/MCP agent adapter, hosted dashboard or OS sandbox is included.

Exit codes: 0 executed/success within scope; 1 unexpected/storage/provider failure; 2 arguments; 3 configuration; 4 threshold findings; 5 policy-test/proposed-change denial; 6 unavailable approval; 7 incomplete scan/requested analysis; 8 audit verification failure. An `ok` envelope is not a security clearance.

This draft is not public publication. The v0.0.1 release is retained separately.
