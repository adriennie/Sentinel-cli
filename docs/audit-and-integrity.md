# Sentinel Audit, Integrity & System Diagnostics

Sentinel provides a tamper-evident audit logging framework and self-diagnostic engine to ensure comprehensive compliance, forensic transparency, and runtime health.

---

## 1. Audit Logging Architecture

Every Sentinel CLI action, policy evaluation, scan execution, and agent pre-action decision is recorded in project-local audit files under `.sentinel/`.

```
.sentinel/
├── audit.jsonl             # Version-1 append-only structured events
├── audit-chain-v2.jsonl    # Version-2 cryptographic SHA-256 hash chain sidecar
├── decisions/              # Individual agent pre-action decision records
│   ├── dec_001.json
│   └── dec_002.json
└── cache/                  # Offline vulnerability & advisory cache
```

### Zero-Secret Redaction Invariant
Before any event or decision is written to disk:
- Raw tool arguments and commands are stripped.
- File contents and code diffs are replaced with SHA-256 state hashes.
- Discovered credential values, tokens, and private keys are redacted into masked placeholders.
- Prompts, conversation history, and model reasoning are never stored.

---

## 2. Event Structure (`audit.jsonl`)

The primary log `.sentinel/audit.jsonl` contains newline-delimited JSON (JSONL) records conforming to schema version 1.

### Example Audit Record:
```json
{
  "schema_version": 1,
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-10-21T08:14:20Z",
  "event_type": "policy_evaluated",
  "actor": "claude-code-2.1.304",
  "action": {
    "action_type": "file.write",
    "target_paths": ["src/auth/jwt.rs"]
  },
  "decision": "require_approval",
  "risk_score": 7,
  "metadata": {
    "rule_ids": ["protect-auth-module"],
    "level": "L1"
  }
}
```

---

## 3. Cryptographic Hash Chaining (`audit-chain-v2.jsonl`)

To prove that audit logs have not been altered or rearranged, Sentinel maintains a parallel sidecar hash chain in `.sentinel/audit-chain-v2.jsonl`.

### Link Formulation:
For each line $i$ in `audit.jsonl`, a cryptographic link is appended to `audit-chain-v2.jsonl`:

```json
{
  "schema_version": 2,
  "sequence": 1,
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "previous": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "4a3521b4f4949b29402e3b2e5...30e8c1b2f7a",
  "attachment": "9f83c1b..."
}
```

- **Domain Separation**: Links are hashed using prefix `sentinel-audit-v2\n{sequence}\n{previous}\n`.
- **Canonical Serialization**: Keys are sorted recursively, and whitespace is stripped to guarantee deterministic byte hashing.
- **Decision Journal Binding**: When an agent decision is made, the SHA-256 digest of the decision journal is attached via `attachment-sha256`.

---

## 4. Checkpoints & Tamper Verification

### The Truncation Problem
An attacker with local write access could delete the last $N$ lines of `audit.jsonl` and recalculate the chain. While the internal links would be valid, historical actions would be erased.

### Independent Checkpoints
Sentinel solves this by allowing operators to export **non-overwriting checkpoints** outside the repository (e.g., to `/var/backups`, an S3 bucket, or an external log collector):

```sh
# Generate external checkpoint
sentinel audit checkpoint --output /var/backups/sentinel/checkpoint-20261021.json
```

A checkpoint records:
```json
{
  "schema_version": 2,
  "project": "my-project",
  "records": 42,
  "head": "4a3521b4f4949b29402e3b2e5...30e8c1b2f7a"
}
```

### Verification Against Checkpoints
Run verification to detect modification, reordering, or truncation:

```sh
sentinel audit verify --checkpoint /var/backups/sentinel/checkpoint-20261021.json
```

Verification verifies:
1. `audit.jsonl` contains at least as many records as the checkpoint ($N \ge 42$).
2. The hash at sequence 42 strictly matches `head`.
3. Every link in the chain correctly recalculates to the canonical SHA-256 digest of its corresponding event.

If any check fails, the command exits with **Exit Code 8**, and guarded agent sessions refuse to launch.

---

## 5. System Diagnostics (`sentinel doctor`)

The `sentinel doctor` command runs comprehensive offline health checks on the environment and Sentinel installation:

```sh
sentinel doctor
```

### Checks Performed:
1. **Binary & Schema Version**: Confirms binary version (v0.0.2) matches expected policy schemas.
2. **Policy Configuration**: Validates `sentinel.yml` syntax, security levels, and rule consistency.
3. **Storage & Permissions**: Performs safe write probes in `.sentinel/` to ensure disk writeability without following symlinks or modifying files.
4. **Cache Freshness**: Inspects `.sentinel/cache/` for corrupt entries or stale advisories.
5. **Lockfile Health**: Discovers supported dependency files (`Cargo.lock`, `package-lock.json`, `uv.lock`, etc.) and validates their format.
6. **Agent Hook State**: Verifies provider hook integrity (`.claude/settings.json`), executable paths, and session nonces.

Output is available in human-readable text or machine-parseable JSON (`sentinel doctor --format json`).

