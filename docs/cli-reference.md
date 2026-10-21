# Sentinel CLI Reference Manual

This document provides a comprehensive command-line reference for the `sentinel` binary, covering all commands, options, exit codes, and machine-readable output formats.

---

## 1. Global Options

Global options may be specified before or after subcommands:

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--project <PATH>` | `-p` | `.` | Sets the project root directory. Does not search parent directories. |
| `--config <PATH>` | `-c` | `sentinel.yml` | Path to policy configuration file. Relative paths resolve against `--project`. |
| `--format <FORMAT>` | `-f` | `text` | Output format: `text`, `json`, or `sarif` (SARIF is supported for `scan` only). |
| `--quiet` | `-q` | `false` | Suppresses non-essential text messages. Incompatible with `--verbose`. |
| `--verbose` | `-v` | `false` | Emits diagnostic progress information to `stderr`. |
| `--no-color` | | `false` | Disables ANSI color escapes (for CI and script compatibility). |
| `--help` | `-h` | | Displays standard help information. |
| `--version` | `-V` | | Displays the Sentinel binary version. |

---

## 2. Exit Code Contract

Sentinel adheres to a strict, deterministic exit code contract:

| Exit Code | Classification | Meaning & Trigger Condition |
| :---: | :--- | :--- |
| **0** | `SUCCESS` | Command completed successfully within policy constraints. Clean scan findings. |
| **1** | `SYSTEM_ERROR` | Unexpected internal failure, I/O error, or storage write failure. |
| **2** | `INVALID_ARGUMENTS` | Invalid CLI options, conflicting flags, or missing required provider flags (e.g. omitting `--allow-degraded-hooks`). |
| **3** | `INVALID_CONFIG` | Malformed `sentinel.yml`, unsupported schema version, invalid glob syntax, or duplicate rule IDs. |
| **4** | `THRESHOLD_VIOLATION` | Scan detected vulnerabilities or secrets meeting or exceeding the configured `--fail-on` threshold. |
| **5** | `POLICY_DENIAL` | Policy test failure (`sentinel policy test`) or proposed change denied by policy rules. |
| **6** | `APPROVAL_REQUIRED` | An agent action requires human approval that is either pending, expired, or unavailable. |
| **7** | `INCOMPLETE_SCAN` | Scan could not achieve full coverage (e.g., missing offline advisory cache, unparsed lockfiles). |
| **8** | `AUDIT_VERIFICATION_FAIL` | Cryptographic audit chain verification failed, link modified, or log truncated below checkpoint. |

---

## 3. Command Reference

### `sentinel init`

Generates a new `sentinel.yml` policy file in the target project directory.

```sh
sentinel init [--level <L0|L1|L2|L3>] [--force]
```

- `--level <L0|L1|L2|L3>`: Sets initial baseline security level. (Default: `L1`).
- `--force`: Replaces an existing `sentinel.yml` file. (Without `--force`, existing files are preserved and an error is returned).

---

### `sentinel policy check`

Validates the syntax, schema version, glob rules, and security levels in `sentinel.yml`.

```sh
sentinel policy check [--format json]
```

---

### `sentinel policy test`

Executes automated deterministic test fixtures against the current policy configuration to verify precedence, level floors, and path matching.

```sh
sentinel policy test
```

---

### `sentinel scan`

Runs vulnerability dependency scanning, exploit intelligence enrichment, and secrets scanning.

```sh
sentinel scan [OPTIONS]
```

- `--type <dependencies|secrets>`: Restricts scan to a single engine. By default, both are executed.
- `--offline`: Disables OSV API lookups; relies exclusively on `.sentinel/cache/`.
- `--sbom <PATH>`: Ingests an external CycloneDX 1.4 or 1.5 JSON Software Bill of Materials.
- `--reachability`: Enables static Python import reachability analysis.
- `--entrypoint <PATH>`: Specifies entrypoint file for reachability analysis (repeatable, 1 to 32 entrypoints).
- `--fail-on <low|medium|high|critical>`: Sets severity threshold for non-zero exit code (default: `high`).
- `--format <text|json|sarif>`: Selects output format.

---

### `sentinel audit`

Queries the append-only JSONL audit event history.

```sh
sentinel audit [--limit <N>] [--event <NAME>] [--format json]
```

- `--limit <N>`: Maximum number of events to display, newest-first. (Default: 50).
- `--event <NAME>`: Filters events by event type (e.g., `policy_evaluated`, `scan_completed`).

---

### `sentinel audit checkpoint`

Validates the current audit chain and creates a standalone cryptographic checkpoint file.

```sh
sentinel audit checkpoint --output <PATH>
```

- `--output <PATH>`: Destination path for the checkpoint JSON file (recommended: store outside the project directory).

---

### `sentinel audit verify`

Verifies the cryptographic continuity of `.sentinel/audit-chain-v2.jsonl` and validates against an optional checkpoint.

```sh
sentinel audit verify [--checkpoint <PATH>] [--format json]
```

- `--checkpoint <PATH>`: Validates that the local chain matches or extends the saved checkpoint, detecting truncation attacks.

---

### `sentinel doctor`

Performs comprehensive system diagnostics, checking binary compatibility, storage permissions, cache freshness, and lockfile parsing.

```sh
sentinel doctor [--format json]
```

---

### `sentinel agent setup`

Registers Sentinel's pre-action hook into the target AI coding agent configuration.

```sh
sentinel agent setup <claude|codex|copilot>
```

---

### `sentinel agent status`

Inspects the installation status, hook registration, and health of agent integrations.

```sh
sentinel agent status [--provider <claude|codex|copilot>]
```

---

### `sentinel guard`

Launches an AI coding agent inside a guarded environment, enforcing pre-action policy gates.

```sh
sentinel guard [OPTIONS] -- <AGENT_COMMAND...>
```

- `--scope <GLOB>`: Restricts permitted file writes to the given glob pattern (e.g., `'src/**'`).
- `--provider <claude|codex|copilot>`: Explicitly identifies the target agent provider (default: `claude`).
- `--allow-degraded-hooks`: Required when using `codex` or `copilot` to acknowledge the preview / fail-open upstream hook model.
- `-- <AGENT_COMMAND...>`: The command to execute (e.g., `-- claude`).

---

### `sentinel approvals list`

Lists all pending and unexpired approval requests.

```sh
sentinel approvals list [--format json]
```

---

### `sentinel approvals grant`

Authorizes an elevated pre-action request for single-use execution within its 5-minute TTL.

```sh
sentinel approvals grant <REQUEST_ID> [--binding <BINDING>]
```

- `<REQUEST_ID>`: The identifier of the pending request (e.g., `req_8f1a`).
- `--binding <BINDING>`: Optional cryptographic binding string from `sentinel approvals list` to verify parameters.

---

### `sentinel redteam`

Executes synthetic adversarial test suites against Sentinel's policy engine, path normalizer, and approval system.

```sh
sentinel redteam
```

---

## 4. Machine-Readable JSON Envelopes

Every JSON invocation returns exactly one JSON document on `stdout`. Diagnostic logs are routed to `stderr`.

### Success Envelope (Schema Version 1)

```json
{
  "schema_version": 1,
  "status": "ok",
  "message": "Policy is valid",
  "data": {
    "config": "/project/sentinel.yml",
    "level": "L1",
    "rules": 2
  }
}
```

### Error Envelope

```json
{
  "schema_version": 1,
  "status": "error",
  "error": {
    "code": "POLICY_PARSE_FAILED",
    "message": "Unknown field `unsupported_key` on line 12"
  }
}
```
