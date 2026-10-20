# Local auditing and doctor diagnostics

## Audit history

```sh
sentinel audit
sentinel audit --limit 50 --event scan.completed --format json
```

Sentinel appends events to `<project>/.sentinel/audit.jsonl` after each parsed command with a resolvable project root. Events include `command.completed`, plus `policy.validated` for policy checks and `scan.completed` for scan attempts. Failed validation and failed scan attempts are recorded too. Help, version output, invalid CLI arguments, and commands whose project root cannot be resolved are not recorded. An audit read shows a snapshot before its own completion event is appended.

`audit.enabled: false` disables writes only when the policy is valid. Invalid or missing policy does not silently disable logging. History can be read even when configuration is invalid or logging is disabled.

Events contain schema version 1, UUID event/invocation IDs, UTC RFC3339 timestamps, typed command/event/outcome values, exit codes, and optional numeric scan counts. No raw arguments, filesystem paths, credentials, environment variables, source snippets, policy values, advisory descriptions, or arbitrary error text are stored. Related events from one invocation share a `session_id`. The API has no free-form metadata field. Logs describe command completion outcomes; they do not claim agent-action interception or policy enforcement.

Writers hold a cooperative exclusive file lock across each event batch, then release it before syncing the file; success is returned only after sync completes. This preserves whole append batches without making other writers wait through disk flushes. Readers hold a shared lock while taking a bounded byte snapshot, then release it before parsing. Lock acquisition times out after two seconds. New Unix log files use mode 0600. Storage-directory symlinks, nonregular log files, and Unix hard-linked logs are rejected. Filesystem races involving an attacker replacing directories are outside these checks; this is not an OS sandbox.

Each record is bounded to 16 KiB, appends to 16 events per batch, and each log to 32 MiB. Oversized logs must be explicitly archived before commands can resume logging. There is no automatic deletion/rotation. Interrupted trailing records are separated with a newline before the next append; existing bytes are not rewritten. Readers omit malformed, unknown-field, invalid-schema, inconsistent-outcome, or unterminated records, report their count, and return incomplete history with exit 1. Rejected raw content is never echoed. Logs are not tamper-evident, authenticated, or independently verified.

History is sorted newest first by parsed timestamp, with reverse append order for equal timestamps. `--limit` accepts 1–10000 (default 50); `--event` accepts the three documented event types. Missing history returns an empty complete report.

Audit-write failures produce a stderr warning and `data.audit_logging: "failed"` without discarding command results. A previously successful operation then exits 1; existing nonzero outcomes (such as scan findings 4, invalid policy 3, or incomplete scan 7) remain unchanged. Successful writes report `recorded`; valid policy opt-out reports `disabled`. The recorded command outcome reflects the command operation before logging is attempted.

## Doctor

```sh
sentinel doctor
sentinel doctor --format json
sentinel doctor --project ./backend --config security.yml
```

Doctor runs offline. It reports build and supported policy-schema versions, project resolution, configuration validity, audit storage/readability, native dependency-input compatibility, cache storage, cached intelligence, and supported capabilities. It never queries OSV or invokes package managers or agents. Cache inspection examines up to 1000 discovered package identities, counting current, stale, missing, and invalid entries. Native discovery retains its documented bounds and exclusions; SBOM coverage is not inferred by doctor.

Storage checks create missing Sentinel storage directories and use temporary write/sync/delete probes. They do not edit the policy or dependency lockfiles. Doctor is itself audited when a project root is available and audit logging is enabled. Existing busy or oversized audit logs fail the storage checks.

Checks use stable IDs and `pass`, `warn`, or `fail` states, with remediation text. Missing cache data, unsupported inputs, disabled scanning/logging, and malformed-but-readable audit history are warnings. Unresolvable roots and unsafe/unwritable storage are failures (exit 1); invalid/missing policy uses exit 3. Warnings alone exit 0. Doctor reports local secrets-scanner availability and warns when policy disables it. Lack of runtime agent integration is reported as an intentional release boundary, not as active protection.

## JSON contracts

Both commands retain the existing version-1 result/error envelope: command execution results use `status: "ok"` with data, while command errors use `status: "error"` and a numeric error code. An `ok` envelope does not mean all doctor checks passed or audit history is complete. Inspect doctor `data.status`/`data.exit_code`, audit `data.complete`/`data.malformed_records`, `data.audit_logging`, and the process exit code.

Committed standalone JSON Schemas:

- `schemas/audit-event.schema.json`
- `schemas/audit-output.schema.json`
- `schemas/doctor-output.schema.json`

Integration tests validate actual outputs against these schemas, including RFC3339 formats, invalid-policy errors, malformed logs, storage failures, and missing project roots. Negative schema tests reject incomplete or inconsistent reports. The unified command-output schema also covers init, policy, scans, and argument errors. JSON mode always emits one document on stdout; stderr holds diagnostics. Quiet mode preserves audit records and doctor check details while suppressing the summary.
