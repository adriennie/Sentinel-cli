# Secrets scanning

`sentinel scan` runs every policy-enabled scanner. Use `--type secrets` for local secret patterns only or `--type dependencies` for dependency intelligence only. Explicitly selecting a disabled scanner is a configuration error; disabling both scanners is also an error. `--offline` never affects local secrets detection and prevents OSV requests. `--sbom` supplies dependency input only and cannot be combined with `--type secrets`.

Implemented rule families: GitHub tokens (SEC-GITHUB-001), GitLab tokens (SEC-GITLAB-001), Slack tokens (SEC-SLACK-001), Stripe live secret/restricted keys (SEC-STRIPE-001), AWS secret-access-key assignments (SEC-AWS-001), and PEM private-key headers (SEC-PEM-001). Findings are high severity. Generic passwords, arbitrary entropy, encrypted archives, provider validity checks, and Git history are not analyzed. A matching pattern can be a false positive; absence of a match does not establish that credentials are absent or the project is secure.

Findings contain a stable rule ID, redacted evidence `[REDACTED]`, relative file, one-based line and UTF-8 byte-column, remediation, and reachability `not_analyzed`. IDs hash only rule and location, never a credential value. No raw value, prefix, snippet, or credential hash is included in output or numeric audit summaries. Detected token patterns in filenames are redacted, and control characters in displayed paths are escaped.

Discovery respects ignore files by default, including ignored `.env` files. Use `--include-ignored` to include ignored files in secrets scanning. Hard exclusions always remain: `.git`, `.sentinel`, `node_modules`, `target`, `vendor`, `dist`, `build`, `.venv`, and `venv`. Symlinks are not followed. Binary files (NUL in the first 8192 bytes) are excluded. Non-UTF-8 text is reported as unsupported coverage. The scanner inspects working-tree files only; filesystem races are not prevented by an OS sandbox.

Limits: 1 MiB per file, 128 MiB total content, 10,000 discovered files, 100,000 findings across the combined report, 100,000 discovery entries, 64 directory levels, and a 120-second secrets-scan budget. Relevant read failures and limits produce incomplete coverage with diagnostics. Ignored/hard-excluded files and binary files are outside the stated scope. Dependency scanning has its separately documented limits.

Combined reports preserve available findings if either scanner is incomplete. Exit 7 (incomplete) precedes exit 4 (threshold findings). Quiet mode preserves findings and coverage diagnostics. JSON contracts are defined in `schemas/scan-output.schema.json` and the unified `schemas/command-output.schema.json`; dependency finding fields are preserved, while secret findings use location evidence without a package field.

All credential fixtures are synthetic and assembled during tests. Required tests never contact credential providers.
