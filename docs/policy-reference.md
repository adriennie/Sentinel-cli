# Sentinel Policy Reference Specification

This document provides the definitive specification for Sentinel policy configuration (`sentinel.yml`), security levels, rule schemas, glob matching rules, and evaluation semantics.

---

## 1. Schema v1 Specification

Every Sentinel policy file (`sentinel.yml`) must conform to `schema_version: 1`. An initialized policy template generated via `sentinel init --level L1` has the following structure:

```yaml
schema_version: 1
project:
  name: my-backend-service
  level: L1
policy:
  default_action: allow
  protected_paths:
    - src/auth/**
    - src/payments/**
    - .github/workflows/**
    - .env*
    - sentinel.yml
  rules: []
scanning:
  dependencies: true
  secrets: true
  offline: false
audit:
  enabled: true
  redact_secrets: true
```

### Top-Level Fields

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `schema_version` | integer | Yes | Must be integer `1`. Future schemas will increment this version. |
| `project` | object | Yes | Project identity and security level. Unknown keys rejected. |
| `policy` | object | Yes | Security rules, protected paths, and default action. |
| `scanning` | object | Yes | Scanner configuration and offline toggles. |
| `audit` | object | Yes | Audit logging configuration and redaction settings. |

> [!IMPORTANT]
> Sentinel's policy parser rejects unknown fields at every level (`#[serde(deny_unknown_fields)]`). File size is strictly bounded to 1 MiB (1,048,576 bytes) to prevent resource exhaustion attacks.

---

## 2. Security Levels (L0 to L3)

The project security level defines the baseline enforcement floor for all operations:

| Level | Name | Protected Path Writes | Unprotected File Writes | Shell & Network Execution |
| :---: | :--- | :--- | :--- | :--- |
| **L0** | **Permissive / Audit** | `log_only` | `allow` | Rule or Default (`allow`) |
| **L1** | **Standard Guarded** *(Default)* | `require_approval` | `allow` | Rule or Default (`allow`) |
| **L2** | **Strict Isolation** | `require_approval` | `allow` (within scope) | **`deny`** (all shell/network blocked) |
| **L3** | **Read-Only Lockdown** | **`deny`** | **`deny`** | **`deny`** (all writes, shell, network blocked) |

### Floor Logic

The security level acts as a non-bypassable floor:

- At **L0**: Writes to protected paths produce `log_only` events in the audit log rather than halting execution.
- At **L1**: Writes to protected paths require explicit developer approval (`sentinel approvals grant <ID>`).
- At **L2**: Shell execution (`shell.execute`) and network access (`network.access`) are strictly denied regardless of custom rules.
- At **L3**: All file write actions (`file.write`), shell execution, and network access are strictly denied.

---

## 3. Custom Rule Syntax

Projects can declare granular custom rules in the `policy.rules` array.

### Rule Structure

```yaml
policy:
  rules:
    - id: block-database-migrations
      action: file.write
      paths:
        - migrations/**
      decision: deny
      description: "Automated agent changes to database migrations are strictly forbidden."

    - id: approve-dependency-updates
      action: file.write
      paths:
        - Cargo.toml
        - Cargo.lock
        - package.json
        - package-lock.json
      decision: require_approval
      description: "Dependency lockfile changes require human review."

    - id: deny-curl-and-wget
      action: network.access
      paths: []
      decision: deny
      description: "Block all network access from agent tools."
```

### Rule Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | string | Unique rule identifier (non-empty, alphanumeric + hyphens/underscores). |
| `action` | string | One of: `file.read`, `file.write`, `shell.execute`, `network.access`. |
| `paths` | list[string] | List of project-relative glob patterns. Must be non-empty for `file.*` actions; must be empty (`[]`) for `shell.execute` and `network.access`. |
| `decision` | string | One of: `allow`, `log_only`, `require_approval`, `deny`. |
| `description` | string | Optional human-readable documentation explaining the purpose of the rule. |

---

## 4. Path and Glob Semantics

All paths in `protected_paths`, rule `paths`, and incoming agent actions must adhere to strict security constraints:

1. **Project-Relative**: Paths must not start with `/` or drive letters (`C:`).
2. **No Traversal**: Any path containing `..` as a component is rejected immediately.
3. **Normalized Separators**: Forward slashes (`/`) must be used. Backslashes (`\`) and colons (`:`) are rejected.
4. **No NUL Bytes**: Embedded null bytes (`\0`) trigger a validation error.
5. **Glob Matching**:
   - `*`: Matches characters within a single directory segment.
   - `**`: Matches zero or more nested directory segments recursively.
   - `?`: Matches any single character.
   - `[a-z]`: Character class matching.

---

## 5. Automated Policy Testing (`sentinel policy test`)

Sentinel supports deterministic policy testing to verify that rules behave as expected before deploying them to production or opening pull requests:

```sh
sentinel policy test
```

### Policy Test Scenarios

The policy test engine validates:

- Target path normalization (relative paths, escaping attempts).
- Precedence ordering: $\text{Deny} \succ \text{RequireApproval} \succ \text{LogOnly} \succ \text{Allow}$.
- Level floor enforcement across L0, L1, L2, and L3.
- Absence of duplicate rule IDs.
- Deterministic risk score calculations.

If any test assertion fails, the command exits with **Exit Code 5**, enabling simple integration into CI commit gates.
