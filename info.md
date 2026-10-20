# Project Idea: Sentinel AI

AI Agent Security, Code Vulnerability Detection & Autonomous Development Governance

Cybersecurity + AI + Developer Tools

#### 1. Project overview

Sentinel AI is a open-source, security first developer platform that monitors, analyzes, and controls changes made by AI coding agents while identifying vulnerabilities in software projects.

**Project vision**

Make AI-assisted software development secure,  transparent, and accountable  without slowing  developers down.

As AI coding assistants become more autonomous, developers increasingly allow them to modify files, install dependencies, execute terminal commands, and interact with external services.

This creates an important problem: How can developers trust AI-generated changes  before those changes affect their applications?

**Sentinel AI addresses this by combining three capabilities:**

- AI Agent Firewall: Intercepts dangerous agent actions and requires approval when necessary.
- Intelligent Vulnerability Scanner: Identifies security vulnerabilities and prioritizes those that can actually affect the application.
- Security Audit & Governance: Records agent activity, tracks decisions, and provides evidence for security reviews.

#### 2. How Sentinel AI works

!image.png

#### 3. Main features

**1. AI Agent Firewall**

Monitors agent requests to edit protected files, execute dangerous commands, install packages, or access sensitive information. Actions can be allowed, denied, or sent for human approval.

**2. Reachability-Aware Vulnerability Scanner**

Detects vulnerable dependencies and prioritizes findings using exploitability signals such as EPSS, CISA KEV, and whether vulnerable code is reachable from the application.

**3. AI-Specific Threat Detection**

Flags suspicious prompt injections in repository content, potentially hallucinated packages, insecure AI-generated code, and attempted secret exposure.

**4. Project Security Levels**

Four predefined levels automatically adjust protection rules, from hobby projects to highly sensitive production systems.

**5. Audit, Rollback & Incident Response**

Maintains a verifiable history of agent actions, supports checkpoints and rollback, and helps investigators understand what changed.

**6. Built-in Security Testing**

A `sentinel redteam` command tests security controls using simulated malicious instructions, unsafe edits, and dependency attacks.

#### 4. Security levels

| Level | Name | Behavior |
| --- | --- | --- |
| L0 | Sandbox | Log activity and basic vulnerability checks |
| L1 | Standard | Require approval for protected changes |
| L2 | Sensitive | Restrict writes, shell commands, and network access |
| L3 | Critical | Read-only agent workflow with human-reviewed patches |

Higher levels require stronger enforcement mechanisms, such as restricted execution environments and server-side CI checks.

#### 5. Example developer experience

A developer installs Sentinel and initializes security policies:

```bash
# Initialize the project
sentinel init --level L2

# Check configuration
sentinel doctor

# Scan for vulnerabilities
sentinel scan

# Run a guarded AI agent
sentinel guard -- claude

# Inspect security events
sentinel audit

# Test security controls
sentinel redteam
```

When the agent attempts a sensitive modification:

!image.png

#### 6. Recommended technology stack

| Component | Technology |
| --- | --- |
| CLI | Rust with Clap |
| Policy engine | Rust + YAML |
| Vulnerability data | OSV API, EPSS, CISA KEV |
| Code analysis | Tree-sitter, Semgrep integration |
| Agent integration | Native hooks, MCP proxy |
| Local storage | SQLite |
| Audit logging | Hash-chained JSONL |
| Dashboard | Next.js, TypeScript, Tailwind CSS |
| Backend API | Rust with Axum |
| CI integration | GitHub Actions |
| Testing | Rust tests, pytest, attack fixtures |

Architecture recommendation: Build the security engine in Rust as a local-first CLI. Make the web dashboard optional so the core protection works without a cloud account.

#### 7. MVP development roadmap

Suggested `16-week` plan for a focused prototype. The broader feature set can follow after evaluation.

!image.png

#### 8. Academic and commercial potential

**For an MSc dissertation, Sentinel AI can investigate:**

How effectively can layered security controls prevent unsafe or unauthorized actions by AI coding agents while minimizing developer friction?

The evaluation can measure action-blocking rates, false positives, bypass resistance,  task completion, performance overhead, and approval fatigue.

For a commercial product, Sentinel could follow an open core model: free local security controls and scanning, with paid team dashboards, centralized policy management,  SSO, audit evidence, and enterprise integrations.

#### 9. What makes this project distinctive?

The strongest feature is not simply vulnerability scanning or agent monitoring. It is the  connection between them.

Sentinel can evaluate an AI agent's proposed action in the context of the application's actual security risks. For example, an authentication edit touching a reachable vulnerable dependency can require more scrutiny than an ordinary UI change.

That gives the project a focused technical contribution, a meaningful research question, and a clear reason for developers to adopt it.

Recommended first milestone: Build a working CLI that protects selected files from one supported AI coding agent, requests approval before risky edits, and records every decision in a tamper-evident log. Add vulnerability-aware risk scoring once that foundation works reliably.

Version 0.0.1 — Core CLI

**Version 0.0.2 — Agent Protection**

Sentinel CLI

## Recommended Rust project structure

```
sentinel/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
│
├── crates/
│   ├── sentinel-cli/
│   ├── sentinel-core/
│   ├── sentinel-policy/
│   ├── sentinel-scanner/
│   ├── sentinel-audit/
│   └── sentinel-agent/
│
├── configs/
│   └── default-policy.yml
│
├── tests/
│   ├── fixtures/
│   └── integration/
│
├── docs/
│   ├── architecture.md
│   └── commands.md
│
└── .github/
    └── workflows/
        ├── ci.yml
        └── release.yml
```

Keep `sentinel-agent` minimal or inactive in v0.0.1. Its full implementation belongs in v0.0.2.

## Release acceptance criteria

| Requirement | v0.0.1 | v0.0.2 |
| --- | --- | --- |
| CLI installs and runs | Required | Required |
| Policy configuration | Required | Extended |
| Dependency and secrets scanning | Basic | Enhanced |
| Structured output | JSON | JSON + SARIF |
| Agent action interception | — | Required |
| Human approval gate | — | Required |
| Reachability analysis | — | Prototype |
| Audit integrity verification | — | Required |
| CI tests passing | Required | Required |

Important: Neither version should be described as providing complete security protection. Both  are early releases, and their documentation should clearly identify supported ecosystems, integrations, and enforcement limitations.

!image.png