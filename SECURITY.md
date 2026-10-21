# Security Policy

Sentinel is a local-first security policy gate, dependency vulnerability scanner, and cryptographic audit engine for AI coding agents and developer workflows.

See [docs/threat-model.md](docs/threat-model.md) for details on Sentinel's operational threat model, security invariants, trust boundaries, and scope limits.

## Reporting Security Vulnerabilities

Please report suspected vulnerabilities privately through GitHub Security Advisory reporting on this repository.

If private vulnerability reporting is unavailable, contact the repository maintainers privately without posting credentials, proof-of-concept exploits, or sensitive details in public issues or pull requests.

## Security Practices

1. **Pre-Action Policy Gate, Not an OS Sandbox**: Sentinel intercepts supported agent actions prior to execution using provider hook protocols and restricted modes. It is not an operating system sandbox (containers/cgroups/hypervisors).
2. **Deterministic Evaluation**: Sentinel never delegates policy or authorization decisions to an LLM.
3. **Zero Credential Leaks**: Never commit real API keys, tokens, or credentials to this repository. All test fixtures must use synthetic, dummy identifiers.
4. **Verified CI & Dependencies**: All release assets must pass automated acceptance suites, 4-target matrix checks, and cryptographic dependency review.
