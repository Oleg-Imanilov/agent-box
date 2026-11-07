# Security Policy

AgentBox is a pre-MVP security project. It is **not yet a trustworthy security boundary**; do not use it to contain untrusted agents on sensitive systems until a reviewed implementation and published adversarial tests exist. See [docs/threat-model.md](docs/threat-model.md) for scope and known limits.

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub's
[private vulnerability reporting](https://github.com/Oleg-Imanilov/agent-box/security/advisories/new)
for this repository. Do not open public issues for security bugs.

Include: affected component/version, reproduction steps, impact, and any suggested fix.
We aim to acknowledge reports within 7 days. This is a best-effort, volunteer-run project.

## Scope

In scope: sandbox escapes caused by AgentBox misconfiguration, policy bypass (network or MCP), secret leakage into agent containers or audit logs, controller/UI authentication or CSRF flaws, fail-open behavior.

Out of scope: vulnerabilities in Docker, the Linux kernel, or third-party agents themselves (report those upstream), and the documented non-goals in the threat model (e.g. TLS payload inspection, auditing of local file operations in the writable workspace).
