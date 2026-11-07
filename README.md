# AgentBox

**A local-first, open-source security sandbox for AI agents.**

AgentBox aims to run existing AI agents in restricted environments, mediate their network and Model Context Protocol (MCP) access, and give users a live view of what their agents are doing — without requiring changes to the agents themselves.

> **Project status: design / pre-MVP.** AgentBox is not yet a working security product. The commands and configuration shown below are **proposed interfaces**, not currently available features.

## Why AgentBox?

AI coding agents can execute code, modify project files, call external services, and use MCP tools. Their default permissions are often broader than the task requires. Prompt injection, accidental tool use, and unreviewed data transfers can therefore have real consequences.

AgentBox is designed around a simple idea: **external capabilities should be explicitly granted, observable, and revocable.**

## Planned capabilities

- **Isolated agent execution:** Run agents in non-privileged Docker containers with access only to selected workspaces.
- **Enforced network boundaries:** Restrict outbound connections at the container/network layer, not just through `HTTP_PROXY` environment variables.
- **MCP gateway:** Route MCP tool calls through a policy-enforcing gateway. MCP servers run outside the agent container, with separate credentials and permissions.
- **Live audit:** Inspect network and MCP decisions, including the agent, destination, tool, rule, and result.
- **Dynamic policies:** Allow or deny destinations and MCP tools, with optional per-request approval.
- **Local-first storage:** Keep policy and audit data locally, using SQLite in a persistent volume.
- **Agent-agnostic design:** Start with Hermes, then support Codex CLI, Claude Code, OpenCode, and custom agent images.

## Architecture (proposed)

```text
Host
│
├── AgentBox CLI / launcher
│   └── manages containers without exposing Docker socket to agents
│
├── AgentBox controller + web UI + SQLite
│
├── Network gateway ──────────────> approved LLM APIs / websites
│
├── MCP gateway ──────────────────> isolated MCP servers / remote MCP
│
└── Agent sandbox (e.g. Hermes)
    ├── selected project directory (writable in MVP)
    ├── no Docker socket or host secrets
    └── restricted outbound network → gateways only
```

The gateway must be the **only permitted network egress path**, enforced by network isolation and firewall rules. A conventional HTTP proxy alone is not sufficient: programs can bypass proxy environment variables.

## Phase 1: Minimum viable product

The first release focuses on a useful, demonstrable local workflow on **Linux + Docker**:

1. Launch Hermes in a restricted container with a writable project directory.
2. Allow approved LLM endpoints and block unauthorized network connections.
3. Route supported MCP calls through a separate gateway; block disallowed tools before execution.
4. Show allowed and blocked actions in a local React dashboard.
5. Update policies while the agent is running, with persistent SQLite audit history.
6. Ship a simple CLI and reproducible tests for network and MCP bypass attempts.

**Important:** In Phase 1, workspace writes affect the host directory immediately. There are no snapshots or rollback guarantees. Use Git and backups.

### Intended user experience

Once implemented, the workflow is intended to look like this:

```bash
# Illustrative commands — not implemented yet
agentbox init
agentbox run hermes --workspace .
agentbox ui
agentbox policy list
agentbox stop <session-id>
```

The user would need Docker and a small AgentBox launcher. Infrastructure containers, gateways, and local audit storage would be managed automatically.

## Example policy (proposed)

```yaml
agent: hermes
workspace:
  path: ./project
  mode: read-write
network:
  default: deny
  allow:
    - api.openai.com:443
mcp:
  github:
    allow_tools:
      - get_file_contents
      - list_issues
    deny_tools:
      - delete_repository
audit:
  enabled: true
  redact_secrets: true
```

The policy format is conceptual and may change. A future policy engine would support global, agent, and session scopes, plus temporary approvals.

## Roadmap

| Phase | Focus |
| --- | --- |
| **1 — Local MVP** | Linux/Docker sandbox, enforced network egress, MCP gateway (Streamable HTTP + stdio bridge), SQLite audit, React UI, dynamic approvals, Hermes/Codex CLI/Claude Code/OpenCode adapters |
| **2 — Hardening & compatibility** | Stronger DNS/IPv6 controls, secrets handling, more agents, Windows/macOS via Linux VM |
| **3 — Controlled file changes** | Copy-on-write workspaces, file diffs, apply/discard, checkpoints and rollback workflows |
| **4 — Advanced security** | gVisor/VM isolation, policy-as-code, richer telemetry, RBAC, SIEM/OpenTelemetry and enterprise integrations |

## Technology direction

- **Go:** launcher, controller, network gateway, MCP gateway
- **React + TypeScript:** local dashboard
- **SQLite:** audit events, policies, sessions, approvals
- **Docker:** sandbox and service isolation
- **YAML/JSON:** initial declarative configuration

## Security model and limitations

AgentBox is intended to enforce *specific boundaries*, not claim complete visibility into everything an agent does.

- A container is **not a virtual machine**; kernel and runtime vulnerabilities remain in scope.
- HTTPS traffic cannot be fully inspected without TLS interception. Connection metadata is not the same as full request visibility.
- Agents may start local processes, including processes speaking MCP. The goal is to deny those processes unauthorized **external capabilities**, not to prove they never exist.
- Local file operations inside a writable mount are **not automatically proxied or individually audited** in the MVP.
- An agent can modify or delete files within its writable workspace; future copy-on-write support will address review and rollback.
- MCP servers require their **own** isolation and least-privilege credentials. Moving them outside the agent container is necessary but not sufficient.
- Audit logs must redact secrets and avoid collecting private prompts or file contents by default.
- Security claims require a threat model, adversarial tests, and independent review. AI-generated code alone does not establish a trustworthy security boundary.

**Fail closed:** If policy enforcement becomes unavailable, new unauthorized operations should not proceed.

## Contributing

AgentBox is at the concept stage. See the [MVP task list](docs/MVP_Task_List.md), [threat model](docs/threat-model.md) and [architecture decisions](docs/adr/0001-phase1-architecture.md). Contributions and discussion are welcome, particularly around Docker network enforcement, MCP transports and isolation, threat modeling, cross-platform sandboxing, and developer experience.

Before relying on AgentBox for sensitive workloads, wait for a reviewed implementation and published security tests.

## License

AgentBox is licensed under the [Apache License 2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
