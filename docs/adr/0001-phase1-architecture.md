# ADR-0001: Phase 1 architecture decisions

- Status: accepted
- Date: 2026-11-07

## Context

The concept document ([AgentBox_Concept_and_MVP_EN.md](../AgentBox_Concept_and_MVP_EN.md)) leaves several Phase 1 choices open. These were decided with the project owner before implementation started. See [threat-model.md](../threat-model.md) for the security rationale.

## Decisions

| # | Decision | Notes |
| --- | --- | --- |
| 1 | **License: Apache-2.0** | Explicit patent grant; contributions licensed under Apache-2.0. |
| 2 | **Network enforcement: Docker networks + gateway container; no host iptables/nftables** | Agent network is `--internal` and created with `com.docker.network.bridge.gateway_mode_ipv4=isolated`. The gateway is dual-homed (agent network + egress network). Chosen because it needs no host root rules and works the same across Docker hosts. Verified by the [network spike](../spikes/network-isolation.md). |
| 3 | **Gateway scope: HTTP proxy + CONNECT + DNS resolver only** | No transparent TCP/UDP redirect. Non-proxy-aware tools simply cannot connect (fail closed). No TLS interception. |
| 4 | **MCP: Streamable HTTP + stdio bridge** | stdio servers run in separate isolated containers behind a bridge that exposes Streamable HTTP to the MCP gateway. (The README previously listed the stdio bridge under Phase 2; it moves into Phase 1.) |
| 5 | **Agents: Hermes (reference), Codex CLI, Claude Code, OpenCode, generic image** | Hermes is built first; others are thin adapters subject to license/installation verification. |
| 6 | **Controller runs in a container; host launcher performs all Docker operations** | Controller and gateways never see `docker.sock`. The controller is **not** attached to the agent network. |
| 7 | **Dynamic approvals in MVP** | allow once / session / persist rule / deny; timeout → deny; no automatic replay. |
| 8 | **Credentials: host OS keyring (fallback 0600 file), injected by gateway** | Agent receives dummy credentials; real keys never enter the agent container. |
| 9 | **Repository layout: single Go module** | `cmd/{agentbox,controller,netgw,mcpgw}`, `internal/`, `web/`, `deploy/`, `test/`. |

## Consequences

- Plain `--internal` is **not** sufficient: it leaves host-namespace services reachable through the bridge IP. `gateway_mode_ipv4=isolated` is mandatory (needs a Docker Engine version that supports it; the launcher's `doctor` must check this and refuse to run otherwise).
- Because there is no transparent redirect, each supported agent must honor `HTTPS_PROXY`/`HTTP_PROXY` or be configured with an explicit endpoint. Agents that ignore proxy settings will not work until adapter-specific shims exist; they will fail closed, not open.
- The gateway holds provider credentials, so it is a high-value target and must be minimal, non-root and carefully reviewed.
- Containerized controller + host launcher means a small authenticated launcher↔controller interface is needed (the launcher creates sessions/tokens; the controller never calls Docker).
- Docker Desktop (macOS/Windows) is usable for development, but only native Linux results count for security claims.

## Addendum: Phase 2 design decisions (2026-11-07)

| # | Decision | Notes |
| --- | --- | --- |
| 10 | **No standalone DNS server** | Refines decision 3. Agents resolve nothing: on the isolated network external names do not resolve (network spike), and proxy-aware clients let the gateway resolve names. The gateway's own resolver is policy-checked, logged and rebinding-safe. A DNS server would add a tunneling channel for no benefit. |
| 11 | **LLM credentials injected by reverse-proxy routes** | Without TLS interception a CONNECT tunnel cannot be modified, so the agent's LLM base URL points at `http://netgw/llm/<provider>` (plain HTTP inside the isolated network) and the gateway adds the real key. The agent only holds a dummy key. |
| 12 | **"Persist" approvals are saved in agent scope** | A persisted approval allows that exact destination/tool for this agent in all sessions; "session" approvals live in the session scope. Explicit deny rules can never be approved. |
| 13 | **Own Go stdio bridge** | Minimal, auditable code instead of wrapping a third-party Node gateway; it adds bearer auth, a minimal child environment, ID namespacing and fail-closed exit. |
| 14 | **Approval timeouts are configurable per entity type** | Network (default 60 s) and MCP (default 120 s), 5–600 s, via settings. |
