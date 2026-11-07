# AgentBox Threat Model (Phase 1)

Status: draft, pre-implementation. Companion to [AgentBox_Concept_and_MVP_EN.md](./AgentBox_Concept_and_MVP_EN.md) and [ADR-0001](./adr/0001-phase1-architecture.md).

AgentBox enforces **specific boundaries** around an AI agent. It does not claim complete visibility into everything the agent does, and it is **not** a hardened virtual-machine boundary.

## 1. Assets

| # | Asset | Why it matters |
| --- | --- | --- |
| A1 | Host filesystem outside the selected workspace (home dir, SSH keys, browser profiles, other repos) | Theft or destruction |
| A2 | Provider credentials (LLM API keys) | Financial loss, impersonation |
| A3 | MCP server credentials (GitHub tokens, DB credentials, etc.) | Lateral access to external systems |
| A4 | Workspace contents (source code, local secrets such as `.env`) | Exfiltration; integrity |
| A5 | Local network and cloud metadata services (LAN hosts, `169.254.169.254`, host services on loopback/bridge) | Pivoting, credential theft |
| A6 | Docker engine and its socket | Equivalent to host root |
| A7 | AgentBox policy and audit data (SQLite) | Integrity of enforcement and evidence |
| A8 | AgentBox control plane (controller API, UI, gateway↔controller channel) | Policy tampering |

## 2. Adversaries and entry points

| # | Adversary | Capability assumed |
| --- | --- | --- |
| T1 | **Prompt-injected agent** — benign agent steered by malicious text in a web page, issue, file or tool result | Arbitrary code execution inside the agent container as the agent user; arbitrary tool calls; can start any local process (including processes that speak MCP) |
| T2 | **Malicious or compromised MCP server / remote MCP response** | Returns hostile tool descriptions, results, server-to-client requests (sampling/elicitation/roots), or oversized/malformed JSON-RPC |
| T3 | **Malicious LLM endpoint or response** | Returns content that triggers T1 behavior |
| T4 | **Malicious dependency inside the agent image** | Same as T1 from container start |
| T5 | **Other local user / local web page** (e.g. a browser tab) | Attempts to reach the controller UI/API on localhost (CSRF, DNS rebinding) |
| T6 | **Curious-but-honest user error** | Over-broad mounts, over-broad allow rules |

Out of adversary scope for Phase 1: a malicious host administrator, malicious Docker engine, physical access.

## 3. Trust boundaries

```text
[Host OS / user]  ──trusted──  Launcher (CLI)  ──Docker API──>  [Docker engine]
                                                                   │
        ┌──────────────────────────────────────────────────────────┤
        │ control network (no agent attached)                      │
        │   Controller + SQLite + UI                               │
        │      ▲            ▲                                      │
        │      │ decisions  │ decisions                            │
        ▼      │            │                                      │
   Net gateway ─────  MCP gateway ───> MCP servers (own containers, own creds)
        │ ▲                  ▲
 egress │ │ agent network    │ agent network
        │ │ (internal, isolated)
        ▼ │                  │
   Internet/LLM        [Agent sandbox]  ← UNTRUSTED
```

Boundaries that AgentBox must enforce:

- **B1 Agent ↔ network:** the agent network is `--internal` with `gateway_mode_ipv4=isolated`; its only reachable peers are the gateways.
- **B2 Agent ↔ host:** only the selected workspace is bind-mounted; no `docker.sock`, no host secrets, unprivileged, all capabilities dropped.
- **B3 Agent ↔ MCP servers:** MCP servers and their credentials live outside the agent container and are reachable only through the MCP gateway.
- **B4 Agent ↔ control plane:** the controller is **not** attached to the agent network.
- **B5 Browser/local user ↔ controller:** loopback-only binding, per-run auth token, Origin/Host validation, CSRF protection.
- **B6 Gateways ↔ controller:** authenticated with per-session tokens; fail closed if unreachable.

## 4. Threats and mitigations

| ID | Threat | Mitigation (planned task) | Verification |
| --- | --- | --- | --- |
| TM1 | Agent ignores `HTTP_PROXY` and opens direct sockets (TCP/UDP/ICMP/raw) | Agent network has no external route (`--internal`); no default route | Network spike; `neg-tests` |
| TM2 | DNS exfiltration / external resolver use | Embedded Docker DNS cannot resolve external names on `--internal`; gateway performs name resolution on CONNECT; gateway DNS logs queries | Network spike (resolver test); `neg-tests` |
| TM3 | Agent reaches host services via bridge gateway IP (INPUT path) | `com.docker.network.bridge.gateway_mode_ipv4=isolated` removes the host-side bridge IP. **Plain `--internal` leaks host services** (verified in spike) | Network spike (comparison probe); native-Linux CI |
| TM4 | IPv6 bypass | IPv6 disabled on agent network; verify on native Linux with IPv6-capable host | `neg-tests` (open item) |
| TM5 | SSRF via gateway: agent asks the gateway to CONNECT to LAN/metadata/loopback/Docker API | Gateway resolves and rejects private, loopback, link-local, metadata and CGNAT ranges (post-resolution IP check, no rebinding); gateway egress hardened | `net-gateway`; `neg-tests` |
| TM6 | Policy bypass via domain fronting / SNI mismatch / alternate ports | Policy is host:port at CONNECT time; **TLS content is not inspected** (documented limit); deny by default | Documented limit |
| TM7 | Agent attacks other containers on its network (gateways) | Gateways expose only the proxy/DNS/MCP ports; run non-root, minimal images; no admin ports on the agent network | `sandbox-hardening`; `neg-tests` |
| TM8 | Container escape / kernel exploit | Non-root, `cap-drop ALL`, `no-new-privileges`, seccomp default, pids/mem limits, no privileged/host namespaces. Residual risk accepted for Phase 1; gVisor/VM in Phase 4 | `neg-tests`; documented limit |
| TM9 | Workspace mount abuse (symlink, hard link, special files, mounting `/` or `$HOME`) | Canonical-path validation, deny-list of sensitive paths, private mount propagation, warnings | `sandbox-hardening` |
| TM10 | Destructive writes in workspace | **Accepted in Phase 1** (direct bind mount, no rollback). Users warned; recommend Git/backups | Documented limit |
| TM11 | Docker socket exposure | Never mounted into agent/MCP/controller; only the host launcher talks to Docker | `sandbox-hardening`; code review rule |
| TM12 | MCP tool call outside policy | MCP gateway enforces allow/deny **before forwarding** `tools/call`; filters `tools/list`; blocks batches that contain denied calls; fail closed on parse error | `mcp-gateway`; `neg-tests` |
| TM13 | Agent spawns its own local MCP process (stdio) to gain capabilities | Cannot be prevented; such a process has no external capability beyond the agent's own network/mount limits | Documented limit; `neg-tests` |
| TM14 | MCP server abuse (confused deputy; over-privileged creds) | Servers in own containers with least-privilege creds; tool-level policy; approvals | `mcp-stdio-bridge` |
| TM15 | Malicious server-to-client requests (sampling, elicitation, roots) | Block by default at the gateway; allow only by explicit policy | `mcp-gateway` |
| TM16 | Hostile MCP responses (prompt injection, huge payloads, SSE floods) | Size/time/rate limits; responses not trusted; audit metadata only | `mcp-gateway` |
| TM17 | Secret leakage: provider key visible to agent | Keys held in host keyring and injected by gateway; agent gets dummy credentials | `init-secrets`; `neg-tests` |
| TM18 | Secret leakage into audit logs/UI | Field- and pattern-based redaction; no prompts/file contents by default | `audit-core` |
| TM19 | Controller/UI attacked from browser (CSRF, DNS rebinding) | Bind to `127.0.0.1`, Host/Origin allow-list, per-run bearer token, no cookies for auth, CSRF protection on state-changing calls | `controller-api`, `ui-scaffold` |
| TM20 | Gateway↔controller impersonation by agent | Controller not on agent network; per-session secrets never given to the agent | `controller-api` |
| TM21 | Fail-open on outage | Gateways default-deny when controller/policy is unreachable; cached decisions expire | `net-gateway`, `mcp-gateway`; `neg-tests` |
| TM22 | Replay of blocked side-effecting operation after approval | Request IDs, idempotency, no auto-replay | `approval-flow` |
| TM23 | Supply chain (images, deps) | Pinned image digests, `govulncheck`, `npm audit`, dependency review, SBOM, signed releases | `repo-bootstrap`, `packaging` |
| TM24 | Resource exhaustion (fork bombs, disk, CPU, connection floods) | cgroup limits on agent; connection/rate limits in gateways | `sandbox-hardening`, gateways |
| TM25 | JSON parser differential: a message that the MCP gateway reads as an allowed call but the MCP server reads as a denied one (duplicate keys, case-variant keys, trailing data, batches) | Gateway rejects duplicate keys, case-variants of protocol keys, trailing data and batches, and decodes case-sensitively | `mcpgw` tests incl. mutation-checked cases and fuzzing |
| TM26 | Restricted address reached through an allowed name (rebinding/SSRF via the network gateway) | Gateway resolves names itself; restricted IP classes need an explicit IP rule; dials the validated IP and re-checks it at socket level | `netgw` tests; `neg-tests` |
| TM27 | Server-initiated MCP requests (sampling, elicitation, roots) used to drive the agent or extract data | Dropped by the MCP gateway; server gets an error reply | `mcpgw` tests |

## 5. Scope

### In scope (Phase 1)

- Linux + Docker Engine; one agent container per session.
- Outbound network policy (host:port) for HTTP proxy / CONNECT and DNS.
- MCP over Streamable HTTP and stdio-via-bridge, tool-level allow/deny, approvals.
- Local controller, SQLite audit/policies, React UI on loopback.

### Out of scope / documented non-goals

- TLS interception; HTTPS URL/payload visibility (only host:port/SNI metadata).
- Auditing or rolling back individual local file operations in the writable workspace.
- Preventing local processes (including MCP-speaking ones) from existing inside the container.
- Defending against container-escape zero-days, malicious host admins, or malicious Docker engine.
- Windows/macOS native enforcement (Docker Desktop is a development convenience, not a validated target).
- Protecting data the user **explicitly allows** to egress (e.g. allowed LLM provider sees the prompt).

## 6. Fail-closed rules

1. No policy decision available → **deny**.
2. Controller unreachable → gateways deny new connections/calls; no stale allow beyond cached TTL (short, configurable).
3. Unparseable MCP message or oversize body → drop and log.
4. Approval timeout → deny.
5. Infrastructure container unhealthy → launcher stops the agent session rather than relaxing the network.

## 7. Required evidence before any "secure" claim

- Adversarial test suite (`neg-tests`) passing in CI on native Linux.
- Manual review of container privileges, mounts, and network rules (`demo` task).
- Published limitations (this document) and independent review.

## 8. Findings from Phase 0 spikes

- [Network isolation spike](./spikes/network-isolation.md): `--internal` + isolated gateway mode blocks direct TCP/UDP/ICMP/DNS/metadata/host-service access; plain `--internal` leaks host-namespace services (TM3).
- [MCP & agent compatibility spike](./spikes/mcp-and-agents.md).
