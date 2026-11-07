# AgentBox Phase 1 (MVP) — Task List

Tracking document for the Phase 1 MVP described in [AgentBox_Concept_and_MVP_EN.md](./AgentBox_Concept_and_MVP_EN.md). Mark tasks `[x]` when complete.

## Decisions

| Area | Decision |
| --- | --- |
| License | Apache-2.0 |
| Network enforcement | Docker internal network + gateway container (no host iptables) |
| Gateway scope | HTTP/HTTPS proxy (CONNECT) + DNS resolver only; no TLS interception |
| MCP | Streamable HTTP + stdio bridge (isolated sidecar containers) |
| Agents | Hermes (reference), Codex CLI, Claude Code, OpenCode, generic custom image |
| Controller | Runs in a container; host launcher performs all Docker operations (no `docker.sock` exposure) |
| Approvals | Dynamic: allow once / session / persist rule / deny, via UI |
| Credentials | Host OS keyring (fallback 0600 file); injected by gateway, never visible to agent |
| Repo layout | Single Go module: `cmd/`, `internal/`, `web/` |

## Phase overview

| Phase | Focus | Depends on |
| --- | --- | --- |
| 0 | Groundwork: repo, threat model, spikes | — |
| 1 | Core: data model, policy, audit, controller | 0 |
| 2 | Gateways: network, MCP, stdio bridge, approvals | 0, 1 |
| 3 | Launcher, sandbox hardening, secrets | 0 (net spike), 1 |
| 4 | Web UI | 0, 1 |
| 5 | Agent adapters | 2, 3 |
| 6 | Verification: negative, E2E tests | 2–5 |
| 7 | Release: packaging, docs, demo | 6 |

---

## Phase 0 — Groundwork

- [x] **repo-bootstrap** — Repository bootstrap & licensing
  - [x] Add Apache-2.0 `LICENSE`; update README license section
  - [x] `go.mod` (single module); dirs `cmd/{agentbox,controller,netgw,mcpgw}`, `internal/`, `web/`, `deploy/`, `test/`
  - [x] `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`, Makefile/Taskfile
  - [x] CI (GitHub Actions): `go vet`, golangci-lint, unit tests, `govulncheck`, UI lint/build, dependency scanning *(workflow written; not yet run on GitHub — `go vet`/`go test`/`go build` verified locally)*
- [x] **threat-model** — Threat model & ADRs
  - [x] [`docs/threat-model.md`](./threat-model.md): assets, adversaries (prompt-injected agent, malicious MCP server/response), trust boundaries
  - [x] In-scope vs out-of-scope (container escape, TLS payloads, local FS ops); fail-closed rules
  - [x] [ADR-0001](./adr/0001-phase1-architecture.md) recording the decisions table above
- [x] **net-spike** — Docker network isolation spike *(after threat-model)* — see [network-isolation.md](./spikes/network-isolation.md)
  - [x] Internal Docker network for agent; gateway attached to internal + egress networks
  - [x] Verify agent cannot reach internet, LAN, `169.254.169.254`, host gateway, Docker API via TCP/UDP/IPv4/DNS/loopback *(IPv6 inconclusive: host has no IPv6)*
  - [x] Verify container DNS (embedded resolver) cannot resolve external names on the internal network; decide IPv6 handling and DNS pointing at gateway *(native-Linux recheck carried to `neg-tests`)*
  - [x] Document findings and residual risks (key finding: plain `--internal` leaks host services; `gateway_mode_ipv4=isolated` required)
- [x] **mcp-spike** — MCP protocol & agent configuration review *(after threat-model)* — see [mcp-and-agents.md](./spikes/mcp-and-agents.md)
  - [x] Study Streamable HTTP (JSON-RPC over POST/SSE, sessions, `initialize`, `tools/list`, `tools/call`) and stdio framing
  - [x] Per agent (Hermes, Codex CLI, Claude Code, OpenCode): install method, license, LLM endpoint/proxy/MCP configuration *(from docs; empirical handshake capture carried to adapter tasks)*
  - [x] Output compatibility matrix
## Phase 1 — Core services

Reference: [controller-api.md](./controller-api.md).

- [x] **data-model** — SQLite schema & migrations *(after repo-bootstrap)*
  - [x] Tables: `sessions`, `events`, `policies` (versioned, scoped), `approvals`, `policy_history`, `settings`
  - [x] Embedded migration runner, pure-Go SQLite driver, WAL mode *(persistent volume wiring belongs to `launcher-core`)*
  - [x] Repository layer + tests
- [x] **policy-engine** — Policy engine *(after repo-bootstrap)*
  - [x] Parse/validate YAML/JSON (agent, workspace, network, mcp, audit)
  - [x] Inheritance global > agent > session > tool, deny precedence
  - [x] Matching: host:port, wildcard, CIDR, tool names
  - [x] Decision output includes rule ID + policy version
  - [x] Live reload; table-driven and fuzz tests
- [x] **audit-core** — Audit/event pipeline *(after data-model)*
  - [x] Event model; secret redaction (headers, tokens, keys, MCP args)
  - [x] No prompts/file contents by default (explicit opt-in only)
  - [x] Async batched SQLite writer; pub/sub for live stream
  - [x] JSONL export; retention pruning
- [x] **controller-api** — Controller service & API *(after policy-engine, audit-core)*
  - [x] REST API: sessions, events, policies, settings *(approval endpoints move to `approval-flow`; the `approvals` table and store methods exist)*
  - [x] SSE live stream (resumable with `Last-Event-ID`)
  - [x] Authenticated gateway↔controller channel (per-session tokens): decision lookup/cache TTL, event ingest; `internal/gwclient` client
  - [x] Loopback default bind; CSRF/Origin/Host checks; admin bearer token
  - [x] Fail closed when controller unreachable (gateway client denies on any error) or audit unavailable (controller denies)
  - [ ] Follow-up: enforce `audit.enabled` / `audit.redact_secrets` per policy (currently always on) — see [Known limits](./controller-api.md#known-limits)
## Phase 2 — Gateways

- [ ] **net-gateway** — Network gateway *(after net-spike, controller-api)*
  - [ ] HTTP proxy + CONNECT handler with per-connection policy check
  - [ ] DNS resolver: policy-checked, logged, blocks private/loopback/link-local/metadata results, rebinding protection
  - [ ] Log host/SNI metadata only (no TLS interception)
  - [ ] Harden gateway's own egress (deny RFC1918, metadata, Docker API)
  - [ ] Inject LLM provider credentials
  - [ ] Fail closed
- [ ] **mcp-gateway** — MCP gateway (Streamable HTTP) *(after mcp-spike, controller-api)*
  - [ ] Proxy POST + SSE with session IDs; parse JSON-RPC
  - [ ] Enforce allow/deny on `tools/call` before forwarding; filter `tools/list`
  - [ ] Redacted argument logging; approval hook
  - [ ] Upstream credentials stay in gateway; per-server config; remote MCP support
  - [ ] Size/time limits; fail closed on parse errors
- [ ] **mcp-stdio-bridge** — stdio MCP bridge/sidecar *(after mcp-gateway)*
  - [ ] Run stdio servers in separate isolated containers (non-root, cap-drop, limited network/mounts, scoped credentials)
  - [ ] Bridge exposes them as Streamable HTTP to the MCP gateway; launcher manages lifecycle
  - [ ] Examples: filesystem (scoped read-only mount), GitHub, PostgreSQL (scoped DB user)
  - [ ] Test: agent cannot reach MCP server containers directly
- [ ] **approval-flow** — Dynamic approvals *(after net-gateway, mcp-gateway)*
  - [ ] Pending-approval queue; gateway holds request with timeout → deny
  - [ ] Decisions: allow once / session / persist rule / deny; stored with actor + expiry
  - [ ] Request IDs and idempotency; no auto-replay of blocked side-effecting operations
  - [ ] Works for both network destinations and MCP tools

## Phase 3 — Launcher & sandbox

- [ ] **launcher-core** — Launcher/CLI core *(after repo-bootstrap, net-spike)*
  - [ ] Docker Engine API on host only: session lifecycle, networks, volumes, infra containers, image pull by digest, health checks, cleanup
  - [ ] Config generation
  - [ ] Commands: `init`, `run <agent> --workspace`, `ui`, `policy list` (+ add/remove), `status`, `doctor`, `stop <session-id>`
  - [ ] Interactive TTY attach to agent
- [ ] **sandbox-hardening** — Agent container hardening *(after launcher-core)*
  - [ ] Non-root, `cap-drop ALL`, `no-new-privileges`, default seccomp, read-only rootfs where feasible, tmpfs
  - [ ] pids/memory/CPU limits; no privileged/host network/pid/ipc; no `docker.sock`; no host secrets
  - [ ] Mount validation: canonical path, reject home dir, `~/.ssh`, `/`, `/var/run`; check symlinks, special files, nested mounts, hard links; private propagation
  - [ ] Warning + confirmation about direct host writes (use Git/backups)
- [ ] **init-secrets** — `agentbox init` & secrets *(after launcher-core)*
  - [ ] Provider selection: Ollama, OpenAI-compatible/OpenRouter, OpenAI, Anthropic
  - [ ] Credentials in host keyring (fallback 0600 file); injected by gateway
  - [ ] Choose workspace + default policy; generate default policy YAML; config dir layout
  - [ ] `doctor` checks: Docker version, Linux, rootless, IPv6

## Phase 4 — Web UI

- [ ] **ui-scaffold** — React/TypeScript scaffold *(after repo-bootstrap)*
  - [ ] `web/`: Vite + React + TS, API client, SSE hook, routing
  - [ ] Served/embedded by controller; localhost only; auth token; CSRF protection
  - [ ] ESLint + tests (Vitest/Playwright)
- [ ] **ui-screens** — UI screens *(after ui-scaffold, controller-api)*
  - [ ] Dashboard: running sessions, blocked attempts
  - [ ] Events: live filterable/searchable table (ts, agent, session, direction, destination, transport, operation, result, latency, rule); JSONL export
  - [ ] Policies: live edit of network/MCP rules, change history, allow-once/deny, pending approval prompts
  - [ ] Settings: providers, mounts, audit retention
  - [ ] Agent and MCP inventories

## Phase 5 — Agent adapters

- [ ] **agent-hermes** — Hermes adapter (reference) *(after launcher-core, net-gateway, mcp-gateway)*
  - [ ] Image/launch template; LLM, proxy and MCP config pointing to gateways only
  - [ ] First-run flow; end-to-end task in writable workspace with changes visible on host
- [ ] **agent-codex** — Codex CLI adapter *(after agent-hermes)*
  - [ ] Verify install/licensing; image and config; works under default-deny; smoke test
- [ ] **agent-claude** — Claude Code adapter *(after agent-hermes)*
  - [ ] Verify install/licensing; image and config; handle telemetry/update endpoints under default-deny; smoke test
- [ ] **agent-opencode** — OpenCode adapter *(after agent-hermes)*
  - [ ] Verify install/licensing; image and provider/MCP config; smoke test
- [ ] **agent-generic** — Generic custom-image mode *(after agent-hermes)*
  - [ ] `agentbox run --image <ref>` with adapter spec (env, mounts, command, proxy/MCP injection)
  - [ ] Document adapter format

## Phase 6 — Verification

- [ ] **neg-tests** — Negative/bypass test suite *(after sandbox-hardening, mcp-stdio-bridge, agent-hermes)*
  - [ ] Direct TCP, DNS to external resolvers, IPv6, UDP, `curl` without proxy env, raw sockets
  - [ ] LAN and metadata access; Docker socket; unmounted host paths
  - [ ] Path traversal, symlink and hard-link escape; container privileges/capabilities
  - [ ] stdio MCP process started inside agent gets no external capability
  - [ ] Denied MCP tool blocked before execution
  - [ ] Controller down → fail closed
- [ ] **e2e-tests** — E2E & persistence tests *(after ui-screens, approval-flow, agent-hermes)*
  - [ ] Hermes task end-to-end; allowed LLM call succeeds
  - [ ] Live policy change affects new connections; document existing-connection/cache behavior
  - [ ] Policies and audit survive infrastructure restart
  - [ ] Events carry session ID + rule ID; UI shows events live

## Phase 7 — Release

- [ ] **packaging** — Packaging & install UX *(after neg-tests, e2e-tests)*
  - [ ] Reproducible builds; multi-arch images with pinned digests
  - [ ] Signed binaries/checksums; release workflow; SBOM
  - [ ] Install docs/script (optional); dependency/image scanning (`govulncheck`, `npm audit`, Trivy)
- [ ] **docs** — Documentation *(after all agent adapters)*
  - [ ] Update README (status, quickstart, real commands; stdio bridge now in MVP)
  - [ ] Policy format reference; adapter guide; ADRs; security policy
  - [ ] Known limits: live-connection behavior, HTTPS visibility, host-mount writes
- [ ] **demo** — Showcase demo & security review *(after packaging, docs, agent-generic, init-secrets)*
  - [ ] Scripted demo: prohibited MCP tool call and unauthorized network request both blocked and visible in UI
  - [ ] Manual review of privileges, network rules and mounts
  - [ ] Final check against Phase 1 acceptance criteria

---

## Acceptance criteria checklist

From section 12 of the concept document:

- [ ] Hermes completes a normal task in a writable workspace; changes visible on host
- [ ] Allowed LLM API calls succeed; forbidden destinations blocked at network layer even if `HTTP_PROXY` is ignored
- [ ] Private LAN, Docker socket and unmounted host paths are inaccessible
- [ ] Allowed MCP tool executes via gateway; denied tool blocked before execution
- [ ] All decisions logged with session ID and rule ID; UI shows events live
- [ ] Policy changes affect new connections/calls; existing-connection and cache behavior documented
- [ ] Policies and audit history survive infrastructure restarts
- [ ] Automated negative tests cover direct TCP, DNS, IPv6, UDP, curl without proxy env, stdio MCP, path traversal, container privileges
