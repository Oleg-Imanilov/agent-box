# Spike: MCP protocol and agent compatibility

Task `mcp-spike` (Phase 0). Goal: protocol facts needed for the MCP gateway and a compatibility matrix for the four target agents.

> **Provenance:** compiled by a research agent from official specs/repos and then summarized here. Individual facts have **not** been independently re-verified, and several agent behaviours are unverified until captured empirically (see [Open items](#open-items)). Treat this as a starting point, not a source of truth. Source URLs were cited in the research output (modelcontextprotocol.io specification pages for 2025-06-18 and 2026-07-28, and each agent's repository/docs).

## 1. MCP protocol facts for the gateway

### Spec eras

| Era | Versions | Model |
| --- | --- | --- |
| Legacy | 2024-11-05 → 2025-11-25 | `initialize`/`initialized` handshake, `Mcp-Session-Id`, resumable SSE (`Last-Event-ID`), server-initiated requests on a GET SSE stream |
| Modern | 2026-07-28 | Stateless: no handshake/sessions/GET stream; per-request protocol version in `_meta`; `server/discover`; sampling/elicitation/roots replaced by `InputRequiredResult` |

**Decision:** build the gateway for the **legacy session-based semantics (2025-06-18 / 2025-11-25)** — reported to be what all four agents currently speak — and keep protocol-version handling pluggable for 2026-07-28. The gateway should **pin** the protocol version it supports (reject others) rather than pass it through.

### Streamable HTTP (legacy)

- One MCP endpoint, `POST` and `GET`. POST carries exactly one JSON-RPC request/notification/response; the reply is `application/json` or an SSE stream scoped to that request; notifications/responses get `202`.
- Client sends `Accept: application/json, text/event-stream`.
- `GET` opens a standalone SSE stream for server-initiated requests/notifications (this is where sampling/elicitation/roots arrive). Server may return `405`.
- `Mcp-Session-Id` is minted by the server at `initialize`; the client echoes it on every request (`400` if missing, `404` if terminated); `DELETE` ends a session.
- `MCP-Protocol-Version` header is required after negotiation.
- Servers must validate `Origin` (DNS-rebinding defense) — the gateway should validate `Origin`/`Host` even on the container-internal network.
- JSON-RPC **batching was removed in 2025-06-18**; unwrap arrays defensively (or reject them) so a batch cannot smuggle a denied call.
- Auth is optional OAuth 2.1-based. All four agents can use a **static header** instead, matching "gateway injects upstream credentials."

### Messages to police

| Message | Direction | Gateway behavior |
| --- | --- | --- |
| `tools/call` (`params.name`) | client→server | **Primary enforcement point**; decide on the request before forwarding or opening any stream; check `method == "tools/call"` exactly |
| `tools/list` | client→server | Filter denied tools out of the response (paginated, follow `nextCursor`), **and** still enforce on `tools/call` |
| `notifications/tools/list_changed` | server→client | Forward; re-validate against policy rather than trusting cached lists |
| `sampling/createMessage`, `elicitation/create`, `roots/list` | server→client | **Deny by default**; allow only by explicit per-server policy (a second enforcement point on the GET-SSE path) |
| SSE `data:` frames (progress/logging) | server→client | Apply size/rate limits and redaction to every frame, not just the final response |

### Gateway gotchas

1. Mint gateway-side session IDs; never forward a client-supplied `Mcp-Session-Id` to a different upstream than the one that issued it.
2. Never authorize from a cached `tools/list`; check the name at `tools/call` time.
3. Block or pin protocol versions from upstreams so a hostile server cannot re-enable batching or other deprecated behavior.
4. Enforce body-size and time limits; fail closed on parse errors.
5. Multiple concurrent clients on one stdio server need ID namespacing (stdio has no multiplexing).

### stdio

- Newline-delimited UTF-8 JSON-RPC, no embedded newlines; `stdout` must carry only MCP messages (be defensive about stray lines); `stderr` is free-form logging.
- stdio has no sessions/Origin: trust = "you launched the process." The bridge is therefore where implicit process trust becomes network-reachable trust, so it needs authentication and isolation.
- Prior art (evaluate, do not assume): `supercorp-ai/supergateway` (stdio → Streamable HTTP/SSE) and `mcp-remote` (opposite direction). Decide in `mcp-stdio-bridge` whether to write our own small Go bridge (preferred for a minimal, auditable trusted base) or vendor/wrap one.

## 2. Agent compatibility matrix

| | **Hermes Agent** (`NousResearch/hermes-agent`) | **Codex CLI** (`openai/codex`) | **Claude Code** (`anthropics/claude-code`) | **OpenCode** (`anomalyco/opencode`, ex-`sst`) |
| --- | --- | --- | --- | --- |
| License | MIT | Apache-2.0 | **Proprietary** (no clear redistribution grant) | MIT |
| Install | curl installer; `pip install hermes-agent` (parity unverified); Docker (`debian:trixie`) | npm `@openai/codex`, brew, standalone binaries; no official image | native installer, brew, npm (deprecated); devcontainer feature | curl, npm; official Alpine image `ghcr.io/anomalyco/opencode` |
| Runtime | Python 3.11–3.14 + Node (installer-managed) | Rust binary (npm launcher needs Node ≥16) | Node ≥22 (per npm `engines`) | single Bun-compiled binary |
| Custom LLM endpoint + dummy key | `model.base_url` / `OPENAI_BASE_URL`, `OPENAI_API_KEY` | `[model_providers.<id>]` in `config.toml` | `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`; dummy-token gateway pattern documented | `providers.<id>.settings.baseURL` + headers |
| Proxy env vars | `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`/`ALL_PROXY` | honored (system proxy, then env) | `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` (no SOCKS) | honored; loopback must be in `NO_PROXY` |
| CA trust with CONNECT (no interception) | OS store / `SSL_CERT_FILE` | `CODEX_CA_CERTIFICATE` / `SSL_CERT_FILE` | bundled roots work; `NODE_EXTRA_CA_CERTS` optional | `NODE_EXTRA_CA_CERTS` |
| Other outbound hosts to handle under default-deny | none by default; **`npx`/pip at MCP connect time** | `chatgpt.com`/`auth.openai.com` (sign-in), `api.statsig.com` (disable `analytics.enabled=false`), update checks (`check_for_update_on_startup=false`) | `claude.ai`/`platform.claude.com` (login), telemetry (`DISABLE_TELEMETRY=1`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`), auto-update (`DISABLE_AUTOUPDATER=1`) | `opencode.ai` update (`"update":"disable"`), `models.dev` model catalog (avoid via fully custom `providers`/`models`) |
| MCP config | `mcp_servers:` in `~/.hermes/config.yaml` (stdio or `url`, `headers`) | `[mcp_servers.<name>]` in `~/.codex/config.toml` (`url` + `http_headers`) | `.mcp.json`; `--strict-mcp-config --mcp-config <file>` pins to one server set | `opencode.json` `mcp` (`type: remote`, `url`, `headers`, `oauth: false`) |
| Headless | `hermes -z "<prompt>"` | `codex exec "<task>"` | `claude -p "<prompt>"` (refuses to run as root) | `opencode run "<prompt>"` |
| Config dir | `~/.hermes/` (`HERMES_HOME`) | `~/.codex/` (`CODEX_HOME`) | `~/.claude/`, `~/.claude.json` (`CLAUDE_CONFIG_DIR`) | `~/.config/opencode`, `~/.local/share/opencode` |

## 3. Implications and decisions for later tasks

- **Claude Code licensing:** do not bake the CLI into images that AgentBox distributes. The adapter must **install it on the user's machine at build/first-run time** (user pulls it from Anthropic's channel) and the task needs legal sign-off before any pre-built image is published. Adjust `agent-claude` and `packaging` accordingly.
- **Run agents as non-root** (Claude Code refuses root anyway).
- **Hermes/MCP `npx` fetches:** stdio MCP servers that download packages at connect time will fail under default-deny. They run in the **bridge sidecar** (own container, own egress allow-list or pre-baked packages), not inside the agent.
- **No transparent redirect** (ADR-0001): each adapter must set `HTTPS_PROXY`/`HTTP_PROXY` and an explicit base URL, and disable telemetry/auto-update/model-catalog fetches so default-deny does not break startup. Remaining endpoints (e.g. login hosts) are **opt-in** policy entries, not defaults.
- **Dummy credentials:** all four support a placeholder key with a custom base URL; the network gateway injects the real provider credential (`init-secrets`).
- **MCP wiring:** point each agent at the MCP gateway only, with static headers and OAuth disabled (OpenCode `oauth:false`; Claude Code `--strict-mcp-config`).
- **Hermes** is the reference adapter; Codex and OpenCode are straightforward (permissive licenses); Claude Code carries the license constraint.

## Open items

- [ ] Capture a real `initialize` handshake from each agent to record the MCP protocol revision it negotiates (docs only; not verified).
- [ ] Hermes: `pip install` vs installer feature parity; license audit of bundled Docker-image binaries.
- [ ] Codex: confirm it is MCP-client-only (no documented server mode).
- [ ] Claude Code: legal confirmation on redistribution; confirm current telemetry hosts.
- [ ] OpenCode: config schema is mid-migration (V1→V2); validate templates against the pinned version.
- [ ] Verify each agent works with a CONNECT-only proxy and an isolated network (end-to-end, in the adapter tasks).
