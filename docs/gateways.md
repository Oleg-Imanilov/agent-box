# Gateways (Phase 2)

Reference for the network gateway (`cmd/netgw`), the MCP gateway (`cmd/mcpgw`) and the stdio MCP bridge (`cmd/mcpbridge`). All three fail closed and take their decisions from the controller ([controller-api.md](./controller-api.md)) through `internal/gwclient`.

```text
agent container (isolated network, no route out)
   │  HTTPS_PROXY=http://netgw:3128        LLM base URL=http://netgw:3128/llm/<provider>
   │  MCP URL=http://mcpgw:8081/mcp/<server>
   ▼
 netgw ── policy ──▶ controller ◀── policy ── mcpgw ──▶ MCP servers / mcpbridge sidecars
   │ (egress network)                                      (MCP network, own credentials)
   ▼
 internet / LLM APIs
```

One gateway pair serves one session: each gateway holds that session's token, so everything it does is attributed to, and limited by, that session.

## Network gateway (`netgw`)

Listens on `:3128` (agent network). Serves:

| Request | Behavior |
| --- | --- |
| `CONNECT host:port` | Tunnels HTTPS and any other TCP through policy. The payload is **not** inspected (no TLS interception). |
| `GET http://host/...` (absolute URI) | Plain HTTP proxying through policy, one authorization per connection (keep-alive disabled). `https://` absolute URIs are rejected; clients must use `CONNECT`. |
| `/llm/<provider>/...` | Reverse proxy to the provider's upstream that **injects the real credential** (see below). |
| `/healthz` | Liveness. |

### How a connection is authorized

1. The destination host is normalized and validated. Ambiguous numeric forms that resolvers accept (`127.1`, `2130706433`, `0x7f.1`) are rejected outright.
2. The controller decides `host:port` (default deny). A denial ends the request with `403` and headers `X-AgentBox-Decision: deny`, `X-AgentBox-Rule: <rule id>`. If the controller cannot be reached, the answer is deny.
3. The gateway resolves the name **itself**. Agents never resolve names: the isolated network has no external DNS (verified in the [network spike](./spikes/network-isolation.md)), which is why there is no separate DNS server.
4. Every resolved address is classified. Public addresses are used. Loopback, private (RFC 1918, ULA), link-local (including `169.254.169.254` cloud metadata), CGNAT, multicast, unspecified, reserved, NAT64/6to4/Teredo and documentation ranges are **restricted**: the gateway asks the controller about that *IP* too, so a policy must contain an explicit IP/CIDR rule for it. A rule for a name never opens an internal address (DNS rebinding / SSRF defense).
5. The gateway connects to the validated IP, never to the name, and re-checks the address at socket level in the dialer's control hook.

Mixed DNS answers are handled per address: restricted addresses are skipped (and reported as `dns.blocked-address`), the rest are used. If nothing remains the request is denied.

Allowing a LAN service therefore takes two rules, for example for Ollama:

```yaml
network:
  allow:
    - ollama.internal:11434      # the name
    - 10.0.0.5:11434             # its (private) address, explicitly
```

### Approvals

With `AGENTBOX_NETGW_APPROVALS=true`, a destination that is denied *only because no rule allows it* is held while a human decides (allow once / for the session / persist for the agent / deny). Explicit deny rules are never escalated. The held `CONNECT` returns after the decision or the per-entity timeout (default 60 s for network), or immediately if the client disconnects. Client tools often time out `CONNECT` sooner than the approval timeout; raise their timeout when using approvals.

### LLM routes and credential injection

An HTTPS tunnel cannot be modified without intercepting TLS, so credentials are injected by a reverse-proxy route instead. Configure the agent's LLM base URL as `http://netgw:3128/llm/<provider>` (plain HTTP on the isolated network) with a **dummy** API key. The gateway forwards to the provider over HTTPS and sets the real credential:

```json
[
  {"name": "openai",    "upstream": "https://api.openai.com",    "key_file": "/run/secrets/openai"},
  {"name": "anthropic", "upstream": "https://api.anthropic.com", "header": "x-api-key",
   "key_file": "/run/secrets/anthropic", "headers": {"anthropic-version": "2023-06-01"}},
  {"name": "ollama",    "upstream": "http://ollama.internal:11434", "no_auth": true}
]
```

(`AGENTBOX_NETGW_PROVIDERS_FILE`.) Notes:

- With no `header`, the credential is sent as `Authorization: Bearer <key>`. With a custom `header` (like `x-api-key`) the bare key is sent unless you also set `scheme`.
- Credentials the agent sends (`Authorization`, `X-Api-Key`, `Api-Key`, `Cookie`, ...) are always removed. The key file is re-read on use, so keys can be rotated without a restart.
- The upstream destination goes through the same policy and address checks as any other connection, so it must be allowed (and an Ollama LAN address needs the explicit IP rule above).
- Responses stream unbuffered (SSE completions work).

### Configuration

| Variable | Purpose |
| --- | --- |
| `AGENTBOX_CONTROLLER_URL`, `AGENTBOX_GATEWAY_TOKEN` / `_FILE` | Controller and the session's token (required). |
| `AGENTBOX_NETGW_LISTEN` | Default `:3128`. |
| `AGENTBOX_NETGW_PROVIDERS_FILE` | LLM routes (JSON array above). |
| `AGENTBOX_NETGW_APPROVALS` | `true` to ask a human for default-denied destinations. |
| `AGENTBOX_NETGW_MAX_CONNS`, `AGENTBOX_NETGW_IDLE_TIMEOUT` | Concurrency limit (512) and idle tunnel timeout (5 m). |

Closed tunnels are reported to the audit log (`connect.closed`, with bytes and duration).

## MCP gateway (`mcpgw`)

Listens on `:8081`. Agents use `http://mcpgw:8081/mcp/<server>`; `<server>` is the name used in policy. The real server URL, credentials and session IDs are never visible to the agent.

| Check | Behavior |
| --- | --- |
| `tools/call` | Decided by policy **before anything is forwarded**. Denied calls get a JSON-RPC error (`-32001`, with the rule ID); the MCP server never sees them. With approvals enabled, default-denied calls are held for a human (default 120 s for MCP). |
| `tools/list` | Denied tools are removed from the response, in JSON and SSE form. If the policy service is unreachable no tools are advertised. |
| Methods | Allowed: `initialize`, `ping`, `tools/list`, `notifications/*`. Everything else (`resources/*`, `prompts/*`, `completion/*`, `logging/*`) is blocked unless the server entry lists it in `allow_methods`. |
| Batches | JSON-RPC batch arrays are rejected. |
| Server-initiated requests | `sampling/createMessage`, `elicitation/create`, `roots/list` and any other server→client request are dropped and answered with an error toward the server, so it does not hang. Only `ping` and `notifications/*` pass. |
| Sessions | The gateway mints its own session IDs, bound to one server. Clients cannot choose an upstream session or reuse one across servers; idle sessions expire (1 h); the table is bounded. |
| Protocol versions | `2024-11-05` to `2025-11-25` are supported. The stateless `2026-07-28` revision is rejected rather than passed through unexamined. |
| Hosts and origins | Optional Host allow-list. A request with an `Origin` header is rejected unless allow-listed (agents are not browsers). |
| Headers | Only gateway-controlled headers go upstream. Client credentials, cookies and other headers are dropped; upstream credentials come from `bearer_file` / `headers`. Redirects from upstream are never followed. |
| Limits | 4 MiB request bodies, 8 MiB buffered responses, 1 MiB per SSE event. |

**Parser differentials are closed off.** Because Go's JSON decoder accepts duplicate keys and matches keys case-insensitively, a message such as `{"method":"tools/list","method":"tools/call",...}` or `{"method":"tools/call","Method":"tools/list"}` could show the gateway one meaning and the MCP server another. The gateway rejects duplicate keys anywhere in a message and case-variants of protocol keys (`method`, `params`, `name`, ...), and decodes with case-sensitive lookups.

Servers file (`AGENTBOX_MCPGW_SERVERS_FILE`):

```json
[
  {"name": "github", "url": "https://api.githubcopilot.com/mcp/", "bearer_file": "/run/secrets/github-mcp"},
  {"name": "files",  "url": "http://mcp-files:9000/mcp", "bearer_file": "/run/secrets/files-bridge"}
]
```

Other variables: `AGENTBOX_MCPGW_LISTEN` (`:8081`), `AGENTBOX_MCPGW_ALLOWED_HOSTS`, `AGENTBOX_MCPGW_APPROVALS`, plus the controller URL/token variables above.

## stdio bridge (`mcpbridge`)

`mcpbridge -- <mcp server command>` runs a stdio MCP server and serves it as Streamable HTTP at `/mcp` (POST, GET, DELETE) behind the MCP gateway. It is meant to run **in its own container with the MCP server it wraps**, attached only to the MCP network, with the server's least-privilege credentials mounted there and nowhere else.

- Requires a bearer token (`AGENTBOX_BRIDGE_TOKEN` / `_FILE`, at least 32 characters); the MCP gateway presents it from its `bearer_file`.
- The MCP server gets a minimal environment: `PATH`, `HOME`, `LANG`, `TMPDIR` plus explicit `AGENTBOX_BRIDGE_ENV_<NAME>=value` and `AGENTBOX_BRIDGE_ENV_FILE_<NAME>=<path>` entries. The bridge's token and the rest of the container environment are never visible to it.
- JSON-RPC request IDs are rewritten to unique IDs, so any number of HTTP sessions share the single stdin/stdout pipe without collisions. The server sees one `initialize` and one `notifications/initialized`; later sessions are answered from the cached handshake.
- Stdout lines that are not JSON objects (stray logging) are quarantined, never forwarded. Messages are compacted onto one line before they reach stdin, so a pretty-printed request cannot break the framing.
- Server-initiated messages go to attached `GET` streams. A server request with no stream attached is answered with an error immediately. Resumption with `Last-Event-ID` is not supported (stdio has no replay).
- Requests time out (default 120 s) and the server is sent `notifications/cancelled`. If the child exits, the bridge exits non-zero and `/healthz` reports 503, so the supervisor restarts the pair.

Build a bridge image around an npm-distributed server with [deploy/Dockerfile.mcp-node](../deploy/Dockerfile.mcp-node) (pin the package version). Required container flags are listed in that file; the launcher will apply them automatically.

## Container images

[deploy/Dockerfile](../deploy/Dockerfile) builds `controller`, `netgw` or `mcpgw` into a distroless, non-root image with a built-in `healthcheck` subcommand. Verified: the controller runs with `--read-only --cap-drop ALL --security-opt no-new-privileges` and a writable `/data` volume.

## Known limits

- **Policy changes apply to new decisions.** An established tunnel keeps running until it ends or idles out; an allow decision cached by a gateway lives at most `AGENTBOX_ALLOW_CACHE_TTL` (default 5 s). Revoking access to an existing tunnel means ending the session.
- **No TLS inspection.** Host/port and byte counts are visible, not URLs or payloads. A name allowed by policy can carry anything, including data in its subdomains if wildcards are allowed.
- **Approval waits vs. client timeouts.** Held requests return only after the decision; MCP clients commonly time out at 60 s while the MCP default wait is 120 s. Raise the client's timeout or lower the approval timeout in settings.
- **stdio servers and the network.** The bridge sidecar has its own network policy; if a wrapped server fetches packages at start-up (for example `npx -y ...`) it needs egress or must be pre-installed. Pre-install at build time.
- **One gateway pair per session.** Gateways are not multi-tenant.
- Gateway enforcement relies on the launcher's network layout (agent network is internal and isolated; only gateways are dual-homed). The negative-test suite will verify it.
