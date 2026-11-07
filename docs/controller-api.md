# Controller API and policy format (Phase 1)

Reference for the control-plane service in `cmd/controller` and the policy format evaluated by `internal/policy`. Status: implemented, unreleased; the API may still change before the MVP.

## Running

The controller runs in a container on the control network (never on the agent network) and has no Docker access. Configuration is by environment variable:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENTBOX_ADMIN_TOKEN` / `AGENTBOX_ADMIN_TOKEN_FILE` | *(required)* | Admin bearer token, at least 32 characters. The controller refuses to start without it. |
| `AGENTBOX_DB` | `/data/agentbox.db` | SQLite file (WAL mode, created `0600`). Put it on a persistent volume. |
| `AGENTBOX_LISTEN` | `127.0.0.1:8080` | Listen address. Inside a container use `0.0.0.0:8080` and publish the port on `127.0.0.1` only. |
| `AGENTBOX_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Host names accepted in `Host` and `Origin` (add the controller's service name for gateways). |
| `AGENTBOX_ALLOW_CACHE_TTL` | `5s` | How long gateways may cache an *allow* decision (`0` disables). Deny is never cached. |

`controller healthcheck` probes `/healthz` and exits 0/1 (for a container `HEALTHCHECK`).

## Authentication and request hygiene

- **Admin token** (UI, launcher): `Authorization: Bearer <token>`, compared in constant time.
- **Gateway token** (one per session): returned once by `POST /v1/sessions`, stored only as a SHA-256 hash. It authenticates exactly one *active* session and works only on `/v1/gw/*`. Ending the session revokes it immediately. The admin token does not work on `/v1/gw/*`, and gateway tokens do not work on admin endpoints.
- Tokens are accepted **only** in the `Authorization` header (not cookies or query strings), so browsers cannot be tricked into sending them (CSRF).
- `Host` must be in `AGENTBOX_ALLOWED_HOSTS` (DNS-rebinding defense); a present `Origin` must also name an allowed host. No CORS headers are ever sent.
- Request bodies are limited to 1 MiB; JSON bodies reject unknown fields and trailing data. All responses are `no-store`.

## Admin endpoints

| Method and path | Description |
| --- | --- |
| `GET /healthz` | Liveness and database check (no auth). |
| `GET /v1/status` | Version, schema version, active sessions, event counters, audit queue stats. |
| `POST /v1/sessions` | Body `{"agent","workspace","image_digest"}`. Returns `{"session", "gateway_token"}` (token shown once). |
| `GET /v1/sessions[?active=true]` | List sessions, newest first. |
| `GET /v1/sessions/{id}` | One session. |
| `POST /v1/sessions/{id}/end` | End a session, revoke its token, drop its session policy. |
| `GET /v1/events` | Filters: `session`, `kind`, `decision`, `rule`, `q` (substring), `after_id`, `before_id`, `since`, `until` (RFC 3339), `limit` (max 1000), `order=asc\|desc` (default `desc`). |
| `GET /v1/events/export` | Same filters; `application/x-ndjson` (JSONL), oldest first. |
| `GET /v1/events/stream` | Server-Sent Events; same filters. Resumable with `Last-Event-ID` (replays missed events, then streams live). Use `fetch` streaming from the UI, since `EventSource` cannot send the `Authorization` header. |
| `GET /v1/policies`, `GET /v1/policies/{scope}`, `GET /v1/policies/{scope}/history` | Read policies and their version history. |
| `PUT /v1/policies/{scope}` | Body: policy as YAML or JSON. Validated, stored as a new version, and applied to the **next** decision. Invalid policies are rejected and change nothing. |
| `GET /v1/settings`, `PUT /v1/settings` | `audit_retention_days` (0–3650, 0 = keep forever) and `include_content` (default `false`). |

`{scope}` is `global`, `agent:<name>` or `session:<id>`. A session-scoped policy requires an active session.

## Gateway endpoints (per-session token)

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/gw/decide/network` | `{"host","port","operation"?}` | `{"effect","rule_id","policy_version","reason"?,"cache_ttl_seconds"}` |
| `POST /v1/gw/decide/mcp` | `{"server","tool","operation"?}` | same |
| `POST /v1/gw/events` | `{"kind": network\|dns\|mcp, "decision": allow\|deny\|error\|info, "destination"?, "operation"?, "rule_id"?, "policy_version"?, "metadata"?}` | `202` |

- Every decision is **audited by the controller** with the session ID, rule ID and policy versions, so a gateway cannot forget to log one. The session always comes from the token; clients cannot name another session.
- **Fail closed:** if the audit trail cannot record a decision, the response is `deny` with rule `audit-unavailable`.
- `internal/gwclient` is the client for gateways. Any error (timeout, non-200, malformed body, redirect) yields `deny`. A cached *allow* is only served within the TTL the controller itself returned.

## Policy format

YAML or JSON; unknown fields are rejected. Example:

```yaml
agent: hermes                 # optional; must match the scope if given
workspace: {path: ./project, mode: read-write}   # consumed by the launcher
network:
  default: deny               # only "deny" is accepted
  allow: [api.openai.com:443, "*.github.com:443", "10.1.0.0/16:8000-9000", "[2001:db8::1]:443"]
  deny:  ["*.evil.com:*"]
mcp:
  github:
    allow_tools: [get_file_contents, "list_*"]
    deny_tools: [delete_repository]
audit: {enabled: true, redact_secrets: true}
```

**Network rules** are `host:port`:

- `host`: exact domain, `*.suffix` (subdomains only, not the apex), IP address, or CIDR. IPv6 hosts/CIDRs must be bracketed. Domains are ASCII (IDNs in punycode), case-insensitive; a trailing dot is ignored; IPv4-mapped IPv6 addresses are treated as IPv4.
- `port`: `443`, a range `8000-9000`, or `*`. A port is required.
- A bare `*` host is not allowed.

**MCP rules** are per server name: `allow_tools` / `deny_tools` with exact names or `*` globs (case-sensitive). A server or tool not allowed is denied.

**Evaluation** (`internal/policy`):

1. Scopes apply in the order `global`, `agent:<name>`, `session:<id>`.
2. **Deny wins:** a matching deny rule in *any* scope denies, even if a narrower scope allows.
3. Otherwise a matching allow rule in any scope allows.
4. Otherwise **default deny** (`rule_id: default-deny`). With no policies at all, everything is denied.
5. Every decision reports the matching rule (`global#network.allow[1]`, `agent:hermes#mcp.github.deny_tools[0]`, ...) and the policy versions in force (`global@3,agent:hermes@1`).

### Known limits

- Policy changes affect **new** decisions only. Connections already established, and allow decisions cached by a gateway (up to `AGENTBOX_ALLOW_CACHE_TTL`), keep working until they end or expire. The gateways must document how they enforce this on long-lived connections.
- Rules match the destination as presented. A deny on a domain does not cover its IP addresses; gateways must also resolve names and reject private, loopback, link-local and metadata addresses after resolution.
- `audit.enabled` and `audit.redact_secrets` are validated but not yet enforced per policy: audit logging and secret redaction are always on. This is the safe direction and will be made configurable with the UI settings.
- Prompts and file contents are omitted from audit metadata unless `include_content` is enabled.

## Audit events

Each event has: `id`, `session_id`, `ts`, `kind` (`network`, `dns`, `mcp`, `policy`, `session`, `approval`), `destination`, `operation`, `decision` (`allow`, `deny`, `error`, `info`), `rule_id`, `policy_version`, and redacted `metadata`. Redaction is key-based (authorization, cookies, tokens, passwords, API keys, ...) and pattern-based (bearer tokens, common provider keys, JWTs, URL credentials, private keys); long strings are truncated and oversized metadata is replaced by a marker.

## Persistence

SQLite (pure Go driver, WAL) with embedded, versioned migrations. Tables: `sessions`, `events`, `policies`, `policy_history`, `approvals` (used by the Phase 2 approval flow), `settings`. Policies, history and audit events survive restarts; session-scoped policies are only restored for sessions that are still active.
