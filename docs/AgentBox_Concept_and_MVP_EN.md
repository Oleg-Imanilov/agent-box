Open Source Security Runtime for AI Agents

Concept, Architecture, Roadmap, and Phase 1 Specification • October 29, 2026

Status: design proposal. The commands, interfaces, and timelines below describe proposed features, not implemented functionality.

# 1. Vision and Value

AgentBox runs existing AI agents in a restricted environment and routes their external interactions through managed gateways. Users gain access policies, an activity log, blocking, and permission changes through a UI without modifying agent source code. Principle: “everything is mediated” — every external capability granted to an agent should be explicitly controllable. This does not mean that arbitrary system calls can literally be routed through an HTTP proxy.

# 2. Problem and Target Audience

- Prompt injection: untrusted text can induce dangerous tool calls.

- Excessive privileges: access to home directories, tokens, shells, and MCP without least-privilege controls.

- Exfiltration: transferring files and secrets through networks, LLM APIs, MCP, and DNS.

- Limited visibility: users cannot see all calls or adjust rules immediately.

- Target users: developers using Hermes, Claude Code, Codex CLI, and OpenCode; teams running autonomous agents on their own machines.

# 3. Core Principles

- Default deny for unauthorized outbound connections and tools; fail closed when the controller fails.

- Agents and MCP servers run in separate isolated environments; MCP secrets remain outside the agent container.

- Policies are enforced at capability boundaries: networking, MCP, filesystem mounts, resources, and process execution.

- Local-first: audit data and SQLite reside in an AgentBox volume; no mandatory cloud service.

- Minimal setup: Docker Engine/Desktop and a small launcher; Compose can remain an implementation detail.

- Limits of transparency: proxying HTTP does not automatically make arbitrary code inside a container safe.

# 4. Logical Architecture

Host launcher / CLI  
├── AgentBox controller + Web UI + SQLite volume  
├── Egress gateway / policy enforcement  
├── MCP gateway ──\> isolated MCP service containers / remote MCP  
└── Agent sandbox (Hermes / Codex / Claude / OpenCode)  
├── project bind mount (Phase 1: writes directly to host)  
├── LLM endpoint via controlled gateway  
└── restricted network: gateway only

The host launcher uses the Docker API on the host. Never expose docker.sock to the agent, MCP services, or an ordinary web controller. If a containerized controller must manage Docker, use a separate narrowly privileged host helper with a limited API; direct socket access effectively grants extensive privileges.

# 5. Components

- Launcher / CLI (Go): install, init, run, stop, status, doctor; Docker orchestration and configuration generation.

- Controller (Go): session state, policy engine, API, audit, live updates.

- Network gateway (Go): outbound HTTP(S), CONNECT, and DNS permissions; TLS visibility is limited without interception.

- MCP gateway (Go): proxy supported transports, including Streamable HTTP; inspect tool names and arguments, log calls, and redact sensitive fields.

- Agent image adapters: ready-made images or launch templates for Hermes, Claude Code, Codex CLI, and OpenCode; generic custom-image mode.

- UI (React/TypeScript): events, filters, allowed/blocked decisions, policy editor, agent and MCP inventories.

- SQLite: events, configuration, and policy change history; no separate database container required.

# 6. Network Isolation: Important Technical Limits

HTTP_PROXY/HTTPS_PROXY alone are insufficient: agents can ignore environment variables and use direct sockets, DNS, or nonstandard protocols. In Phase 1, enforce isolation using Docker/host firewall rules: permit access only to the gateway and deny LAN access, metadata endpoints, Docker API, and other networks. Test IPv4, IPv6, DNS, UDP, loopback, host networking, side channels, and container DNS configuration. The gateway itself must have strictly controlled egress.

# 7. MCP: A Separate Trust Boundary

An MCP server must not run as a privileged service inside the agent container. AgentBox provides agents with configuration pointing only to the MCP gateway; actual servers run separately or are accessed remotely. Stdio MCP requires a bridge/sidecar that converts stdio to a managed transport. It is not technically possible to prevent an agent from starting any process that speaks MCP inside its own container; what can be prevented is that process gaining unauthorized external capabilities. Isolate MCP servers independently and scope their credentials and permissions.

# 8. Filesystem and Execution

Phase 1: bind-mount only the selected directory, writable for coding agents. Docker mount namespaces prevent an ordinary symlink from revealing host paths not mounted or otherwise visible inside the container. However, bind mounts modify host files immediately; warn users and recommend Git and backups. Validate canonical paths, nested mounts, special files, accessible sockets, hard links, and mount propagation. Never mount the entire home directory, SSH keys, or Docker socket. Run without privileges and with restricted Linux capabilities, seccomp, and resource limits.

# 9. Declarative Policy (Future DSL)

Start with YAML/JSON; introduce a Terraform-like DSL only when there is proven demand. Rules inherit from global → agent → session → tool, with deny precedence; record each decision and policy version in the audit log. Example proposed format:

agent: hermes  
workspace: {path: ./project, mode: read-write}  
network:  
default: deny  
allow: \[api.openai.com:443, ollama.internal:11434\]  
mcp:  
github:  
allow_tools: \[get_file_contents, list_issues\]  
deny_tools: \[delete_repository\]  
audit: {enabled: true, redact_secrets: true}

Dynamic approval: allow once / allow for session / persist rule / deny. Do not automatically replay a blocked operation when a retry could have side effects; use request IDs and idempotency safeguards.

# 10. UI and Audit

- Live timeline: timestamp, agent, session, direction, destination, transport, operation, result, latency, policy rule.

- MCP: server/tool, redacted arguments, status, response metadata; optional approval before execution.

- Network: domain/IP/port, CONNECT/HTTP method when visible, traffic volume; do not promise TLS payload visibility.

- Edit rules live, view change history, search, and export JSONL.

- The audit system must not store tokens, keys, private file contents, or full prompts/responses without explicit opt-in.

# 11. Full Roadmap

## Phase 1 — Useful Local MVP

Linux + Docker, launcher, one agent container, separate gateway, basic MCP gateway, SQLite, React UI, live allow/deny, and ready-made adapters. Files are saved directly to the workspace. No OverlayFS, TLS interception, proprietary DSL, native Windows interception, or automatic security certification.

## Phase 2 — Security and Compatibility

Harden network rules and DNS, add a stdio bridge, per-tool approvals, MCP container management, profiles for popular agents, broader bypass testing, secure secret handling, audit export, and Windows/macOS support via Linux VM/Docker Desktop.

## Phase 3 — Controlled File Changes

OverlayFS / copy-on-write workspaces, diffs, commit/discard, selective application of changes, checkpoints, and session history. OverlayFS is not a complete snapshot system; multi-layer checkpoints require managing layers, open files, and process consistency. Git worktrees or snapshot-capable storage may be simpler alternatives.

## Phase 4 — Advanced Sandbox and Enterprise

gVisor/Firecracker or VM isolation, Landlock/seccomp/eBPF telemetry, policy-as-code, multi-user RBAC, centralized SIEM/OpenTelemetry, SSO, signed images, attestations, threat detection, approvals for dangerous operations, CI/CD and Kubernetes integrations. Linux first; native macOS/Windows support through separate adapters.

# 12. Phase 1: Concrete Specification

## User Journey

- Install Docker Engine or Docker Desktop.

- Install the AgentBox CLI (package or signed binary; install script optional).

- agentbox init — choose a provider, store credentials in a host-side secret store, select workspace and policy.

- agentbox run hermes — the CLI pulls the image, starts infrastructure, creates a sandbox, and opens the agent terminal.

- agentbox ui — open the localhost UI, inspect connection attempts, allow/deny domains and MCP tools.

- agentbox stop — stop the session; the audit SQLite database persists in a separate volume.

## Proposed Commands (Not Yet Implemented)

agentbox init  
agentbox run hermes --workspace .  
agentbox run codex --workspace .  
agentbox ui  
agentbox policy list  
agentbox doctor  
agentbox stop \<session-id\>

## Out-of-the-Box Support

Agents: Hermes (reference scenario), Codex CLI, Claude Code, OpenCode, subject to verification of actual installation methods and licensing. LLMs: Ollama (local), OpenAI-compatible APIs/OpenRouter, Anthropic/OpenAI via official APIs. MCP: remote Streamable HTTP and stdio via an isolated bridge; examples include GitHub, filesystem, and PostgreSQL. Do not give agents direct DB/FS credentials.

## Minimum Screens

Dashboard: running sessions and blocked attempts. Events: live filterable table. Policies: destinations and MCP tools, allow once/deny. Settings: providers, mounts, audit retention. No separate account system in the local single-user MVP; bind the UI to 127.0.0.1 and protect against CSRF and unauthorized requests.

## Minimum Data Model

sessions(id, agent, image_digest, workspace, started_at, ended_at)  
events(id, session_id, ts, kind, destination, operation, decision, rule_id, metadata_redacted)  
policies(id, scope, version, rule_json, updated_at)  
approvals(id, event_id, decision, actor, expires_at)

## Acceptance Criteria and Demo

- Hermes completes a normal task in a writable workspace; changes are visible on the host.

- Calls to an allowed LLM API succeed; forbidden destinations are blocked at the network layer even when an application ignores HTTP_PROXY.

- Attempts to access private LAN, Docker socket, and unmounted host paths fail.

- An allowed MCP tool executes through the gateway; a denied tool is blocked before execution.

- All decisions are logged with session ID and rule ID; the UI displays events live.

- Policy changes affect new connections/calls; behavior of existing connections and caches is documented separately.

- Policies and audit history survive infrastructure restarts.

- Automated negative tests cover direct TCP, DNS, IPv6, UDP, curl without proxy environment variables, stdio MCP, path traversal, and container privileges.

# 13. AI-Assisted Development

AI can generate substantial Go/React/Compose code and tests, but generated code cannot be trusted to establish a security boundary on its own. Require a threat model, independent adversarial tests, manual review of privileges and firewall rules, reproducible builds, dependency scanning, and CI integration tests. Plan by deliverables rather than promising fixed weeks.

# 14. Work Plan and Complexity Estimate

- Step 0 (several days): threat model, Docker networking spike, test blocking direct egress and review MCP protocols.

- Step 1: launcher + sandbox + writable mount + one agent + default-deny network.

- Step 2: gateway + SQLite audit + UI timeline + live policy updates.

- Step 3: MCP gateway + isolated MCP services + approval tests.

- Step 4: agent adapters, installation UX, packaging, CI, and documentation.

- Estimate: prototype in 2–4 weeks; MVP suitable for public testing in 6–12 weeks with intensive AI-assisted coding and experienced review; a robust security product will take substantially longer. These are ranges, not commitments.

# 15. Risks and Trade-offs

- Container escapes/kernel vulnerabilities: Docker is not a VM; gVisor/VM may be needed for untrusted arbitrary code.

- Proxy bypass: environment-only proxies are insecure; enforce network namespaces/firewall and test IPv6/DNS.

- HTTPS visibility: without TLS termination, full HTTPS URLs and payloads cannot be inspected.

- Dynamic MCP capabilities and stdio: adapters and protocols evolve; maintain version compatibility.

- Secret leakage: environment variables, logging, and the agent workspace are separate attack surfaces.

- Writable host mount: agents can delete/overwrite files in the granted directory; Git and backups are essential.

- Docker socket: never expose it to agents; minimize host helper privileges.

- UX: overly strict deny rules can break workflows; provide clear explanations and allow-once.

# 16. Open-Source Strategy

Positioning: “Run your existing AI coding agents with enforceable network and MCP permissions, live audit and local-first control.” Choose Apache-2.0 or MIT after reviewing dependencies. Public repository: README with threat model and limitations, quickstart, Docker/Compose manifests, examples, architecture ADRs, security policy, reproducible demo, and contribution guide. Showcase: an agent attempts a prohibited MCP tool call and an unauthorized network request; both are blocked and visible in the UI.

# 17. What Not to Promise in Version One

Do not promise 100% interception of all system calls, local filesystem operations, HTTPS URLs, MCP processes, or absolute protection against container escapes. Do not call the MVP “complete isolation” without a validated threat model. The accurate promise is: a restricted sandbox, controlled external capabilities, and auditable decisions at observable boundaries.
