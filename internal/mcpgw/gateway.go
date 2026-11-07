package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/bgtask"
	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/secretfile"
)

// Rule IDs reported by the gateway itself (not by the policy engine).
const (
	RuleBatch         = "mcpgw#batch-rejected"
	RuleMalformed     = "mcpgw#malformed"
	RuleMethodBlocked = "mcpgw#method-blocked"
	RuleServerRequest = "mcpgw#server-request-blocked"
	RuleUnexpected    = "mcpgw#unexpected-response"
	RuleVersion       = "mcpgw#unsupported-protocol-version"
)

// Gateway is the MCP gateway.
type Gateway struct {
	cfg      Config
	log      *slog.Logger
	servers  map[string]*upstream
	sessions *sessionTable
	hc       *http.Client
	bearers  map[string]*secretfile.File
	hosts    map[string]bool
	origins  map[string]bool

	bg bgtask.Group
}

// New validates cfg and creates a Gateway.
func New(cfg Config) (*Gateway, error) {
	if cfg.Controller == nil {
		return nil, errors.New("mcpgw: controller is required")
	}
	if len(cfg.Servers) == 0 {
		return nil, errNoServers
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4 << 20
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 8 << 20
	}
	if cfg.MaxSSEEventBytes <= 0 {
		cfg.MaxSSEEventBytes = 1 << 20
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = time.Hour
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 1024
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	servers, err := buildServers(cfg.Servers)
	if err != nil {
		return nil, err
	}
	g := &Gateway{
		cfg: cfg, log: cfg.Logger, servers: servers,
		sessions: newSessionTable(cfg.SessionTTL, cfg.MaxSessions, cfg.Now),
		hc:       cfg.HTTPClient,
		bearers:  map[string]*secretfile.File{},
		hosts:    map[string]bool{},
		origins:  map[string]bool{},
	}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	if g.hc == nil {
		g.hc = &http.Client{
			// Never follow redirects: upstream credentials must not be replayed
			// to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{ResponseHeaderTimeout: 60 * time.Second, Proxy: nil},
		}
	}
	for name, up := range servers {
		if up.BearerFile != "" {
			g.bearers[name] = secretfile.New(up.BearerFile)
		}
	}
	for _, h := range cfg.AllowedHosts {
		g.hosts[strings.ToLower(h)] = true
	}
	for _, o := range cfg.AllowedOrigins {
		g.origins[strings.ToLower(o)] = true
	}
	return g, nil
}

// Wait blocks until background work (event reports, error replies) finishes.
func (g *Gateway) Wait() { g.bg.Wait() }

// Handler returns the gateway's HTTP handler.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/mcp/{server}", g.handleMCP)
	return g.guard(mux)
}

func (g *Gateway) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(g.hosts) > 0 {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !g.hosts[strings.ToLower(host)] {
				http.Error(w, "host not allowed", http.StatusForbidden)
				return
			}
		}
		if o := r.Header.Get("Origin"); o != "" && !g.origins[strings.ToLower(o)] {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	up, ok := g.servers[r.PathValue("server")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !supportedVersions[v] {
		g.writeRPC(w, http.StatusBadRequest, rpcError(nil, codeInvalidReq, "unsupported MCP protocol version", map[string]any{"supported": supportedList()}))
		g.reportDeny(up, RuleVersion, "protocol-version", map[string]any{"version": v})
		return
	}
	switch r.Method {
	case http.MethodPost:
		g.handlePost(w, r, up)
	case http.MethodGet:
		g.handleGet(w, r, up)
	case http.MethodDelete:
		g.handleDelete(w, r, up)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func supportedList() []string {
	return []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
}

func (g *Gateway) writeRPC(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (g *Gateway) reportDeny(up *upstream, rule, op string, meta map[string]any) {
	g.report(gwclient.Event{Kind: "mcp", Destination: up.Name, Operation: op, Decision: "deny", RuleID: rule, Metadata: meta})
}

func (g *Gateway) report(e gwclient.Event) {
	g.bg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.cfg.Controller.ReportEvent(ctx, e); err != nil {
			g.log.Warn("event report failed", "op", e.Operation, "err", err)
		}
	})
}

// streamCtx describes the request a response (or stream) belongs to.
type streamCtx struct {
	up          *upstream
	reqID       json.RawMessage // id of the forwarded request, nil for GET streams
	reqMethod   string
	upstreamSID string
}

func (g *Gateway) handlePost(w http.ResponseWriter, r *http.Request, up *upstream) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			g.writeRPC(w, http.StatusRequestEntityTooLarge, rpcError(nil, codeInvalidReq, "request too large", nil))
			return
		}
		g.writeRPC(w, http.StatusBadRequest, rpcError(nil, codeParse, "cannot read request", nil))
		return
	}
	msg, err := parseMessage(body)
	if err != nil {
		rule, code := RuleMalformed, codeParse
		if errors.Is(err, errBatch) {
			rule, code = RuleBatch, codeInvalidReq
		} else if errors.Is(err, errAmbiguous) {
			code = codeInvalidReq
		}
		g.writeRPC(w, http.StatusBadRequest, rpcError(nil, code, err.Error(), nil))
		g.reportDeny(up, rule, "post", map[string]any{"error": err.Error()})
		return
	}
	if msg.Method == "" {
		// A client response only makes sense for a server-initiated request,
		// and those are blocked, so there is nothing legitimate to forward.
		g.writeRPC(w, http.StatusBadRequest, rpcError(msg.ID, codeInvalidReq, "unexpected response message", nil))
		g.reportDeny(up, RuleUnexpected, "post", nil)
		return
	}

	switch {
	case msg.Method == "tools/call":
		if !msg.isRequest() {
			g.writeRPC(w, http.StatusBadRequest, rpcError(nil, codeInvalidReq, "tools/call must be a request with an id", nil))
			g.reportDeny(up, RuleMalformed, "tools/call", nil)
			return
		}
		tool, err := callParams(msg.Params)
		if err != nil {
			g.writeRPC(w, http.StatusBadRequest, rpcError(msg.ID, codeInvalidReq, err.Error(), nil))
			g.reportDeny(up, RuleMalformed, "tools/call", map[string]any{"error": err.Error()})
			return
		}
		if d := g.decideCall(r.Context(), up.Name, tool); !d.Allowed() {
			g.writeRPC(w, http.StatusOK, rpcError(msg.ID, codePolicyDenied, "Tool call blocked by AgentBox policy",
				map[string]any{"rule_id": d.RuleID, "tool": tool}))
			return
		}
	case msg.isRequest() && !up.allowed[msg.Method]:
		g.writeRPC(w, http.StatusOK, rpcError(msg.ID, codeMethodBlocked, "Method not permitted by AgentBox gateway", map[string]any{"method": msg.Method}))
		g.reportDeny(up, RuleMethodBlocked, msg.Method, nil)
		return
	case msg.isNotification() && !strings.HasPrefix(msg.Method, "notifications/"):
		w.WriteHeader(http.StatusAccepted)
		g.reportDeny(up, RuleMethodBlocked, msg.Method, nil)
		return
	}

	upstreamSID := ""
	if msg.Method != "initialize" {
		if cs := r.Header.Get("Mcp-Session-Id"); cs != "" {
			sid, ok := g.sessions.get(cs, up.Name)
			if !ok {
				g.writeRPC(w, http.StatusNotFound, rpcError(msg.ID, codeNoSession, "session not found", nil))
				return
			}
			upstreamSID = sid
		}
	}

	req, err := g.upstreamRequest(r.Context(), up, http.MethodPost, bytes.NewReader(body), r, upstreamSID)
	if err != nil {
		g.writeRPC(w, http.StatusBadGateway, rpcError(msg.ID, codeUpstream, "upstream credentials unavailable", nil))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := g.hc.Do(req)
	if err != nil {
		g.upstreamFailed(w, up, msg.ID, err)
		return
	}
	defer resp.Body.Close()
	g.relay(w, r, resp, &streamCtx{up: up, reqID: msg.ID, reqMethod: msg.Method, upstreamSID: upstreamSID}, r.Header.Get("Mcp-Session-Id"))
}

func (g *Gateway) decideCall(ctx context.Context, server, tool string) gwclient.Decision {
	if g.cfg.Approvals {
		return g.cfg.Controller.DecideMCPAsk(ctx, server, tool, gwclient.NewRequestID())
	}
	return g.cfg.Controller.DecideMCP(ctx, server, tool)
}

func (g *Gateway) handleGet(w http.ResponseWriter, r *http.Request, up *upstream) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "Accept must include text/event-stream", http.StatusNotAcceptable)
		return
	}
	clientSID := r.Header.Get("Mcp-Session-Id")
	upstreamSID := ""
	if clientSID != "" {
		sid, ok := g.sessions.get(clientSID, up.Name)
		if !ok {
			g.writeRPC(w, http.StatusNotFound, rpcError(nil, codeNoSession, "session not found", nil))
			return
		}
		upstreamSID = sid
	}
	req, err := g.upstreamRequest(r.Context(), up, http.MethodGet, nil, r, upstreamSID)
	if err != nil {
		g.writeRPC(w, http.StatusBadGateway, rpcError(nil, codeUpstream, "upstream credentials unavailable", nil))
		return
	}
	req.Header.Set("Accept", "text/event-stream")
	if v := r.Header.Get("Last-Event-ID"); v != "" && !strings.ContainsAny(v, "\r\n") {
		req.Header.Set("Last-Event-ID", v)
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		g.upstreamFailed(w, up, nil, err)
		return
	}
	defer resp.Body.Close()
	g.relay(w, r, resp, &streamCtx{up: up, upstreamSID: upstreamSID}, clientSID)
}

func (g *Gateway) handleDelete(w http.ResponseWriter, r *http.Request, up *upstream) {
	clientSID := r.Header.Get("Mcp-Session-Id")
	if clientSID == "" {
		http.Error(w, "Mcp-Session-Id required", http.StatusBadRequest)
		return
	}
	sid, ok := g.sessions.get(clientSID, up.Name)
	if !ok {
		g.writeRPC(w, http.StatusNotFound, rpcError(nil, codeNoSession, "session not found", nil))
		return
	}
	req, err := g.upstreamRequest(r.Context(), up, http.MethodDelete, nil, r, sid)
	if err != nil {
		g.writeRPC(w, http.StatusBadGateway, rpcError(nil, codeUpstream, "upstream credentials unavailable", nil))
		return
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		g.upstreamFailed(w, up, nil, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 300 || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		g.sessions.delete(clientSID)
	}
	w.WriteHeader(resp.StatusCode)
}

func (g *Gateway) upstreamFailed(w http.ResponseWriter, up *upstream, id json.RawMessage, err error) {
	g.log.Warn("upstream request failed", "server", up.Name, "err", err)
	g.report(gwclient.Event{Kind: "mcp", Destination: up.Name, Operation: "upstream", Decision: "error", Metadata: map[string]any{"error": err.Error()}})
	g.writeRPC(w, http.StatusBadGateway, rpcError(id, codeUpstream, "upstream MCP server unavailable", nil))
}

// upstreamRequest builds a request to the upstream. Only gateway-controlled
// headers are sent: client credentials, cookies and arbitrary headers are
// never forwarded.
func (g *Gateway) upstreamRequest(ctx context.Context, up *upstream, method string, body io.Reader, client *http.Request, upstreamSID string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, up.url.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range up.Headers {
		req.Header.Set(k, v)
	}
	if bf := g.bearers[up.Name]; bf != nil {
		tok, err := bf.Get()
		if err != nil {
			g.log.Error("upstream credential unavailable", "server", up.Name, "err", err)
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if v := client.Header.Get("MCP-Protocol-Version"); v != "" {
		req.Header.Set("MCP-Protocol-Version", v)
	}
	if upstreamSID != "" {
		req.Header.Set("Mcp-Session-Id", upstreamSID)
	}
	return req, nil
}

// relay sends the upstream response to the client, applying the message
// filter to JSON bodies and to every SSE event.
func (g *Gateway) relay(w http.ResponseWriter, r *http.Request, resp *http.Response, sc *streamCtx, clientSID string) {
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	h := w.Header()

	if resp.StatusCode >= 300 || (mt != "application/json" && mt != "text/event-stream") {
		// Errors, 202 Accepted, 405 for unsupported GET, etc.
		if mt != "" {
			h.Set("Content-Type", resp.Header.Get("Content-Type"))
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, g.cfg.MaxResponseBytes))
		return
	}

	// Session handling: mint a gateway session for a new upstream session.
	if sc.reqMethod == "initialize" {
		if upSID := resp.Header.Get("Mcp-Session-Id"); upSID != "" {
			if !visibleASCII(upSID) {
				g.writeRPC(w, http.StatusBadGateway, rpcError(sc.reqID, codeUpstream, "invalid upstream session id", nil))
				return
			}
			gwSID, err := g.sessions.create(sc.up.Name, upSID)
			if err != nil {
				g.deleteUpstreamSession(sc.up, upSID)
				g.writeRPC(w, http.StatusServiceUnavailable, rpcError(sc.reqID, codeUpstream, "too many sessions", nil))
				return
			}
			h.Set("Mcp-Session-Id", gwSID)
			sc.upstreamSID = upSID
		}
	} else if clientSID != "" {
		h.Set("Mcp-Session-Id", clientSID)
	}

	if mt == "text/event-stream" {
		g.pipeSSE(w, r, resp.Body, sc)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxResponseBytes+1))
	if err != nil || int64(len(body)) > g.cfg.MaxResponseBytes {
		g.writeRPC(w, http.StatusBadGateway, rpcError(sc.reqID, codeUpstream, "upstream response too large or unreadable", nil))
		return
	}
	out, ok := g.filterMessage(r.Context(), sc, body)
	if !ok {
		g.writeRPC(w, http.StatusBadGateway, rpcError(sc.reqID, codeUpstream, "upstream response blocked by AgentBox gateway", nil))
		return
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

func visibleASCII(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (g *Gateway) pipeSSE(w http.ResponseWriter, r *http.Request, body io.Reader, sc *streamCtx) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived stream
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	br := bufio.NewReaderSize(body, 64<<10)
	for {
		ev, err := readSSE(br, g.cfg.MaxSSEEventBytes)
		if err != nil {
			if errors.Is(err, errEventTooLarge) {
				g.reportDeny(sc.up, RuleMalformed, "sse", map[string]any{"error": "event too large"})
			}
			return
		}
		if ev.HasData {
			out, ok := g.filterMessage(r.Context(), sc, ev.Data)
			if !ok {
				continue // dropped; retain id so Last-Event-ID resumption still advances
			}
			ev.Data = out
		}
		if err := writeSSE(w, ev); err != nil {
			return
		}
		_ = rc.Flush()
	}
}

// filterMessage inspects one server→client message. It returns the (possibly
// rewritten) message, or ok=false if it must be dropped.
func (g *Gateway) filterMessage(ctx context.Context, sc *streamCtx, data []byte) ([]byte, bool) {
	m, err := parseMessage(data)
	if err != nil {
		g.reportDeny(sc.up, RuleMalformed, "response", map[string]any{"error": err.Error()})
		return nil, false
	}
	switch {
	case m.isResponse():
		return g.filterResponse(ctx, sc, m, data)
	case m.isRequest():
		if m.Method == "ping" {
			return data, true
		}
		// sampling/createMessage, elicitation/create, roots/list, ... : the
		// agent must not be driven by (or leak data to) an MCP server this
		// way. Tell the server "not supported" so it does not hang.
		g.reportDeny(sc.up, RuleServerRequest, m.Method, nil)
		g.replyUpstreamError(sc, m.ID)
		return nil, false
	default: // notification
		if strings.HasPrefix(m.Method, "notifications/") {
			return data, true
		}
		g.reportDeny(sc.up, RuleMethodBlocked, m.Method, nil)
		return nil, false
	}
}

func (g *Gateway) filterResponse(ctx context.Context, sc *streamCtx, m *message, data []byte) ([]byte, bool) {
	if sc.reqID == nil || !bytes.Equal(m.ID, sc.reqID) {
		return data, true
	}
	result, hasResult := m.fields["result"]
	if !hasResult {
		return data, true
	}
	switch sc.reqMethod {
	case "initialize":
		var r struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(result, &r); err != nil || !supportedVersions[r.ProtocolVersion] {
			g.reportDeny(sc.up, RuleVersion, "initialize", map[string]any{"version": r.ProtocolVersion})
			return rpcError(m.ID, codeUpstream, "unsupported MCP protocol version from upstream server", nil), true
		}
	case "tools/list":
		return g.filterTools(ctx, sc, m, result)
	}
	return data, true
}

// filterTools removes tools that policy does not allow from a tools/list
// result. If the policy service cannot be reached, no tools are advertised.
func (g *Gateway) filterTools(ctx context.Context, sc *streamCtx, m *message, result json.RawMessage) ([]byte, bool) {
	fields, err := decodeObject(result)
	if err != nil {
		return nil, false
	}
	var tools []json.RawMessage
	if raw, ok := fields["tools"]; ok {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return nil, false
		}
	}
	type entry struct {
		name string
		raw  json.RawMessage
	}
	var entries []entry
	var names []string
	for _, t := range tools {
		obj, err := decodeObject(t)
		if err != nil {
			continue
		}
		var name string
		if raw, ok := obj["name"]; !ok || json.Unmarshal(raw, &name) != nil || name == "" || len(name) > maxToolLen {
			continue
		}
		entries = append(entries, entry{name: name, raw: t})
		names = append(names, name)
	}

	kept := []json.RawMessage{}
	if len(names) > 0 {
		decisions, err := g.cfg.Controller.DecideMCPTools(ctx, sc.up.Name, names)
		if err != nil {
			g.log.Warn("tools/list filtering failed; advertising no tools", "server", sc.up.Name, "err", err)
			g.report(gwclient.Event{Kind: "mcp", Destination: sc.up.Name, Operation: "tools/list", Decision: "error",
				Metadata: map[string]any{"error": err.Error()}})
		} else {
			for _, e := range entries {
				if d, ok := decisions[e.name]; ok && d.Allowed() {
					kept = append(kept, e.raw)
				}
			}
		}
	}
	fields["tools"], _ = json.Marshal(kept)
	newResult, err := json.Marshal(fields)
	if err != nil {
		return nil, false
	}
	out := make(map[string]json.RawMessage, len(m.fields))
	for k, v := range m.fields {
		out[k] = v
	}
	out["result"] = newResult
	b, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	return b, true
}

// replyUpstreamError answers a blocked server→client request with a JSON-RPC
// error so the server does not wait for a reply that will never come.
func (g *Gateway) replyUpstreamError(sc *streamCtx, id json.RawMessage) {
	body := rpcError(id, -32601, "Not supported by AgentBox gateway", nil)
	g.bg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := g.upstreamRequest(ctx, sc.up, http.MethodPost, bytes.NewReader(body), &http.Request{Header: http.Header{}}, sc.upstreamSID)
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := g.hc.Do(req)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	})
}

func (g *Gateway) deleteUpstreamSession(up *upstream, upSID string) {
	g.bg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := g.upstreamRequest(ctx, up, http.MethodDelete, nil, &http.Request{Header: http.Header{}}, upSID)
		if err != nil {
			return
		}
		if resp, err := g.hc.Do(req); err == nil {
			resp.Body.Close()
		}
	})
}
