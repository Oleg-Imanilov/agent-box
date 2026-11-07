package controller

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

// RuleAuditUnavailable is reported when a decision cannot be audited. The
// request is denied: enforcement without an audit trail fails closed.
const RuleAuditUnavailable = "audit-unavailable"

// DecisionResponse is returned by the gateway decision endpoints.
type DecisionResponse struct {
	Effect          policy.Effect `json:"effect"`
	RuleID          string        `json:"rule_id"`
	PolicyVersion   string        `json:"policy_version"`
	Reason          string        `json:"reason,omitempty"`
	CacheTTLSeconds int           `json:"cache_ttl_seconds"`
}

type decideNetworkReq struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Operation string `json:"operation"`
	// Ask requests human approval when the request is denied only because no
	// rule allows it. RequestID identifies the logical request (idempotency).
	Ask       bool   `json:"ask"`
	RequestID string `json:"request_id"`
}

type decideMCPReq struct {
	Server    string `json:"server"`
	Tool      string `json:"tool"`
	Operation string `json:"operation"`
	Ask       bool   `json:"ask"`
	RequestID string `json:"request_id"`
}

func (s *Server) respondDecision(w http.ResponseWriter, sess store.Session, kind, destination, operation string, d policy.Decision, started time.Time) {
	resp := DecisionResponse{Effect: d.Effect, RuleID: d.RuleID, PolicyVersion: d.PolicyVersion, Reason: d.Reason}
	err := s.audit.Log(audit.Entry{
		SessionID: sess.ID, Kind: kind, Destination: destination, Operation: operation,
		Decision: string(d.Effect), RuleID: d.RuleID, PolicyVersion: d.PolicyVersion,
		Metadata: map[string]any{"agent": sess.Agent, "direction": "outbound", "decision_latency_us": time.Since(started).Microseconds()},
	})
	if err != nil {
		s.log.Error("audit unavailable; denying", "kind", kind, "err", err)
		resp.Effect, resp.RuleID, resp.Reason = policy.Deny, RuleAuditUnavailable, "audit trail unavailable"
	}
	// Approval outcomes are never cached: "once" must not outlive its request.
	if resp.Effect == policy.Allow && s.cfg.AllowCacheTTL > 0 && !strings.HasPrefix(resp.RuleID, "approval:") {
		resp.CacheTTLSeconds = int(s.cfg.AllowCacheTTL / time.Second)
	}
	writeJSON(w, http.StatusOK, resp)
}

// wantsApproval reports whether an ask is permitted for d. Only a plain
// default-deny can be escalated; explicit deny rules can never be approved.
func wantsApproval(ask bool, d policy.Decision) bool {
	return ask && d.Effect == policy.Deny && d.RuleID == policy.RuleDefaultDeny
}

func (s *Server) handleDecideNetwork(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var req decideNetworkReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Host) > 255 || len(req.Operation) > 64 {
		writeError(w, http.StatusBadRequest, "host or operation too long")
		return
	}
	if req.Ask && !validClientRequestID(req.RequestID) {
		writeError(w, http.StatusBadRequest, "request_id (8-64 chars of A-Za-z0-9_-) is required when ask is true")
		return
	}
	sess := sessionFrom(r)
	d := s.eng.EvaluateNetwork(policy.Subject{Agent: sess.Agent, Session: sess.ID}, req.Host, req.Port)
	dest := net.JoinHostPort(strings.ToLower(req.Host), strconv.Itoa(req.Port))
	if wantsApproval(req.Ask, d) {
		d = s.askApproval(r.Context(), sess, audit.KindNetwork, dest, req.RequestID, d)
	}
	op := req.Operation
	if op == "" {
		op = "connect"
	}
	s.respondDecision(w, sess, audit.KindNetwork, dest, op, d, started)
}

func (s *Server) handleDecideMCP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var req decideMCPReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Server) > 128 || len(req.Tool) > 256 || len(req.Operation) > 64 {
		writeError(w, http.StatusBadRequest, "server, tool or operation too long")
		return
	}
	if req.Ask && !validClientRequestID(req.RequestID) {
		writeError(w, http.StatusBadRequest, "request_id (8-64 chars of A-Za-z0-9_-) is required when ask is true")
		return
	}
	sess := sessionFrom(r)
	d := s.eng.EvaluateMCPTool(policy.Subject{Agent: sess.Agent, Session: sess.ID}, req.Server, req.Tool)
	subject := req.Server + "/" + req.Tool
	if wantsApproval(req.Ask, d) {
		d = s.askApproval(r.Context(), sess, audit.KindMCP, subject, req.RequestID, d)
	}
	op := req.Operation
	if op == "" {
		op = "tools/call"
	}
	s.respondDecision(w, sess, audit.KindMCP, subject, op, d, started)
}

type decideToolsReq struct {
	Server string   `json:"server"`
	Tools  []string `json:"tools"`
}

type toolDecision struct {
	Tool   string        `json:"tool"`
	Effect policy.Effect `json:"effect"`
	RuleID string        `json:"rule_id"`
}

// handleDecideMCPTools evaluates many tool names at once, so a gateway can
// filter a tools/list response. It writes a single summary audit event.
func (s *Server) handleDecideMCPTools(w http.ResponseWriter, r *http.Request) {
	var req decideToolsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Server == "" || len(req.Server) > 128 || len(req.Tools) > 1000 {
		writeError(w, http.StatusBadRequest, "server is required (max 128 chars) and at most 1000 tools")
		return
	}
	sess := sessionFrom(r)
	subj := policy.Subject{Agent: sess.Agent, Session: sess.ID}
	out := make([]toolDecision, 0, len(req.Tools))
	version, allowed := "", 0
	for _, tool := range req.Tools {
		if len(tool) > 256 {
			writeError(w, http.StatusBadRequest, "tool name too long")
			return
		}
		d := s.eng.EvaluateMCPTool(subj, req.Server, tool)
		version = d.PolicyVersion
		if d.Allowed() {
			allowed++
		}
		out = append(out, toolDecision{Tool: tool, Effect: d.Effect, RuleID: d.RuleID})
	}
	if err := s.audit.Log(audit.Entry{SessionID: sess.ID, Kind: audit.KindMCP, Destination: req.Server, Operation: "tools/list",
		Decision: audit.DecisionInfo, PolicyVersion: version,
		Metadata: map[string]any{"agent": sess.Agent, "total": len(req.Tools), "allowed": allowed, "hidden": len(req.Tools) - allowed}}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_version": version, "decisions": out})
}

type gatewayEventReq struct {
	Kind          string         `json:"kind"`
	Destination   string         `json:"destination"`
	Operation     string         `json:"operation"`
	Decision      string         `json:"decision"`
	RuleID        string         `json:"rule_id"`
	PolicyVersion string         `json:"policy_version"`
	Metadata      map[string]any `json:"metadata"`
}

// handleGatewayEvent lets a gateway add detail to the audit trail (for example
// bytes transferred, or DNS lookups). The session is taken from the token; a
// gateway can never write events for another session.
func (s *Server) handleGatewayEvent(w http.ResponseWriter, r *http.Request) {
	var req gatewayEventReq
	if !decodeJSON(w, r, &req) {
		return
	}
	switch req.Kind {
	case audit.KindNetwork, audit.KindDNS, audit.KindMCP:
	default:
		writeError(w, http.StatusBadRequest, "kind must be network, dns or mcp")
		return
	}
	switch req.Decision {
	case audit.DecisionAllow, audit.DecisionDeny, audit.DecisionError, audit.DecisionInfo:
	default:
		writeError(w, http.StatusBadRequest, "decision must be allow, deny, error or info")
		return
	}
	if len(req.Destination) > 512 || len(req.Operation) > 128 || len(req.RuleID) > 256 || len(req.PolicyVersion) > 256 {
		writeError(w, http.StatusBadRequest, "field too long")
		return
	}
	sess := sessionFrom(r)
	meta := req.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	meta["agent"] = sess.Agent
	if err := s.audit.Log(audit.Entry{
		SessionID: sess.ID, Kind: req.Kind, Destination: req.Destination, Operation: req.Operation,
		Decision: req.Decision, RuleID: req.RuleID, PolicyVersion: req.PolicyVersion, Metadata: meta,
	}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// handleStreamEvents streams audit events as Server-Sent Events. Clients may
// resume with the Last-Event-ID header; events are replayed from the store
// first, then streamed live.
func (s *Server) handleStreamEvents(w http.ResponseWriter, r *http.Request) {
	f, bad := parseEventFilter(r)
	if bad != "" {
		writeError(w, http.StatusBadRequest, bad)
		return
	}
	rc := http.NewResponseController(w)
	if _, ok := w.(http.Flusher); !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived response

	var lastID int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "Last-Event-ID: invalid")
			return
		}
		lastID = n
	}
	if f.AfterID > lastID {
		lastID = f.AfterID
	}

	match := func(e store.Event) bool {
		return (f.SessionID == "" || e.SessionID == f.SessionID) &&
			(f.Kind == "" || e.Kind == f.Kind) &&
			(f.Decision == "" || e.Decision == f.Decision) &&
			(f.RuleID == "" || e.RuleID == f.RuleID)
	}
	// Subscribe before backfilling so no event falls in the gap.
	live, cancel := s.audit.Subscribe(256, match)
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	_ = rc.Flush()

	send := func(e store.Event) bool {
		if e.ID <= lastID {
			return true
		}
		b, err := json.Marshal(e)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "id: %d\nevent: audit\ndata: %s\n\n", e.ID, b); err != nil {
			return false
		}
		lastID = e.ID
		return true
	}

	if lastID > 0 || r.Header.Get("Last-Event-ID") != "" {
		bf := f
		bf.AfterID, bf.Desc, bf.Limit = lastID, false, 1000
		if past, err := s.st.ListEvents(r.Context(), bf); err == nil {
			for _, e := range past {
				if !send(e) {
					return
				}
			}
		}
		_ = rc.Flush()
	}

	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-live:
			if !ok {
				return
			}
			if !send(e) {
				return
			}
			_ = rc.Flush()
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}
