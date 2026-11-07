package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
}

type decideMCPReq struct {
	Server    string `json:"server"`
	Tool      string `json:"tool"`
	Operation string `json:"operation"`
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
	if resp.Effect == policy.Allow && s.cfg.AllowCacheTTL > 0 {
		resp.CacheTTLSeconds = int(s.cfg.AllowCacheTTL / time.Second)
	}
	writeJSON(w, http.StatusOK, resp)
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
	sess := sessionFrom(r)
	d := s.eng.EvaluateNetwork(policy.Subject{Agent: sess.Agent, Session: sess.ID}, req.Host, req.Port)
	dest := req.Host + ":" + strconv.Itoa(req.Port)
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
	sess := sessionFrom(r)
	d := s.eng.EvaluateMCPTool(policy.Subject{Agent: sess.Agent, Session: sess.ID}, req.Server, req.Tool)
	op := req.Operation
	if op == "" {
		op = "tools/call"
	}
	s.respondDecision(w, sess, audit.KindMCP, req.Server+"/"+req.Tool, op, d, started)
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
