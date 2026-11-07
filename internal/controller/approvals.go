package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

// Approval timeouts are configurable per entity type (network, mcp).
const (
	SettingApprovalTimeoutNetwork = "approval_timeout_network_seconds"
	SettingApprovalTimeoutMCP     = "approval_timeout_mcp_seconds"

	DefaultApprovalTimeoutNetwork = 60
	DefaultApprovalTimeoutMCP     = 120
	minApprovalTimeoutSeconds     = 5
	maxApprovalTimeoutSeconds     = 600

	maxPendingApprovalsPerSession = 20
)

// Rule IDs for approval outcomes that are not user decisions.
const (
	RuleApprovalTimeout   = "approval-timeout"
	RuleApprovalQueueFull = "approval-queue-full"
	RuleApprovalError     = "approval-error"
	RuleApprovalConflict  = "approval-conflict"
	RuleApprovalCancelled = "approval-cancelled"
)

var clientRequestIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// approvalHub wakes goroutines waiting for an approval decision.
type approvalHub struct {
	mu    sync.Mutex
	chans map[string]chan struct{}
}

func (h *approvalHub) channel(id string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.chans == nil {
		h.chans = map[string]chan struct{}{}
	}
	ch, ok := h.chans[id]
	if !ok {
		ch = make(chan struct{})
		h.chans[id] = ch
	}
	return ch
}

func (h *approvalHub) wake(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.chans[id]; ok {
		close(ch)
		delete(h.chans, id)
	}
}

func (h *approvalHub) wakePrefix(prefix string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ch := range h.chans {
		if strings.HasPrefix(id, prefix) {
			close(ch)
			delete(h.chans, id)
		}
	}
}

// approvalTimeout returns the configured wait for an entity type.
func (s *Server) approvalTimeout(kind string) time.Duration {
	key, def := SettingApprovalTimeoutNetwork, DefaultApprovalTimeoutNetwork
	if kind == audit.KindMCP {
		key, def = SettingApprovalTimeoutMCP, DefaultApprovalTimeoutMCP
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	secs := def
	if v, err := s.st.GetSetting(ctx, key); err == nil {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= maxApprovalTimeoutSeconds {
			secs = n
		}
	}
	return time.Duration(secs) * time.Second
}

func validClientRequestID(id string) bool { return clientRequestIDRe.MatchString(id) }

// askApproval turns a default-deny decision into a human decision. It blocks
// until the approval is decided, expires, or ctx is cancelled, and always
// returns a final decision (deny on anything other than an explicit allow).
// Explicit deny rules never reach this function: they cannot be approved.
func (s *Server) askApproval(ctx context.Context, sess store.Session, kind, subject, clientReqID string, base policy.Decision) policy.Decision {
	fail := func(rule, reason string) policy.Decision {
		base.Effect, base.RuleID, base.Reason = policy.Deny, rule, reason
		return base
	}
	reqID := sess.ID + "/" + clientReqID
	timeout := s.approvalTimeout(kind)
	created := false

	existing, err := s.st.ApprovalByRequestID(ctx, reqID)
	switch {
	case err == nil:
		if existing.SessionID != sess.ID || existing.Kind != kind || existing.Subject != subject {
			return fail(RuleApprovalConflict, "request id was used for a different request")
		}
	case errors.Is(err, store.ErrNotFound):
		n, err := s.st.PendingApprovalCount(ctx, sess.ID)
		if err != nil {
			return fail(RuleApprovalError, "approval unavailable")
		}
		if n >= maxPendingApprovalsPerSession {
			return fail(RuleApprovalQueueFull, "too many pending approvals")
		}
		exp := time.Now().Add(timeout)
		if _, err := s.st.CreateApproval(ctx, store.Approval{RequestID: reqID, SessionID: sess.ID, Kind: kind, Subject: subject, ExpiresAt: &exp}); err != nil {
			s.log.Error("create approval", "err", err)
			return fail(RuleApprovalError, "approval unavailable")
		}
		created = true
		s.logAdmin(audit.Entry{SessionID: sess.ID, Kind: audit.KindApproval, Destination: subject, Operation: "approval.requested",
			Decision: audit.DecisionInfo, PolicyVersion: base.PolicyVersion,
			Metadata: map[string]any{"request_id": reqID, "entity": kind, "timeout_seconds": int(timeout / time.Second), "agent": sess.Agent}})
	default:
		return fail(RuleApprovalError, "approval unavailable")
	}

	d := s.waitApproval(ctx, reqID, base)
	if created && d.RuleID == RuleApprovalTimeout {
		s.logAdmin(audit.Entry{SessionID: sess.ID, Kind: audit.KindApproval, Destination: subject, Operation: "approval.expired",
			Decision: audit.DecisionDeny, RuleID: RuleApprovalTimeout, PolicyVersion: base.PolicyVersion,
			Metadata: map[string]any{"request_id": reqID}})
	}
	return d
}

func (s *Server) waitApproval(ctx context.Context, reqID string, base policy.Decision) policy.Decision {
	deny := func(rule, reason string) policy.Decision {
		base.Effect, base.RuleID, base.Reason = policy.Deny, rule, reason
		return base
	}
	for {
		ch := s.hub.channel(reqID) // obtained before reading state: no lost wakeups
		a, err := s.st.ApprovalByRequestID(ctx, reqID)
		if err != nil {
			return deny(RuleApprovalError, "approval unavailable")
		}
		switch a.Status {
		case store.ApprovalDecided:
			return decisionFromApproval(a, base)
		case store.ApprovalExpired:
			return deny(RuleApprovalTimeout, "approval timed out")
		}
		wait := time.Second
		if a.ExpiresAt != nil {
			wait = time.Until(*a.ExpiresAt)
		}
		if wait <= 0 {
			_, _ = s.st.ExpireApprovals(ctx, time.Now())
			continue // re-read: now expired (or decided in the meantime)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ch:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return deny(RuleApprovalCancelled, "request cancelled while waiting for approval")
		}
		timer.Stop()
	}
}

func decisionFromApproval(a store.Approval, base policy.Decision) policy.Decision {
	base.RuleID = fmt.Sprintf("approval:%d:%s", a.ID, a.Decision)
	if a.Decision == store.DecisionDeny {
		base.Effect, base.Reason = policy.Deny, "denied by user"
		return base
	}
	base.Effect, base.Reason = policy.Allow, "approved by user"
	return base
}

// Admin API.

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "":
		status = store.ApprovalPending
	case "all":
		status = ""
	case store.ApprovalPending, store.ApprovalDecided, store.ApprovalExpired:
	default:
		writeError(w, http.StatusBadRequest, "status must be pending, decided, expired or all")
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "limit: invalid")
			return
		}
		limit = n
	}
	list, err := s.st.ListApprovals(r.Context(), status, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []store.Approval{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": list})
}

type decideApprovalReq struct {
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
}

// handleDecideApproval records a user decision. "session" adds an allow rule
// to the session scope, "persist" adds it to the agent scope; both apply to
// later requests through the normal policy engine.
func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	var req decideApprovalReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !store.ValidApprovalDecision(req.Decision) {
		writeError(w, http.StatusBadRequest, "decision must be once, session, persist or deny")
		return
	}
	ctx := r.Context()
	a, err := s.st.ApprovalByRequestID(ctx, req.RequestID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if a.Status != store.ApprovalPending || (a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now())) {
		writeError(w, http.StatusConflict, "approval already decided or expired")
		return
	}

	if req.Decision == store.DecisionSession || req.Decision == store.DecisionPersist {
		sess, err := s.st.GetSession(ctx, a.SessionID)
		if err != nil || !sess.Active() {
			writeError(w, http.StatusConflict, "session has ended")
			return
		}
		scope := policy.SessionScope(sess.ID)
		if req.Decision == store.DecisionPersist {
			scope = policy.AgentScope(sess.Agent)
		}
		if err := s.appendAllowRule(ctx, scope, a.Kind, a.Subject); err != nil {
			s.log.Error("approval rule", "scope", scope, "err", err)
			writeError(w, http.StatusUnprocessableEntity, "cannot create a rule for this request; use once or deny: "+err.Error())
			return
		}
	}

	decided, err := s.st.DecideApproval(ctx, req.RequestID, req.Decision, "admin", time.Now())
	if errors.Is(err, store.ErrAlreadyDecided) {
		writeError(w, http.StatusConflict, "approval already decided or expired")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	effect := audit.DecisionAllow
	if decided.Decision == store.DecisionDeny {
		effect = audit.DecisionDeny
	}
	s.logAdmin(audit.Entry{SessionID: decided.SessionID, Kind: audit.KindApproval, Destination: decided.Subject, Operation: "approval.decided",
		Decision: effect, RuleID: fmt.Sprintf("approval:%d:%s", decided.ID, decided.Decision),
		Metadata: map[string]any{"request_id": decided.RequestID, "choice": decided.Decision, "actor": decided.Actor}})
	s.hub.wake(decided.RequestID)
	writeJSON(w, http.StatusOK, decided)
}

// appendAllowRule adds an exact allow rule for an approved request to the
// policy at scope (creating the policy if needed) and installs it live.
func (s *Server) appendAllowRule(ctx context.Context, scope, kind, subject string) error {
	s.polMu.Lock()
	defer s.polMu.Unlock()

	p := &policy.Policy{}
	if rec, err := s.st.GetPolicy(ctx, scope); err == nil {
		parsed, err := policy.Parse(rec.RuleJSON)
		if err != nil {
			return fmt.Errorf("existing policy invalid: %w", err)
		}
		p = parsed
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	switch kind {
	case audit.KindNetwork:
		host, port, err := net.SplitHostPort(subject)
		if err != nil {
			return fmt.Errorf("bad network subject %q", subject)
		}
		rule := net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
		if !contains(p.Network.Allow, rule) {
			p.Network.Allow = append(p.Network.Allow, rule)
		}
	case audit.KindMCP:
		server, tool, ok := strings.Cut(subject, "/")
		if !ok {
			return fmt.Errorf("bad mcp subject %q", subject)
		}
		if p.MCP == nil {
			p.MCP = map[string]policy.MCPServer{}
		}
		srv := p.MCP[server]
		if !contains(srv.AllowTools, tool) {
			srv.AllowTools = append(srv.AllowTools, tool)
		}
		p.MCP[server] = srv
	default:
		return fmt.Errorf("unsupported approval kind %q", kind)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return err
	}
	version, err := s.st.PutPolicy(ctx, scope, canonical, "approval")
	if err != nil {
		return err
	}
	if err := s.eng.Set(scope, version, p); err != nil {
		return err
	}
	s.logAdmin(audit.Entry{Kind: audit.KindPolicy, Destination: scope, Operation: "policy.update", Decision: audit.DecisionInfo,
		Metadata: map[string]any{"scope": scope, "version": version, "source": "approval"}})
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
