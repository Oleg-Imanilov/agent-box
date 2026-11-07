package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

// Setting keys accepted by PUT /v1/settings.
const (
	SettingRetentionDays  = "audit_retention_days"
	SettingIncludeContent = "include_content"

	maxRetentionDays = 3650
)

var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newGatewayToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "abgw_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// logAdmin records an administrative action; failures are logged but do not
// fail the (already committed) operation.
func (s *Server) logAdmin(e audit.Entry) {
	if err := s.audit.Log(e); err != nil {
		s.log.Error("audit log failed", "kind", e.Kind, "err", err)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ver, err := s.st.SchemaVersion(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	active, _ := s.st.ListSessions(ctx, true, 1000)
	total, _ := s.st.CountEvents(ctx, "")
	denied, _ := s.st.CountEvents(ctx, audit.DecisionDeny)
	st := s.audit.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         s.cfg.Version,
		"schema_version":  ver,
		"active_sessions": len(active),
		"events_total":    total,
		"events_denied":   denied,
		"audit": map[string]any{
			"written": st.Written, "queue_full": st.QueueFull, "write_errors": st.WriteErrors,
			"subscriber_drops": st.SubscriberDrops, "queued": st.CurrentQueuedLen,
		},
	})
}

// Sessions.

type createSessionReq struct {
	Agent       string `json:"agent"`
	Workspace   string `json:"workspace"`
	ImageDigest string `json:"image_digest"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !agentNameRe.MatchString(req.Agent) {
		writeError(w, http.StatusBadRequest, "agent: invalid name")
		return
	}
	if len(req.Workspace) > 4096 || len(req.ImageDigest) > 256 {
		writeError(w, http.StatusBadRequest, "workspace or image_digest too long")
		return
	}
	id, err := randomHex(8)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "entropy unavailable")
		return
	}
	token, err := newGatewayToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "entropy unavailable")
		return
	}
	sess := store.Session{ID: id, Agent: req.Agent, Workspace: req.Workspace, ImageDigest: req.ImageDigest, StartedAt: time.Now()}
	if err := s.st.CreateSession(r.Context(), sess, store.HashToken(token)); err != nil {
		s.log.Error("create session", "err", err)
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.logAdmin(audit.Entry{SessionID: id, Kind: audit.KindSession, Operation: "session.start", Decision: audit.DecisionInfo,
		Metadata: map[string]any{"agent": req.Agent}})
	got, _ := s.st.GetSession(r.Context(), id)
	// The token is returned exactly once and never stored in clear text.
	writeJSON(w, http.StatusCreated, map[string]any{"session": got, "gateway_token": token})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	active := r.URL.Query().Get("active") == "true" || r.URL.Query().Get("active") == "1"
	list, err := s.st.ListSessions(r.Context(), active, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []store.Session{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, err := s.st.GetSession(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, err := s.st.EndSession(r.Context(), id, time.Time{})
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.polMu.Lock()
	s.eng.Remove(policy.SessionScope(id))
	s.polMu.Unlock()
	s.logAdmin(audit.Entry{SessionID: id, Kind: audit.KindSession, Operation: "session.end", Decision: audit.DecisionInfo})
	writeJSON(w, http.StatusOK, sess)
}

// Events.

func parseEventFilter(r *http.Request) (store.EventFilter, string) {
	q := r.URL.Query()
	f := store.EventFilter{
		SessionID: q.Get("session"),
		Kind:      q.Get("kind"),
		Decision:  q.Get("decision"),
		RuleID:    q.Get("rule"),
		Query:     q.Get("q"),
		Desc:      q.Get("order") != "asc",
	}
	for name, dst := range map[string]*int64{"after_id": &f.AfterID, "before_id": &f.BeforeID} {
		if v := q.Get(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return f, name + ": invalid"
			}
			*dst = n
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return f, "limit: invalid"
		}
		f.Limit = n
	}
	for name, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return f, name + ": must be RFC 3339"
			}
			*dst = t
		}
	}
	return f, ""
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	f, bad := parseEventFilter(r)
	if bad != "" {
		writeError(w, http.StatusBadRequest, bad)
		return
	}
	events, err := s.st.ListEvents(r.Context(), f)
	if err != nil {
		s.log.Error("list events", "err", err)
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if events == nil {
		events = []store.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleExportEvents(w http.ResponseWriter, r *http.Request) {
	f, bad := parseEventFilter(r)
	if bad != "" {
		writeError(w, http.StatusBadRequest, bad)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="agentbox-events.jsonl"`)
	if _, err := audit.ExportJSONL(r.Context(), s.st, w, f); err != nil {
		s.log.Error("export events", "err", err) // headers already sent; connection ends
	}
}

// Policies.

func scopeFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	scope := r.PathValue("scope")
	if !policy.ValidScope(scope) {
		writeError(w, http.StatusBadRequest, "invalid scope (use global, agent:<name> or session:<id>)")
		return "", false
	}
	return scope, true
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	recs, err := s.st.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if recs == nil {
		recs = []store.PolicyRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": recs})
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	scope, ok := scopeFromPath(w, r)
	if !ok {
		return
	}
	rec, err := s.st.GetPolicy(r.Context(), scope)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no policy for scope")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handlePolicyHistory(w http.ResponseWriter, r *http.Request) {
	scope, ok := scopeFromPath(w, r)
	if !ok {
		return
	}
	h, err := s.st.PolicyHistory(r.Context(), scope, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if h == nil {
		h = []store.PolicyRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": h})
}

// handlePutPolicy validates and stores a new policy version, then installs it
// in the engine so it applies to the next decision (live update). Existing
// connections are not affected; that is a gateway concern.
func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	scope, ok := scopeFromPath(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, policy.MaxPolicyBytes+1)
	if !ok {
		return
	}
	p, err := policy.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if name, isAgent := cutPrefix(scope, "agent:"); isAgent && p.Agent != "" && p.Agent != name {
		writeError(w, http.StatusBadRequest, "policy agent does not match scope")
		return
	}
	if id, isSession := cutPrefix(scope, "session:"); isSession {
		sess, err := s.st.GetSession(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if !sess.Active() {
			writeError(w, http.StatusConflict, "session has ended")
			return
		}
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode error")
		return
	}

	s.polMu.Lock()
	version, err := s.st.PutPolicy(r.Context(), scope, canonical, "admin")
	if err == nil {
		err = s.eng.Set(scope, version, p)
	}
	s.polMu.Unlock()
	if err != nil {
		s.log.Error("put policy", "scope", scope, "err", err)
		writeError(w, http.StatusInternalServerError, "could not store policy")
		return
	}
	sessionID := ""
	if id, isSession := cutPrefix(scope, "session:"); isSession {
		sessionID = id
	}
	s.logAdmin(audit.Entry{SessionID: sessionID, Kind: audit.KindPolicy, Destination: scope, Operation: "policy.update",
		Decision: audit.DecisionInfo, Metadata: map[string]any{"scope": scope, "version": version}})
	rec, _ := s.st.GetPolicy(r.Context(), scope)
	writeJSON(w, http.StatusOK, rec)
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

// Settings.

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsView(r.Context()))
}

func (s *Server) settingsView(ctx context.Context) map[string]any {
	days := 0
	include := false
	if all, err := s.st.AllSettings(ctx); err == nil {
		if n, err := parseSmallInt(all[SettingRetentionDays]); err == nil {
			days = n
		}
		include = all[SettingIncludeContent] == "true"
	}
	return map[string]any{SettingRetentionDays: days, SettingIncludeContent: include}
}

type settingsReq struct {
	AuditRetentionDays *int  `json:"audit_retention_days"`
	IncludeContent     *bool `json:"include_content"`
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.AuditRetentionDays != nil && (*req.AuditRetentionDays < 0 || *req.AuditRetentionDays > maxRetentionDays) {
		writeError(w, http.StatusBadRequest, "audit_retention_days must be between 0 and 3650 (0 = keep forever)")
		return
	}
	ctx := r.Context()
	if req.AuditRetentionDays != nil {
		if err := s.st.SetSetting(ctx, SettingRetentionDays, strconv.Itoa(*req.AuditRetentionDays)); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
	}
	if req.IncludeContent != nil {
		if err := s.st.SetSetting(ctx, SettingIncludeContent, strconv.FormatBool(*req.IncludeContent)); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
	}
	if err := s.applySettings(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.logAdmin(audit.Entry{Kind: audit.KindPolicy, Operation: "settings.update", Decision: audit.DecisionInfo,
		Metadata: map[string]any{"include_content": s.settingsView(ctx)[SettingIncludeContent]}})
	writeJSON(w, http.StatusOK, s.settingsView(ctx))
}

func (s *Server) applySettings(ctx context.Context) error {
	all, err := s.st.AllSettings(ctx)
	if err != nil {
		return err
	}
	s.audit.SetIncludeContent(all[SettingIncludeContent] == "true")
	return nil
}
