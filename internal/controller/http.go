package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

type ctxKey int

const sessionKey ctxKey = 1

// Handler returns the HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Admin API.
	admin := func(h http.HandlerFunc) http.Handler { return s.requireAdmin(h) }
	mux.Handle("GET /v1/status", admin(s.handleStatus))
	mux.Handle("POST /v1/sessions", admin(s.handleCreateSession))
	mux.Handle("GET /v1/sessions", admin(s.handleListSessions))
	mux.Handle("GET /v1/sessions/{id}", admin(s.handleGetSession))
	mux.Handle("POST /v1/sessions/{id}/end", admin(s.handleEndSession))
	mux.Handle("GET /v1/events", admin(s.handleListEvents))
	mux.Handle("GET /v1/events/export", admin(s.handleExportEvents))
	mux.Handle("GET /v1/events/stream", admin(s.handleStreamEvents))
	mux.Handle("GET /v1/policies", admin(s.handleListPolicies))
	mux.Handle("GET /v1/policies/{scope}", admin(s.handleGetPolicy))
	mux.Handle("PUT /v1/policies/{scope}", admin(s.handlePutPolicy))
	mux.Handle("GET /v1/policies/{scope}/history", admin(s.handlePolicyHistory))
	mux.Handle("GET /v1/settings", admin(s.handleGetSettings))
	mux.Handle("PUT /v1/settings", admin(s.handlePutSettings))
	mux.Handle("GET /v1/approvals", admin(s.handleListApprovals))
	mux.Handle("POST /v1/approvals/decide", admin(s.handleDecideApproval))

	// Gateway API (per-session token).
	gw := func(h http.HandlerFunc) http.Handler { return s.requireGateway(h) }
	mux.Handle("POST /v1/gw/decide/network", gw(s.handleDecideNetwork))
	mux.Handle("POST /v1/gw/decide/mcp", gw(s.handleDecideMCP))
	mux.Handle("POST /v1/gw/decide/mcp/tools", gw(s.handleDecideMCPTools))
	mux.Handle("POST /v1/gw/events", gw(s.handleGatewayEvent))

	return s.recoverer(s.baseHeaders(s.hostAndOrigin(mux)))
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic in handler", "path", r.URL.Path, "panic", fmt.Sprint(v))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) baseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// hostAndOrigin rejects requests with an unexpected Host (DNS rebinding) or a
// cross-origin Origin header. No CORS headers are ever emitted.
func (s *Server) hostAndOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hosts[hostOnly(r.Host)] {
			writeError(w, http.StatusForbidden, "host not allowed")
			return
		}
		if !s.originOK(r.Header.Get("Origin")) {
			writeError(w, http.StatusForbidden, "origin not allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" || !s.adminOK(tok) {
			unauthorized(w)
			return
		}
		next(w, r)
	})
}

// requireGateway authenticates a per-session token. Ended sessions are
// rejected, so ending a session immediately revokes its gateways.
func (s *Server) requireGateway(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			unauthorized(w)
			return
		}
		sess, err := s.st.SessionByTokenHash(r.Context(), store.HashToken(tok))
		if err != nil || !sess.Active() {
			unauthorized(w)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

func sessionFrom(r *http.Request) store.Session {
	sess, _ := r.Context().Value(sessionKey).(store.Session)
	return sess
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="agentbox"`)
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON strictly decodes a single JSON object from the request body.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON: trailing data")
		return false
	}
	return true
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "cannot read body")
		}
		return nil, false
	}
	return b, true
}

func parseSmallInt(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.st.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
