// Package controller implements the AgentBox control plane HTTP API:
// sessions, policies, audit events (including a live stream), settings, and
// the authenticated decision endpoints used by the gateways.
//
// Two credential types exist:
//   - the admin token (UI/launcher), compared in constant time;
//   - per-session gateway tokens, which identify exactly one active session
//     and can only be used for the /v1/gw/ endpoints.
//
// Tokens are only accepted in the Authorization header (never cookies or query
// strings), which also makes the API immune to classic CSRF. Host and Origin
// headers are validated to defeat DNS rebinding.
package controller

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

// MinAdminTokenLen is the minimum accepted admin token length.
const MinAdminTokenLen = 32

// Config configures a Server.
type Config struct {
	// AdminToken authenticates the UI and launcher (required, >= 32 chars).
	AdminToken string
	// AllowedHosts are the host names (without port) accepted in the Host and
	// Origin headers. Defaults to localhost, 127.0.0.1 and ::1.
	AllowedHosts []string
	// MaxBodyBytes bounds request bodies (default 1 MiB).
	MaxBodyBytes int64
	// AllowCacheTTL is how long gateways may cache an "allow" decision.
	// Zero disables caching.
	AllowCacheTTL time.Duration
	// Version is reported by /v1/status.
	Version string
	// Logger receives operational logs. Tokens are never logged.
	Logger *slog.Logger
}

// Server is the controller HTTP API.
type Server struct {
	cfg   Config
	st    *store.Store
	eng   *policy.Engine
	audit *audit.Logger
	log   *slog.Logger

	hosts map[string]bool

	adminDigest [sha256.Size]byte

	polMu sync.Mutex // serializes store+engine policy updates
	hub   approvalHub
}

// New creates a Server.
func New(cfg Config, st *store.Store, eng *policy.Engine, al *audit.Logger) (*Server, error) {
	if len(cfg.AdminToken) < MinAdminTokenLen {
		return nil, fmt.Errorf("controller: admin token must be at least %d characters", MinAdminTokenLen)
	}
	if st == nil || eng == nil || al == nil {
		return nil, errors.New("controller: store, engine and audit logger are required")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if len(cfg.AllowedHosts) == 0 {
		cfg.AllowedHosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, st: st, eng: eng, audit: al, log: cfg.Logger, hosts: map[string]bool{}}
	for _, h := range cfg.AllowedHosts {
		s.hosts[normalizeHostName(h)] = true
	}
	s.adminDigest = sha256.Sum256([]byte(cfg.AdminToken))
	return s, nil
}

// LoadState loads persisted policies into the engine and applies persisted
// settings. Session-scoped policies are only loaded for active sessions.
func (s *Server) LoadState(ctx context.Context) error {
	// Requests waiting on approvals died with the previous process; expire
	// them so the queue does not show stale items.
	if _, err := s.st.ExpireApprovals(ctx, time.Now().AddDate(100, 0, 0)); err != nil {
		return err
	}
	recs, err := s.st.ListPolicies(ctx)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if id, ok := strings.CutPrefix(r.Scope, "session:"); ok {
			sess, err := s.st.GetSession(ctx, id)
			if err != nil || !sess.Active() {
				continue
			}
		}
		p, err := policy.Parse(r.RuleJSON)
		if err != nil {
			// Fail closed: a policy that no longer validates is not installed.
			s.log.Error("stored policy invalid; not loaded", "scope", r.Scope, "version", r.Version, "err", err)
			continue
		}
		if err := s.eng.Set(r.Scope, r.Version, p); err != nil {
			s.log.Error("stored policy rejected by engine", "scope", r.Scope, "err", err)
		}
	}
	return s.applySettings(ctx)
}

// RetentionDays returns the configured audit retention in days (0 = forever).
func (s *Server) RetentionDays() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v, err := s.st.GetSetting(ctx, SettingRetentionDays)
	if err != nil {
		return 0
	}
	n, err := parseSmallInt(v)
	if err != nil {
		return 0
	}
	return n
}

func normalizeHostName(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return h
}

// hostOnly extracts the host (without port) from a Host header or URL host.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return normalizeHostName(h)
	}
	return normalizeHostName(hostport)
}

func (s *Server) adminOK(token string) bool {
	d := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(d[:], s.adminDigest[:]) == 1
}

// originOK validates the Origin header, when present.
func (s *Server) originOK(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return s.hosts[hostOnly(u.Host)]
}
