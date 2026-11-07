package controller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

const adminToken = "0123456789abcdef0123456789abcdef-admin"

type env struct {
	t   *testing.T
	st  *store.Store
	eng *policy.Engine
	al  *audit.Logger
	srv *Server
	ts  *httptest.Server
}

func newEnv(t *testing.T, cfg Config) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine()
	al := audit.NewLogger(st, audit.Options{FlushInterval: 5 * time.Millisecond})
	if cfg.AdminToken == "" {
		cfg.AdminToken = adminToken
	}
	srv, err := New(cfg, st, eng, al)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	e := &env{t: t, st: st, eng: eng, al: al, srv: srv, ts: ts}
	t.Cleanup(func() {
		ts.CloseClientConnections() // unblocks any open SSE streams
		ts.Close()
		_ = al.Close(context.Background())
		_ = st.Close()
	})
	return e
}

// do sends a request. The Host header is localhost by default.
func (e *env) do(method, path, token string, body any, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Host = "localhost"
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (e *env) admin(method, path string, body any) (*http.Response, []byte) {
	return e.do(method, path, adminToken, body, nil)
}

func (e *env) createSession(agent string) (id, token string) {
	e.t.Helper()
	resp, body := e.admin("POST", "/v1/sessions", map[string]string{"agent": agent, "workspace": "/w"})
	if resp.StatusCode != 201 {
		e.t.Fatalf("create session: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Session store.Session `json:"session"`
		Token   string        `json:"gateway_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		e.t.Fatal(err)
	}
	return out.Session.ID, out.Token
}

func (e *env) putPolicy(scope, doc string) {
	e.t.Helper()
	resp, body := e.admin("PUT", "/v1/policies/"+scope, doc)
	if resp.StatusCode != 200 {
		e.t.Fatalf("put policy %s: %d %s", scope, resp.StatusCode, body)
	}
}

func (e *env) flush() {
	e.t.Helper()
	if err := e.al.Flush(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

func TestNewValidatesConfig(t *testing.T) {
	st, _ := store.Open(context.Background(), filepath.Join(t.TempDir(), "x.db"))
	defer st.Close()
	al := audit.NewLogger(st, audit.Options{})
	defer al.Close(context.Background())
	if _, err := New(Config{AdminToken: "short"}, st, policy.NewEngine(), al); err == nil {
		t.Fatal("short admin token must be rejected")
	}
	if _, err := New(Config{AdminToken: adminToken}, nil, policy.NewEngine(), al); err == nil {
		t.Fatal("nil store must be rejected")
	}
}

func TestHealthNeedsNoAuth(t *testing.T) {
	e := newEnv(t, Config{})
	resp, _ := e.do("GET", "/healthz", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("security headers missing")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS must never be enabled")
	}
}

func TestAdminAuth(t *testing.T) {
	e := newEnv(t, Config{})
	paths := []struct{ m, p string }{
		{"GET", "/v1/status"}, {"GET", "/v1/sessions"}, {"GET", "/v1/events"}, {"GET", "/v1/events/export"},
		{"GET", "/v1/events/stream"}, {"GET", "/v1/policies"}, {"PUT", "/v1/policies/global"}, {"GET", "/v1/settings"},
		{"POST", "/v1/sessions"},
	}
	for _, tc := range paths {
		for name, tok := range map[string]string{"none": "", "wrong": "wrong-token-wrong-token-wrong-token-xx", "prefix": adminToken[:20]} {
			resp, _ := e.do(tc.m, tc.p, tok, "{}", nil)
			if resp.StatusCode != 401 {
				t.Errorf("%s %s with %s token = %d, want 401", tc.m, tc.p, name, resp.StatusCode)
			}
		}
	}
	// The token must not be accepted from query string or cookie.
	req, _ := http.NewRequest("GET", e.ts.URL+"/v1/status?token="+adminToken, nil)
	req.Host = "localhost"
	req.AddCookie(&http.Cookie{Name: "token", Value: adminToken})
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("query/cookie token accepted: %d", resp.StatusCode)
	}
	if resp, _ := e.admin("GET", "/v1/status", nil); resp.StatusCode != 200 {
		t.Fatalf("valid token = %d", resp.StatusCode)
	}
}

func TestGatewayTokenCannotUseAdminAPI(t *testing.T) {
	e := newEnv(t, Config{})
	_, gw := e.createSession("hermes")
	for _, p := range []string{"/v1/status", "/v1/sessions", "/v1/events", "/v1/policies", "/v1/settings"} {
		if resp, _ := e.do("GET", p, gw, nil, nil); resp.StatusCode != 401 {
			t.Errorf("gateway token on %s = %d, want 401", p, resp.StatusCode)
		}
	}
	// And the admin token is not a gateway token.
	if resp, _ := e.do("POST", "/v1/gw/decide/network", adminToken, map[string]any{"host": "a.com", "port": 443}, nil); resp.StatusCode != 401 {
		t.Errorf("admin token on gateway API = %d, want 401", resp.StatusCode)
	}
}

func TestHostAndOriginChecks(t *testing.T) {
	e := newEnv(t, Config{AllowedHosts: []string{"localhost", "controller"}})
	if resp, _ := e.do("GET", "/healthz", "", nil, map[string]string{"Host": "evil.example.com"}); resp.StatusCode != 403 {
		t.Errorf("rebinding host = %d, want 403", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/healthz", "", nil, map[string]string{"Host": "controller:8080"}); resp.StatusCode != 200 {
		t.Errorf("configured host with port = %d, want 200", resp.StatusCode)
	}
	for _, origin := range []string{"https://evil.example.com", "null", "http://localhost.evil.com", "ftp://localhost"} {
		resp, _ := e.admin("GET", "/v1/status", nil)
		_ = resp
		resp, _ = e.do("GET", "/v1/status", adminToken, nil, map[string]string{"Origin": origin})
		if resp.StatusCode != 403 {
			t.Errorf("origin %q = %d, want 403", origin, resp.StatusCode)
		}
	}
	if resp, _ := e.do("GET", "/v1/status", adminToken, nil, map[string]string{"Origin": "http://localhost:5173"}); resp.StatusCode != 200 {
		t.Errorf("localhost origin = %d, want 200", resp.StatusCode)
	}
	// CSRF-style simple POST from another origin with no credentials is rejected before auth matters.
	if resp, _ := e.do("POST", "/v1/sessions", "", `{"agent":"x"}`, map[string]string{"Origin": "https://evil.example.com"}); resp.StatusCode != 403 {
		t.Errorf("cross-origin POST = %d, want 403", resp.StatusCode)
	}
}

func TestSessionLifecycleAndTokenRevocation(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	if !strings.HasPrefix(tok, "abgw_") || len(tok) < 40 {
		t.Fatalf("token format: %q", tok)
	}
	// Token is stored only as a hash.
	if _, err := e.st.SessionByTokenHash(context.Background(), tok); err == nil {
		t.Fatal("clear-text token must not be stored")
	}
	body := map[string]any{"host": "a.com", "port": 443}
	if resp, _ := e.do("POST", "/v1/gw/decide/network", tok, body, nil); resp.StatusCode != 200 {
		t.Fatalf("decide = %d", resp.StatusCode)
	}
	resp, out := e.admin("POST", "/v1/sessions/"+id+"/end", nil)
	if resp.StatusCode != 200 || decode[store.Session](t, out).Active() {
		t.Fatalf("end = %d %s", resp.StatusCode, out)
	}
	if resp, _ := e.do("POST", "/v1/gw/decide/network", tok, body, nil); resp.StatusCode != 401 {
		t.Fatalf("ended session token must be rejected, got %d", resp.StatusCode)
	}
	if resp, _ := e.admin("POST", "/v1/sessions/nope/end", nil); resp.StatusCode != 404 {
		t.Fatalf("end unknown = %d", resp.StatusCode)
	}
	if resp, _ := e.admin("GET", "/v1/sessions/nope", nil); resp.StatusCode != 404 {
		t.Fatalf("get unknown = %d", resp.StatusCode)
	}
	_, out = e.admin("GET", "/v1/sessions?active=true", nil)
	if n := len(decode[struct{ Sessions []store.Session }](t, out).Sessions); n != 0 {
		t.Fatalf("active sessions = %d", n)
	}
	for _, bad := range []string{`{"agent":"Bad Name"}`, `{"agent":""}`, `{"agent":"ok","extra":1}`, `not json`, `{"agent":"ok"} {}`} {
		if resp, _ := e.admin("POST", "/v1/sessions", bad); resp.StatusCode != 400 {
			t.Errorf("create session %q = %d, want 400", bad, resp.StatusCode)
		}
	}
}

func TestPolicyLiveUpdateAffectsNextDecision(t *testing.T) {
	e := newEnv(t, Config{AllowCacheTTL: 5 * time.Second})
	_, tok := e.createSession("hermes")
	decide := func(host string, port int) DecisionResponse {
		resp, out := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": host, "port": port}, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("decide = %d %s", resp.StatusCode, out)
		}
		return decode[DecisionResponse](t, out)
	}

	if d := decide("api.openai.com", 443); d.Effect != policy.Deny || d.RuleID != policy.RuleDefaultDeny {
		t.Fatalf("no policy must deny: %+v", d)
	}
	e.putPolicy("global", "network:\n  allow: [api.openai.com:443]")
	d := decide("api.openai.com", 443)
	if d.Effect != policy.Allow || d.RuleID != "global#network.allow[0]" || d.PolicyVersion != "global@1" || d.CacheTTLSeconds != 5 {
		t.Fatalf("after allow: %+v", d)
	}
	e.putPolicy("agent:hermes", "network:\n  deny: [api.openai.com:443]")
	if d := decide("api.openai.com", 443); d.Effect != policy.Deny || d.RuleID != "agent:hermes#network.deny[0]" || d.CacheTTLSeconds != 0 {
		t.Fatalf("agent deny must take effect immediately: %+v", d)
	}
	e.putPolicy("global", "network:\n  allow: [other.com:443]") // v2
	if d := decide("other.com", 443); d.PolicyVersion != "global@2,agent:hermes@1" {
		t.Fatalf("policy version: %+v", d)
	}

	// Invalid policies are rejected and do not change enforcement.
	for _, bad := range []string{"network:\n  default: allow", "network:\n  allow: [nope]", "bogus: 1", "agent: other\n"} {
		scope := "global"
		if strings.HasPrefix(bad, "agent:") {
			scope = "agent:hermes"
		}
		if resp, _ := e.admin("PUT", "/v1/policies/"+scope, bad); resp.StatusCode != 400 {
			t.Errorf("bad policy %q = %d, want 400", bad, resp.StatusCode)
		}
	}
	if d := decide("other.com", 443); d.Effect != policy.Allow {
		t.Fatalf("rejected update altered enforcement: %+v", d)
	}
	if resp, _ := e.admin("PUT", "/v1/policies/bogus", "{}"); resp.StatusCode != 400 {
		t.Errorf("bad scope = %d", resp.StatusCode)
	}
	if resp, _ := e.admin("PUT", "/v1/policies/session:missing", "{}"); resp.StatusCode != 404 {
		t.Errorf("session policy for missing session = %d", resp.StatusCode)
	}
	big := "# " + strings.Repeat("x", policy.MaxPolicyBytes+10)
	if resp, _ := e.admin("PUT", "/v1/policies/global", big); resp.StatusCode != 413 {
		t.Errorf("oversize policy = %d, want 413", resp.StatusCode)
	}

	_, out := e.admin("GET", "/v1/policies/global/history", nil)
	if h := decode[struct{ History []store.PolicyRecord }](t, out).History; len(h) != 2 || h[0].Version != 2 {
		t.Fatalf("history = %+v", h)
	}
	if resp, _ := e.admin("GET", "/v1/policies/agent:nobody", nil); resp.StatusCode != 404 {
		t.Errorf("get missing policy = %d", resp.StatusCode)
	}
}

func TestSessionScopedPolicyDiesWithSession(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	e.putPolicy("session:"+id, "network:\n  allow: [tmp.example.com:443]")
	resp, out := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "tmp.example.com", "port": 443}, nil)
	if resp.StatusCode != 200 || decode[DecisionResponse](t, out).Effect != policy.Allow {
		t.Fatalf("session policy not applied: %s", out)
	}
	e.admin("POST", "/v1/sessions/"+id+"/end", nil)
	if d := e.eng.EvaluateNetwork(policy.Subject{Agent: "hermes", Session: id}, "tmp.example.com", 443); d.Allowed() {
		t.Fatal("session policy must be removed when the session ends")
	}
	if resp, _ := e.admin("PUT", "/v1/policies/session:"+id, "{}"); resp.StatusCode != 409 {
		t.Fatalf("policy for ended session = %d, want 409", resp.StatusCode)
	}
}

func TestMCPDecision(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	e.putPolicy("global", "mcp:\n  github:\n    allow_tools: [get_file_contents, list_issues]\n    deny_tools: [delete_repository]")
	for tool, want := range map[string]policy.Effect{"get_file_contents": policy.Allow, "delete_repository": policy.Deny, "create_issue": policy.Deny} {
		_, out := e.do("POST", "/v1/gw/decide/mcp", tok, map[string]any{"server": "github", "tool": tool}, nil)
		if d := decode[DecisionResponse](t, out); d.Effect != want {
			t.Errorf("%s = %+v, want %s", tool, d, want)
		}
	}
}

func TestEveryDecisionIsAuditedWithSessionAndRule(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	e.putPolicy("global", "network:\n  allow: [a.com:443]\nmcp:\n  gh:\n    allow_tools: [ok]")
	e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "a.com", "port": 443}, nil)
	e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "b.com", "port": 443}, nil)
	e.do("POST", "/v1/gw/decide/mcp", tok, map[string]any{"server": "gh", "tool": "evil"}, nil)
	e.flush()

	_, out := e.admin("GET", "/v1/events?session="+id+"&order=asc&limit=100", nil)
	events := decode[struct{ Events []store.Event }](t, out).Events
	var net, mcp []store.Event
	for _, ev := range events {
		switch ev.Kind {
		case "network":
			net = append(net, ev)
		case "mcp":
			mcp = append(mcp, ev)
		}
	}
	if len(net) != 2 || len(mcp) != 1 {
		t.Fatalf("events: %+v", events)
	}
	if net[0].Decision != "allow" || net[0].RuleID != "global#network.allow[0]" || net[0].Destination != "a.com:443" || net[0].SessionID != id {
		t.Errorf("allow event = %+v", net[0])
	}
	if net[1].Decision != "deny" || net[1].RuleID != policy.RuleDefaultDeny || net[1].PolicyVersion != "global@1" {
		t.Errorf("deny event = %+v", net[1])
	}
	if mcp[0].Decision != "deny" || mcp[0].Destination != "gh/evil" {
		t.Errorf("mcp event = %+v", mcp[0])
	}

	_, out = e.admin("GET", "/v1/events?decision=deny&kind=network", nil)
	if n := len(decode[struct{ Events []store.Event }](t, out).Events); n != 1 {
		t.Errorf("filtered = %d", n)
	}
	for _, bad := range []string{"limit=x", "after_id=-1", "since=yesterday", "before_id=abc"} {
		if resp, _ := e.admin("GET", "/v1/events?"+bad, nil); resp.StatusCode != 400 {
			t.Errorf("events?%s = %d, want 400", bad, resp.StatusCode)
		}
	}
}

func TestFailClosedWhenAuditUnavailable(t *testing.T) {
	e := newEnv(t, Config{AllowCacheTTL: 5 * time.Second})
	_, tok := e.createSession("hermes")
	e.putPolicy("global", "network:\n  allow: [a.com:443]")
	_ = e.al.Close(context.Background()) // simulates an unavailable audit trail
	_, out := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "a.com", "port": 443}, nil)
	d := decode[DecisionResponse](t, out)
	if d.Effect != policy.Deny || d.RuleID != RuleAuditUnavailable || d.CacheTTLSeconds != 0 {
		t.Fatalf("must deny when audit is down: %+v", d)
	}
}

func TestGatewayEvents(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	ok := map[string]any{"kind": "dns", "destination": "a.com", "decision": "allow", "metadata": map[string]any{"bytes": 10, "authorization": "Bearer abcdefgh12345678"}}
	if resp, out := e.do("POST", "/v1/gw/events", tok, ok, nil); resp.StatusCode != 202 {
		t.Fatalf("event = %d %s", resp.StatusCode, out)
	}
	for _, bad := range []map[string]any{
		{"kind": "policy", "decision": "allow"},
		{"kind": "dns", "decision": "maybe"},
		{"kind": "dns", "decision": "allow", "session_id": "other"}, // unknown field: cannot spoof a session
		{"kind": "dns", "decision": "allow", "destination": strings.Repeat("x", 600)},
	} {
		if resp, _ := e.do("POST", "/v1/gw/events", tok, bad, nil); resp.StatusCode != 400 {
			t.Errorf("bad event %v = %d, want 400", bad, resp.StatusCode)
		}
	}
	e.flush()
	events, _ := e.st.ListEvents(context.Background(), store.EventFilter{Kind: "dns"})
	if len(events) != 1 || events[0].SessionID != id {
		t.Fatalf("events = %+v", events)
	}
	if strings.Contains(string(events[0].Metadata), "abcdefgh12345678") {
		t.Fatalf("secret persisted: %s", events[0].Metadata)
	}
}

func TestBodyLimitAndStrictJSON(t *testing.T) {
	e := newEnv(t, Config{MaxBodyBytes: 256})
	_, tok := e.createSession("hermes")
	big := `{"host":"` + strings.Repeat("a", 1000) + `","port":1}`
	if resp, _ := e.do("POST", "/v1/gw/decide/network", tok, big, nil); resp.StatusCode != 413 {
		t.Errorf("oversize = %d, want 413", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/v1/gw/decide/network", tok, `{"host":"a.com","port":1,"extra":true}`, nil); resp.StatusCode != 400 {
		t.Errorf("unknown field = %d, want 400", resp.StatusCode)
	}
}

func TestExportJSONL(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	for i := 0; i < 5; i++ {
		e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "a.com", "port": 443}, nil)
	}
	e.flush()
	resp, out := e.admin("GET", "/v1/events/export?kind=network", nil)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "ndjson") {
		t.Fatalf("export = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines = %d", len(lines))
	}
	var ev store.Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil || ev.Kind != "network" {
		t.Fatalf("line 0: %v %+v", err, ev)
	}
}

func TestSettings(t *testing.T) {
	e := newEnv(t, Config{})
	_, out := e.admin("GET", "/v1/settings", nil)
	if s := decode[map[string]any](t, out); s["audit_retention_days"] != float64(0) || s["include_content"] != false {
		t.Fatalf("defaults = %v", s)
	}
	resp, out := e.admin("PUT", "/v1/settings", map[string]any{"audit_retention_days": 30, "include_content": true})
	if resp.StatusCode != 200 {
		t.Fatalf("put = %d %s", resp.StatusCode, out)
	}
	if e.srv.RetentionDays() != 30 {
		t.Fatalf("RetentionDays = %d", e.srv.RetentionDays())
	}
	// include_content takes effect on the live logger.
	_, tok := e.createSession("hermes")
	e.do("POST", "/v1/gw/events", tok, map[string]any{"kind": "mcp", "decision": "info", "metadata": map[string]any{"prompt": "visible"}}, nil)
	e.flush()
	events, _ := e.st.ListEvents(context.Background(), store.EventFilter{Kind: "mcp"})
	if len(events) != 1 || !strings.Contains(string(events[0].Metadata), "visible") {
		t.Fatalf("include_content not applied: %+v", events)
	}
	for _, bad := range []any{map[string]any{"audit_retention_days": -1}, map[string]any{"audit_retention_days": 99999}, map[string]any{"unknown": 1}} {
		if resp, _ := e.admin("PUT", "/v1/settings", bad); resp.StatusCode != 400 {
			t.Errorf("bad settings %v = %d", bad, resp.StatusCode)
		}
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t, Config{Version: "9.9.9"})
	_, tok := e.createSession("hermes")
	e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "x.com", "port": 1}, nil)
	e.flush()
	_, out := e.admin("GET", "/v1/status", nil)
	s := decode[map[string]any](t, out)
	if s["version"] != "9.9.9" || s["active_sessions"] != float64(1) || s["events_denied"] != float64(1) || s["schema_version"] != float64(1) {
		t.Fatalf("status = %v", s)
	}
}

func TestLoadStateRestoresPoliciesAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	open := func() (*Server, *policy.Engine, *store.Store, *audit.Logger) {
		st, err := store.Open(ctx, filepath.Join(dir, "r.db"))
		if err != nil {
			t.Fatal(err)
		}
		eng := policy.NewEngine()
		al := audit.NewLogger(st, audit.Options{FlushInterval: 5 * time.Millisecond})
		srv, err := New(Config{AdminToken: adminToken}, st, eng, al)
		if err != nil {
			t.Fatal(err)
		}
		return srv, eng, st, al
	}
	srv, _, st, al := open()
	ts := httptest.NewServer(srv.Handler())
	req, _ := http.NewRequest("PUT", ts.URL+"/v1/policies/global", strings.NewReader("network:\n  allow: [a.com:443]"))
	req.Host = "localhost"
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("put: %v %v", resp, err)
	}
	// An ended session's policy must not be restored.
	sess := store.Session{ID: "old", Agent: "hermes"}
	_ = st.CreateSession(ctx, sess, store.HashToken("t"))
	_, _ = st.PutPolicy(ctx, "session:old", []byte(`{"network":{"allow":["z.com:443"]}}`), "t")
	_, _ = st.EndSession(ctx, "old", time.Time{})
	ts.Close()
	_ = al.Close(ctx)
	_ = st.Close()

	srv2, eng2, st2, al2 := open()
	defer st2.Close()
	defer al2.Close(ctx)
	if err := srv2.LoadState(ctx); err != nil {
		t.Fatal(err)
	}
	if !eng2.EvaluateNetwork(policy.Subject{}, "a.com", 443).Allowed() {
		t.Fatal("global policy not restored after restart")
	}
	if eng2.EvaluateNetwork(policy.Subject{Agent: "hermes", Session: "old"}, "z.com", 443).Allowed() {
		t.Fatal("ended session policy must not be restored")
	}
}

func TestEventStreamLiveAndResume(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	e.flush()

	open := func(lastID string) (*bufio.Reader, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "GET", e.ts.URL+"/v1/events/stream?kind=network", nil)
		req.Host = "localhost"
		req.Header.Set("Authorization", "Bearer "+adminToken)
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			t.Fatalf("stream = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		return bufio.NewReader(resp.Body), func() { cancel(); resp.Body.Close() }
	}
	readEvent := func(r *bufio.Reader) store.Event {
		t.Helper()
		type result struct {
			ev  store.Event
			err error
		}
		ch := make(chan result, 1)
		go func() {
			var data string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					ch <- result{err: err}
					return
				}
				line = strings.TrimRight(line, "\r\n")
				if strings.HasPrefix(line, "data: ") {
					data = strings.TrimPrefix(line, "data: ")
				}
				if line == "" && data != "" {
					var ev store.Event
					ch <- result{ev: ev, err: json.Unmarshal([]byte(data), &ev)}
					return
				}
			}
		}()
		select {
		case res := <-ch:
			if res.err != nil {
				t.Fatal(res.err)
			}
			return res.ev
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for SSE event")
			return store.Event{}
		}
	}

	r, closeStream := open("")
	e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "live.com", "port": 443}, nil)
	first := readEvent(r)
	if first.Destination != "live.com:443" || first.Kind != "network" || first.ID == 0 {
		t.Fatalf("live event = %+v", first)
	}
	closeStream()

	// Events that happen while disconnected are replayed from Last-Event-ID.
	e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "missed.com", "port": 443}, nil)
	e.flush()
	r2, closeStream2 := open(strconv.FormatInt(first.ID, 10))
	defer closeStream2()
	if got := readEvent(r2); got.Destination != "missed.com:443" {
		t.Fatalf("resume replay = %+v", got)
	}
}
