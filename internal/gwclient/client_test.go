package gwclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/controller"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

const adminToken = "0123456789abcdef0123456789abcdef-admin"

// realController starts a real controller and returns its URL and a session token.
func realController(t *testing.T, cacheTTL time.Duration) (url, token string, putPolicy func(scope, doc string)) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	al := audit.NewLogger(st, audit.Options{FlushInterval: 5 * time.Millisecond})
	srv, err := controller.New(controller.Config{
		AdminToken: adminToken, AllowCacheTTL: cacheTTL, AllowedHosts: []string{"localhost", "127.0.0.1"},
	}, st, policy.NewEngine(), al)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close(); _ = al.Close(ctx); _ = st.Close() })

	admin := func(method, path, body string) []byte {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 300 {
			t.Fatalf("%s %s = %d %s", method, path, resp.StatusCode, b)
		}
		return b
	}
	out := admin("POST", "/v1/sessions", `{"agent":"hermes"}`)
	var created struct {
		Token string `json:"gateway_token"`
	}
	if err := json.Unmarshal(out, &created); err != nil {
		t.Fatal(err)
	}
	return ts.URL, created.Token, func(scope, doc string) { admin("PUT", "/v1/policies/"+scope, doc) }
}

func TestDecideAgainstRealController(t *testing.T) {
	url, tok, put := realController(t, 0)
	c, err := New(url, tok, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if d := c.DecideNetwork(ctx, "a.com", 443); d.Allowed() || d.RuleID != policy.RuleDefaultDeny || d.Err != nil {
		t.Fatalf("no policy: %+v", d)
	}
	put("global", "network:\n  allow: [a.com:443]\nmcp:\n  gh:\n    allow_tools: [ok]")
	if d := c.DecideNetwork(ctx, "a.com", 443); !d.Allowed() || d.RuleID != "global#network.allow[0]" {
		t.Fatalf("allow: %+v", d)
	}
	if d := c.DecideMCP(ctx, "gh", "ok"); !d.Allowed() {
		t.Fatalf("mcp allow: %+v", d)
	}
	if d := c.DecideMCP(ctx, "gh", "nope"); d.Allowed() {
		t.Fatalf("mcp deny: %+v", d)
	}
	if err := c.ReportEvent(ctx, Event{Kind: "dns", Destination: "a.com", Decision: "allow"}); err != nil {
		t.Fatalf("ReportEvent: %v", err)
	}
	if err := c.ReportEvent(ctx, Event{Kind: "bogus", Decision: "allow"}); err == nil {
		t.Fatal("rejected event must return an error")
	}
}

func TestFailsClosedOnEveryFailureMode(t *testing.T) {
	good := `{"effect":"allow","rule_id":"r","policy_version":"v","cache_ttl_seconds":0}`
	cases := map[string]http.HandlerFunc{
		"500":            func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) },
		"401":            func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) },
		"redirect":       func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://evil.example/", 302) },
		"malformed":      func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{not json")) },
		"empty":          func(w http.ResponseWriter, r *http.Request) {},
		"unknown effect": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"effect":"maybe"}`)) },
		"missing effect": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"rule_id":"x"}`)) },
		"capitalized":    func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"effect":"ALLOW"}`)) },
		"slow": func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write([]byte(good))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(h)
			defer ts.Close()
			c, _ := New(ts.URL, "tok", Options{Timeout: 100 * time.Millisecond})
			d := c.DecideNetwork(context.Background(), "a.com", 443)
			if d.Allowed() || d.Err == nil {
				t.Fatalf("must deny with error: %+v", d)
			}
		})
	}
	t.Run("connection refused", func(t *testing.T) {
		ts := httptest.NewServer(http.NotFoundHandler())
		url := ts.URL
		ts.Close()
		c, _ := New(url, "tok", Options{Timeout: 200 * time.Millisecond})
		if d := c.DecideMCP(context.Background(), "s", "t"); d.Allowed() || d.RuleID != RuleControllerUnavailable {
			t.Fatalf("got %+v", d)
		}
		if err := c.ReportEvent(context.Background(), Event{Kind: "dns", Decision: "allow"}); err == nil {
			t.Fatal("ReportEvent must fail when controller is down")
		}
	})
	t.Run("context cancelled", func(t *testing.T) {
		ts := httptest.NewServer(cases["slow"])
		defer ts.Close()
		c, _ := New(ts.URL, "tok", Options{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if d := c.DecideNetwork(ctx, "a.com", 443); d.Allowed() {
			t.Fatalf("got %+v", d)
		}
	})
}

func TestAllowCacheHonorsServerTTLOnly(t *testing.T) {
	var calls atomic.Int32
	ttl := 2
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"effect": "allow", "rule_id": "r", "policy_version": "v", "cache_ttl_seconds": ttl})
	}))
	defer ts.Close()

	now := time.Now()
	c, _ := New(ts.URL, "tok", Options{Now: func() time.Time { return now }})
	ctx := context.Background()
	if d := c.DecideNetwork(ctx, "a.com", 443); !d.Allowed() || d.Cached {
		t.Fatalf("first: %+v", d)
	}
	if d := c.DecideNetwork(ctx, "a.com", 443); !d.Allowed() || !d.Cached || calls.Load() != 1 {
		t.Fatalf("second should be cached: %+v calls=%d", d, calls.Load())
	}
	if d := c.DecideNetwork(ctx, "b.com", 443); d.Cached {
		t.Fatal("different destination must not hit cache")
	}
	if d := c.DecideNetwork(ctx, "a.com", 80); d.Cached {
		t.Fatal("different port must not hit cache")
	}
	now = now.Add(3 * time.Second) // past TTL
	if d := c.DecideNetwork(ctx, "a.com", 443); d.Cached || calls.Load() != 4 {
		t.Fatalf("expired entry must be refetched: %+v calls=%d", d, calls.Load())
	}

	// Once the TTL has passed and the controller is gone, there is no stale allow.
	ts.Close()
	now = now.Add(time.Hour)
	if d := c.DecideNetwork(ctx, "a.com", 443); d.Allowed() {
		t.Fatalf("stale allow served after TTL: %+v", d)
	}
}

func TestDenyIsNeverCached(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"effect":"deny","rule_id":"r","policy_version":"v","cache_ttl_seconds":60}`))
	}))
	defer ts.Close()
	c, _ := New(ts.URL, "tok", Options{})
	c.DecideNetwork(context.Background(), "a.com", 443)
	c.DecideNetwork(context.Background(), "a.com", 443)
	if calls.Load() != 2 {
		t.Fatalf("deny decisions must always be re-evaluated, calls=%d", calls.Load())
	}
}

func TestNewValidation(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "http://", "not a url", "controller:8080"} {
		if _, err := New(u, "tok", Options{}); err == nil {
			t.Errorf("New(%q) should fail", u)
		}
	}
	if _, err := New("http://controller:8080", "", Options{}); err == nil {
		t.Error("empty token should fail")
	}
}
