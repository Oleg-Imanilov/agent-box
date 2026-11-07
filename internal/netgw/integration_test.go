package netgw_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/controller"
	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/netgw"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

const adminToken = "0123456789abcdef0123456789abcdef-admin"

type stack struct {
	t     *testing.T
	st    *store.Store
	ctlTS *httptest.Server
	token string
	sid   string
}

func newStack(t *testing.T) *stack {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	al := audit.NewLogger(st, audit.Options{FlushInterval: 5 * time.Millisecond})
	srv, err := controller.New(controller.Config{AdminToken: adminToken, AllowedHosts: []string{"localhost", "127.0.0.1"}}, st, policy.NewEngine(), al)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close(); _ = al.Close(ctx); _ = st.Close() })
	s := &stack{t: t, st: st, ctlTS: ts}
	var created struct {
		Session store.Session `json:"session"`
		Token   string        `json:"gateway_token"`
	}
	s.admin("POST", "/v1/sessions", `{"agent":"hermes"}`, &created)
	s.token, s.sid = created.Token, created.Session.ID
	return s
}

func (s *stack) admin(method, path, body string, out any) int {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.ctlTS.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			s.t.Fatalf("decode %s: %v", b, err)
		}
	}
	return resp.StatusCode
}

func (s *stack) client() *gwclient.Client {
	c, err := gwclient.New(s.ctlTS.URL, s.token, gwclient.Options{})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

func (s *stack) waitPending() store.Approval {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var out struct{ Approvals []store.Approval }
		s.admin("GET", "/v1/approvals", "", &out)
		if len(out.Approvals) > 0 {
			return out.Approvals[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.t.Fatal("no pending approval appeared")
	return store.Approval{}
}

func (s *stack) decide(requestID, decision string) {
	s.t.Helper()
	body, _ := json.Marshal(map[string]string{"request_id": requestID, "decision": decision})
	if code := s.admin("POST", "/v1/approvals/decide", string(body), nil); code != 200 {
		s.t.Fatalf("decide = %d", code)
	}
}

func echoServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

// connect performs CONNECT through the proxy and returns the status line.
func connect(t *testing.T, proxyURL, target string) (string, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyURL, "http://"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	return strings.TrimSpace(status), c, br
}

func startGateway(t *testing.T, s *stack, approvals bool) string {
	t.Helper()
	gw, err := netgw.New(netgw.Config{Controller: s.client(), Approvals: approvals, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close(); gw.Wait() })
	return ts.URL
}

func TestApprovalHoldsConnectUntilDecided(t *testing.T) {
	s := newStack(t)
	host, port := echoServer(t)
	target := fmt.Sprintf("%s:%d", host, port)
	proxy := startGateway(t, s, true)

	type result struct {
		status string
		conn   net.Conn
		br     *bufio.Reader
	}
	done := make(chan result, 1)
	go func() {
		st, c, br := connect(t, proxy, target)
		done <- result{st, c, br}
	}()
	p := s.waitPending()
	if p.Kind != "network" || p.Subject != target || p.SessionID != s.sid {
		t.Fatalf("pending = %+v", p)
	}
	select {
	case r := <-done:
		t.Fatalf("CONNECT returned before a decision: %s", r.status)
	case <-time.After(200 * time.Millisecond):
	}
	s.decide(p.RequestID, "persist") // allow 127.0.0.1:port for this agent from now on

	r := <-done
	if !strings.Contains(r.status, "200") {
		t.Fatalf("after approval status = %q", r.status)
	}
	fmt.Fprint(r.conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r.br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel echo = %q %v", buf, err)
	}

	// The persisted rule applies immediately: no new approval is needed.
	st, c, _ := connect(t, proxy, target)
	if !strings.Contains(st, "200") {
		t.Fatalf("second CONNECT = %q", st)
	}
	c.Close()
	var pending struct{ Approvals []store.Approval }
	s.admin("GET", "/v1/approvals", "", &pending)
	if len(pending.Approvals) != 0 {
		t.Fatalf("unexpected pending approvals: %+v", pending.Approvals)
	}
}

func TestApprovalDenyReturns403WithRule(t *testing.T) {
	s := newStack(t)
	host, port := echoServer(t)
	target := fmt.Sprintf("%s:%d", host, port)
	proxy := startGateway(t, s, true)

	done := make(chan string, 1)
	go func() { st, _, _ := connect(t, proxy, target); done <- st }()
	p := s.waitPending()
	s.decide(p.RequestID, "deny")
	if st := <-done; !strings.Contains(st, "403") {
		t.Fatalf("status = %q", st)
	}
}

func TestWithoutApprovalsDefaultDenyIsImmediate(t *testing.T) {
	s := newStack(t)
	host, port := echoServer(t)
	proxy := startGateway(t, s, false)
	start := time.Now()
	st, _, _ := connect(t, proxy, fmt.Sprintf("%s:%d", host, port))
	if !strings.Contains(st, "403") || time.Since(start) > 2*time.Second {
		t.Fatalf("status = %q after %v", st, time.Since(start))
	}
	var pending struct{ Approvals []store.Approval }
	s.admin("GET", "/v1/approvals", "", &pending)
	if len(pending.Approvals) != 0 {
		t.Fatal("approvals must not be requested when the gateway is not configured for them")
	}
}

func TestRealPolicyAllowsLoopbackOnlyWhenExplicit(t *testing.T) {
	s := newStack(t)
	host, port := echoServer(t)
	proxy := startGateway(t, s, false)
	target := fmt.Sprintf("%s:%d", host, port)
	put := func(doc string) {
		t.Helper()
		if code := s.admin("PUT", "/v1/policies/global", doc, nil); code != 200 {
			t.Fatalf("PUT policy = %d", code)
		}
	}
	// A rule for a different name does not open a loopback literal.
	put(fmt.Sprintf("network:\n  allow: ['localhost:%d']", port))
	if st, _, _ := connect(t, proxy, target); !strings.Contains(st, "403") {
		t.Fatalf("rule for another host must not allow 127.0.0.1; got %q", st)
	}
	// An explicit rule for the IP does.
	put(fmt.Sprintf("network:\n  allow: ['127.0.0.1:%d']", port))
	if st, _, _ := connect(t, proxy, target); !strings.Contains(st, "200") {
		t.Fatalf("explicit IP rule must allow; got %q", st)
	}
	// Live revocation applies to the next connection.
	put("network:\n  deny: ['127.0.0.1:*']")
	if st, _, _ := connect(t, proxy, target); !strings.Contains(st, "403") {
		t.Fatalf("revocation not applied; got %q", st)
	}
}
