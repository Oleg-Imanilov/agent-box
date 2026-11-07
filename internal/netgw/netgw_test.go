package netgw

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
)

type fakeCtl struct {
	mu        sync.Mutex
	allow     func(host string, port int) bool
	decisions []string
	asks      []string // request ids used with ask
	events    []gwclient.Event
	down      bool
}

func (f *fakeCtl) decision(host string, port int) gwclient.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisions = append(f.decisions, fmt.Sprintf("%s:%d", host, port))
	if f.down {
		return gwclient.Decision{
			Decision: policy.Decision{Effect: policy.Deny, RuleID: gwclient.RuleControllerUnavailable},
			Err:      errors.New("controller down"),
		}
	}
	if f.allow != nil && f.allow(host, port) {
		return gwclient.Decision{Decision: policy.Decision{Effect: policy.Allow, RuleID: "test#allow", PolicyVersion: "v1"}}
	}
	return gwclient.Decision{Decision: policy.Decision{Effect: policy.Deny, RuleID: policy.RuleDefaultDeny, PolicyVersion: "v1"}}
}

func (f *fakeCtl) DecideNetwork(_ context.Context, host string, port int) gwclient.Decision {
	return f.decision(host, port)
}

func (f *fakeCtl) DecideNetworkAsk(_ context.Context, host string, port int, id string) gwclient.Decision {
	f.mu.Lock()
	f.asks = append(f.asks, id)
	f.mu.Unlock()
	return f.decision(host, port)
}

func (f *fakeCtl) ReportEvent(_ context.Context, e gwclient.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeCtl) eventOps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, e.Operation)
	}
	return out
}

func (f *fakeCtl) decided() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.decisions...)
}

type fakeResolver struct {
	mu    sync.Mutex
	hosts map[string][]netip.Addr
	calls int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if ips, ok := r.hosts[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

func (r *fakeResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func ips(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, v := range s {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

func allowAll(string, int) bool { return true }

func TestClassify(t *testing.T) {
	tests := map[string]string{
		"8.8.8.8": "", "1.1.1.1": "", "93.184.216.34": "", "2606:4700:4700::1111": "",
		"127.0.0.1": "loopback", "::1": "loopback", "127.255.255.254": "loopback",
		"10.0.0.1": "private", "172.16.5.4": "private", "172.31.255.255": "private", "192.168.1.1": "private", "fd00::1": "private",
		"169.254.169.254": "link-local", "fe80::1": "link-local",
		"0.0.0.0": "unspecified", "::": "unspecified",
		"224.0.0.1": "multicast", "ff02::1": "multicast",
		"100.64.0.1": "reserved", "198.18.0.1": "reserved", "240.0.0.1": "reserved", "255.255.255.255": "reserved",
		"0.1.2.3": "reserved", "64:ff9b::7f00:1": "reserved", "2002:7f00:1::1": "reserved", "2001:db8::1": "reserved",
		"::ffff:127.0.0.1": "loopback", "::ffff:10.1.2.3": "private", "::ffff:8.8.8.8": "",
		"172.15.0.1": "", "172.32.0.1": "",
	}
	for in, want := range tests {
		if got := Classify(netip.MustParseAddr(in)); got != want {
			t.Errorf("Classify(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanHost(t *testing.T) {
	good := map[string]string{
		"Example.COM": "example.com", "example.com.": "example.com", "a-b_c.example.com": "a-b_c.example.com",
		"8.8.8.8": "8.8.8.8", "[::1]": "::1", "::ffff:8.8.8.8": "8.8.8.8", "2606:4700::1111": "2606:4700::1111",
	}
	for in, want := range good {
		got, _, err := cleanHost(in)
		if err != nil || got != want {
			t.Errorf("cleanHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", " ", "127.1", "2130706433", "0x7f.0.0.1", "0x7f000001", "1.2.3", "1.2.3.4.5", "017700000001",
		"a b.com", "a..com", ".com", "exa$mple.com", "fe80::1%eth0", "bücher.de", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com",
		"example.com/path", "user@example.com", "example.com:80",
	}
	for _, in := range bad {
		if got, _, err := cleanHost(in); err == nil {
			t.Errorf("cleanHost(%q) = %q, want error", in, got)
		}
	}
}

// dialRecorder is a DialFunc that records addresses and returns a pipe.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
	err   error
}

func (d *dialRecorder) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addrs = append(d.addrs, address)
	if d.err != nil {
		return nil, d.err
	}
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	return a, nil
}

func (d *dialRecorder) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

func newGW(t *testing.T, ctl *fakeCtl, res *fakeResolver, dial DialFunc, mod func(*Config)) *Gateway {
	t.Helper()
	cfg := Config{Controller: ctl, Resolver: res, DialContext: dial, IdleTimeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Wait)
	return g
}

func asDenied(t *testing.T, err error) *DeniedError {
	t.Helper()
	var d *DeniedError
	if !errors.As(err, &d) {
		t.Fatalf("want *DeniedError, got %T %v", err, err)
	}
	return d
}

func TestDialPinsValidatedIP(t *testing.T) {
	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "api.example.com" && p == 443 }}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"api.example.com": ips("93.184.216.34")}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)

	c, err := g.Dial(context.Background(), "API.Example.com.", 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := rec.dialed(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v, want the pinned IP only (never the name)", got)
	}
	if d := ctl.decided(); len(d) != 1 || d[0] != "api.example.com:443" {
		t.Fatalf("decisions = %v (public address needs no extra decision)", d)
	}
}

func TestDialDeniedByPolicyDoesNotResolveOrDial(t *testing.T) {
	ctl := &fakeCtl{}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"evil.com": ips("93.184.216.34")}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)
	_, err := g.Dial(context.Background(), "evil.com", 443)
	d := asDenied(t, err)
	if d.Decision.RuleID != policy.RuleDefaultDeny {
		t.Fatalf("rule = %q", d.Decision.RuleID)
	}
	if res.count() != 0 || len(rec.dialed()) != 0 {
		t.Fatalf("denied request must not resolve (%d) or dial (%v)", res.count(), rec.dialed())
	}
}

func TestDialFailsClosedWhenControllerDown(t *testing.T) {
	ctl := &fakeCtl{down: true}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"a.com": ips("93.184.216.34")}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)
	_, err := g.Dial(context.Background(), "a.com", 443)
	d := asDenied(t, err)
	if !strings.Contains(d.Reason, "unavailable") || len(rec.dialed()) != 0 {
		t.Fatalf("got %v dialed=%v", d, rec.dialed())
	}
}

func TestDialRebindingToInternalAddressIsBlocked(t *testing.T) {
	// Policy allows the NAME; DNS points it at internal addresses.
	for _, internal := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.10", "169.254.169.254", "::1", "fd00::5", "100.64.1.1", "::ffff:127.0.0.1"} {
		t.Run(internal, func(t *testing.T) {
			ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "rebind.example.com" }}
			res := &fakeResolver{hosts: map[string][]netip.Addr{"rebind.example.com": ips(internal)}}
			rec := &dialRecorder{}
			g := newGW(t, ctl, res, rec.dial, nil)
			_, err := g.Dial(context.Background(), "rebind.example.com", 443)
			d := asDenied(t, err)
			if len(rec.dialed()) != 0 {
				t.Fatalf("connected to %v", rec.dialed())
			}
			if d.Decision.RuleID == "" {
				t.Fatal("missing rule id")
			}
			g.Wait()
			if ops := ctl.eventOps(); len(ops) != 1 || ops[0] != "dns.blocked-address" {
				t.Fatalf("events = %v", ops)
			}
		})
	}
}

func TestDialInternalAddressNeedsExplicitIPRule(t *testing.T) {
	ctl := &fakeCtl{allow: func(h string, p int) bool {
		return h == "ollama.internal" || (h == "10.0.0.5" && p == 11434)
	}}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"ollama.internal": ips("10.0.0.5")}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)

	if c, err := g.Dial(context.Background(), "ollama.internal", 11434); err != nil {
		t.Fatalf("explicitly allowed internal host: %v", err)
	} else {
		c.Close()
	}
	if got := rec.dialed(); len(got) != 1 || got[0] != "10.0.0.5:11434" {
		t.Fatalf("dialed %v", got)
	}
	if d := ctl.decided(); len(d) != 2 || d[1] != "10.0.0.5:11434" {
		t.Fatalf("decisions = %v (the IP must be decided separately)", d)
	}
	// Same name on a port for which the IP isn't allowed is refused.
	ctl.allow = func(h string, p int) bool { return h == "ollama.internal" }
	_, err := g.Dial(context.Background(), "ollama.internal", 22)
	asDenied(t, err)
}

func TestDialMixedAnswersOnlyUsePermittedAddresses(t *testing.T) {
	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "mixed.example.com" }}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"mixed.example.com": ips("127.0.0.1", "93.184.216.34", "10.0.0.1", "93.184.216.34")}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)
	c, err := g.Dial(context.Background(), "mixed.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := rec.dialed(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v; restricted addresses must never be tried", got)
	}
	g.Wait()
	if ops := ctl.eventOps(); len(ops) != 1 || ops[0] != "dns.blocked-address" {
		t.Fatalf("events = %v", ops)
	}
}

func TestDialFallsBackToNextAddress(t *testing.T) {
	ctl := &fakeCtl{allow: allowAll}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"multi.example.com": ips("93.184.216.1", "93.184.216.2")}}
	var calls []string
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		calls = append(calls, addr)
		if strings.HasPrefix(addr, "93.184.216.1:") {
			return nil, errors.New("refused")
		}
		a, b := net.Pipe()
		go b.Close()
		return a, nil
	}
	g := newGW(t, ctl, res, dial, nil)
	c, err := g.Dial(context.Background(), "multi.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if strings.Join(calls, ",") != "93.184.216.1:443,93.184.216.2:443" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestDialBadHostsAreRejectedBeforeAnything(t *testing.T) {
	ctl := &fakeCtl{allow: allowAll}
	res := &fakeResolver{hosts: map[string][]netip.Addr{}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)
	for _, h := range []string{"127.1", "2130706433", "0x7f.1", "a b", "", "fe80::1%lo"} {
		_, err := g.Dial(context.Background(), h, 80)
		if d := asDenied(t, err); d.Decision.RuleID != RuleBadHost {
			t.Errorf("%q: rule = %q", h, d.Decision.RuleID)
		}
	}
	for _, p := range []int{0, -1, 65536} {
		if _, err := g.Dial(context.Background(), "a.com", p); err == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	if len(ctl.decided()) != 0 || res.count() != 0 || len(rec.dialed()) != 0 {
		t.Fatal("malformed destinations must not reach the controller, resolver or network")
	}
}

func TestDialIPLiteralUsesSingleDecision(t *testing.T) {
	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "10.9.8.7" || h == "93.184.216.34" }}
	res := &fakeResolver{}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, nil)
	for _, lit := range []string{"10.9.8.7", "93.184.216.34", "[::ffff:10.9.8.7]"} {
		c, err := g.Dial(context.Background(), lit, 8080)
		if err != nil {
			t.Fatalf("%s: %v", lit, err)
		}
		c.Close()
	}
	if res.count() != 0 {
		t.Fatal("IP literals must not be resolved")
	}
	if _, err := g.Dial(context.Background(), "127.0.0.1", 80); err == nil {
		t.Fatal("loopback literal without an explicit rule must be denied")
	}
}

func TestApprovalsUseAskWithUniqueRequestIDs(t *testing.T) {
	ctl := &fakeCtl{allow: allowAll}
	res := &fakeResolver{hosts: map[string][]netip.Addr{"a.example.com": ips("93.184.216.34")}}
	rec := &dialRecorder{}
	g := newGW(t, ctl, res, rec.dial, func(c *Config) { c.Approvals = true })
	for i := 0; i < 2; i++ {
		c, err := g.Dial(context.Background(), "a.example.com", 443)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if len(ctl.asks) != 2 || ctl.asks[0] == ctl.asks[1] || len(ctl.asks[0]) < 16 {
		t.Fatalf("asks = %v", ctl.asks)
	}
}

// Integration tests through the HTTP handler with real sockets.

func startEcho(t *testing.T) string {
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
	return ln.Addr().String()
}

func startGWServer(t *testing.T, g *Gateway) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(g.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close() })
	return ts
}

func rawConnect(t *testing.T, proxy, target string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy, "http://"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return c, br, strings.TrimSpace(status)
}

func TestConnectTunnelsAndReports(t *testing.T) {
	echo := startEcho(t)
	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "127.0.0.1" }}
	g := newGW(t, ctl, &fakeResolver{}, nil, nil) // real dialer: exercises the socket-level guard
	ts := startGWServer(t, g)

	c, br, status := rawConnect(t, ts.URL, echo)
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q", status)
	}
	for { // consume the rest of the response head
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	fmt.Fprint(c, "hello through the tunnel")
	buf := make([]byte, len("hello through the tunnel"))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello through the tunnel" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ops := ctl.eventOps(); len(ops) == 1 && ops[0] == "connect.closed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	if len(ctl.events) != 1 || ctl.events[0].Operation != "connect.closed" {
		t.Fatalf("events = %+v", ctl.events)
	}
	if up := ctl.events[0].Metadata["bytes_up"]; up != int64(24) {
		t.Fatalf("bytes_up = %v (%T)", up, up)
	}
}

func TestConnectDenied(t *testing.T) {
	ctl := &fakeCtl{}
	g := newGW(t, ctl, &fakeResolver{}, nil, nil)
	ts := startGWServer(t, g)
	_, br, status := rawConnect(t, ts.URL, "example.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q", status)
	}
	var rule string
	for {
		line, _ := br.ReadString('\n')
		if strings.HasPrefix(strings.ToLower(line), "x-agentbox-rule:") {
			rule = strings.TrimSpace(line[len("x-agentbox-rule:"):])
		}
		if line == "\r\n" || line == "" {
			break
		}
	}
	if rule != policy.RuleDefaultDeny {
		t.Fatalf("rule header = %q", rule)
	}
}

func TestConnectMalformed(t *testing.T) {
	g := newGW(t, &fakeCtl{allow: allowAll}, &fakeResolver{}, nil, nil)
	ts := startGWServer(t, g)
	for _, target := range []string{"example.com", "example.com:abc", "127.1:80"} {
		_, _, status := rawConnect(t, ts.URL, target)
		if !strings.Contains(status, "400") && !strings.Contains(status, "403") {
			t.Errorf("CONNECT %s status = %q, want 400/403", target, status)
		}
	}
}

func TestConnectLimits(t *testing.T) {
	echo := startEcho(t)
	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "127.0.0.1" }}
	g := newGW(t, ctl, &fakeResolver{}, nil, func(c *Config) { c.MaxConns = 1; c.IdleTimeout = 300 * time.Millisecond })
	ts := startGWServer(t, g)

	c1, br1, status := rawConnect(t, ts.URL, echo)
	if !strings.Contains(status, "200") {
		t.Fatalf("first = %q", status)
	}
	_ = br1
	_, _, status2 := rawConnect(t, ts.URL, echo)
	if !strings.Contains(status2, "503") {
		t.Fatalf("second tunnel above MaxConns = %q, want 503", status2)
	}
	// An idle tunnel is closed by the gateway.
	_ = c1.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 16)
	start := time.Now()
	for {
		if _, err := c1.Read(buf); err != nil {
			break
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("idle tunnel was not closed")
	}
}

func proxyClient(proxyURL string) *http.Client {
	u, err := url.Parse(proxyURL)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestForwardProxyHTTP(t *testing.T) {
	var seen http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		fmt.Fprintf(w, "origin saw %s %s", r.Method, r.URL.RequestURI())
	}))
	defer origin.Close()
	originHost := strings.TrimPrefix(origin.URL, "http://")

	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "127.0.0.1" }}
	g := newGW(t, ctl, &fakeResolver{}, nil, nil)
	ts := startGWServer(t, g)

	req, _ := http.NewRequest("GET", "http://"+originHost+"/path?q=1", nil)
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := proxyClient(ts.URL).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "origin saw GET /path?q=1" {
		t.Fatalf("resp = %d %q", resp.StatusCode, body)
	}
	if seen.Get("Proxy-Authorization") != "" || seen.Get("Proxy-Connection") != "" || seen.Get("X-Forwarded-For") != "" {
		t.Fatalf("proxy headers leaked upstream: %v", seen)
	}

	// Denied destination.
	ctl.mu.Lock()
	ctl.allow = nil
	ctl.mu.Unlock()
	resp, err = proxyClient(ts.URL).Get("http://" + originHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || resp.Header.Get("X-AgentBox-Decision") != "deny" {
		t.Fatalf("denied status = %d %v", resp.StatusCode, resp.Header)
	}
}

func TestForwardProxyRejectsHTTPSAbsoluteURI(t *testing.T) {
	g := newGW(t, &fakeCtl{allow: allowAll}, &fakeResolver{}, nil, nil)
	ts := startGWServer(t, g)
	c, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Fatalf("status = %q", line)
	}
}

func TestHealthAndUnknownPaths(t *testing.T) {
	g := newGW(t, &fakeCtl{}, &fakeResolver{}, nil, nil)
	ts := startGWServer(t, g)
	if resp, _ := http.Get(ts.URL + "/healthz"); resp.StatusCode != 200 {
		t.Fatal("healthz")
	}
	if resp, _ := http.Get(ts.URL + "/nope"); resp.StatusCode != 404 {
		t.Fatal("unknown path must 404")
	}
	if resp, _ := http.Get(ts.URL + "/llm/unknown/v1/x"); resp.StatusCode != 404 {
		t.Fatal("unknown provider must 404")
	}
}

func TestLLMRouteInjectsCredentials(t *testing.T) {
	var got struct {
		sync.Mutex
		hdr  http.Header
		path string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Lock()
		got.hdr, got.path = r.Header.Clone(), r.URL.RequestURI()
		got.Unlock()
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("sk-REAL-secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctl := &fakeCtl{allow: func(h string, p int) bool { return h == "127.0.0.1" }}
	g := newGW(t, ctl, &fakeResolver{}, nil, func(c *Config) {
		c.Providers = []Provider{
			{Name: "openai", Upstream: upstream.URL + "/base", KeyFile: keyFile, Headers: map[string]string{"X-Static": "yes"}},
			{Name: "anthropic", Upstream: upstream.URL, Header: "x-api-key", KeyFile: keyFile},
			{Name: "ollama", Upstream: upstream.URL, NoAuth: true},
		}
	})
	ts := startGWServer(t, g)

	do := func(path string, hdr map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(`{"model":"x"}`))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}

	resp, body := do("/llm/openai/v1/chat/completions?stream=false", map[string]string{
		"Authorization": "Bearer dummy-agent-key", "Cookie": "session=abc", "X-Api-Key": "agent-key",
	})
	if resp.StatusCode != 200 || body != `{"ok":true}` {
		t.Fatalf("resp = %d %q", resp.StatusCode, body)
	}
	got.Lock()
	if h := got.hdr.Get("Authorization"); h != "Bearer sk-REAL-secret-key" {
		t.Fatalf("Authorization = %q", h)
	}
	if got.hdr.Get("Cookie") != "" || got.hdr.Get("X-Api-Key") != "" || got.hdr.Get("X-Static") != "yes" {
		t.Fatalf("headers = %v", got.hdr)
	}
	if got.path != "/base/v1/chat/completions?stream=false" {
		t.Fatalf("upstream path = %q", got.path)
	}
	got.Unlock()

	do("/llm/anthropic/v1/messages", map[string]string{"x-api-key": "dummy", "Authorization": "Bearer dummy"})
	got.Lock()
	if got.hdr.Get("X-Api-Key") != "sk-REAL-secret-key" || got.hdr.Get("Authorization") != "" {
		t.Fatalf("anthropic headers = %v", got.hdr)
	}
	got.Unlock()

	do("/llm/ollama/api/chat", map[string]string{"Authorization": "Bearer dummy"})
	got.Lock()
	if got.hdr.Get("Authorization") != "" {
		t.Fatalf("no_auth route must still strip agent credentials: %v", got.hdr)
	}
	got.Unlock()

	// The upstream destination went through policy.
	if d := ctl.decided(); len(d) == 0 || d[0] != "127.0.0.1:"+strings.Split(upstream.URL, ":")[2] {
		t.Fatalf("decisions = %v", d)
	}
}

func TestLLMRouteDeniedByPolicyAndMissingKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("upstream must not be reached") }))
	defer upstream.Close()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	_ = os.WriteFile(keyFile, []byte("k"), 0o600)
	g := newGW(t, &fakeCtl{}, &fakeResolver{}, nil, func(c *Config) {
		c.Providers = []Provider{
			{Name: "p", Upstream: upstream.URL, KeyFile: keyFile},
			{Name: "nokey", Upstream: upstream.URL, KeyFile: filepath.Join(dir, "missing")},
		}
	})
	ts := startGWServer(t, g)
	resp, _ := http.Post(ts.URL+"/llm/p/v1/x", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 403 || resp.Header.Get("X-AgentBox-Rule") != policy.RuleDefaultDeny {
		t.Fatalf("denied = %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = http.Post(ts.URL+"/llm/nokey/v1/x", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 502 {
		t.Fatalf("missing key = %d, want 502", resp.StatusCode)
	}
}

func TestLLMRouteStreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: second\n\n")
	}))
	defer upstream.Close()
	defer close(release)
	g := newGW(t, &fakeCtl{allow: allowAll}, &fakeResolver{}, nil, func(c *Config) {
		c.Providers = []Provider{{Name: "s", Upstream: upstream.URL, NoAuth: true}}
	})
	ts := startGWServer(t, g)
	resp, err := http.Post(ts.URL+"/llm/s/stream", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	done := make(chan string, 1)
	go func() { l, _ := br.ReadString('\n'); done <- l }()
	select {
	case l := <-done:
		if l != "data: first\n" {
			t.Fatalf("first chunk = %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first SSE chunk was buffered until the response ended")
	}
}

func TestBuildProvidersValidation(t *testing.T) {
	bad := []Provider{
		{Name: "", Upstream: "https://a.com", NoAuth: true},
		{Name: "UPPER", Upstream: "https://a.com", NoAuth: true},
		{Name: "a/b", Upstream: "https://a.com", NoAuth: true},
		{Name: "p", Upstream: "ftp://a.com", NoAuth: true},
		{Name: "p", Upstream: "https://user:pw@a.com", NoAuth: true},
		{Name: "p", Upstream: "https://a.com?x=1", NoAuth: true},
		{Name: "p", Upstream: "https://", NoAuth: true},
		{Name: "p", Upstream: "https://a.com"},                                     // no key, no no_auth
		{Name: "p", Upstream: "https://a.com", NoAuth: true, KeyFile: "/x"},        // both
		{Name: "p", Upstream: "https://a.com", KeyFile: "/x", Header: "X Bad"},     // header with space
		{Name: "p", Upstream: "https://a.com", KeyFile: "/x", Scheme: "a\r\nb: c"}, // header injection
		{Name: "p", Upstream: "https://a.com", NoAuth: true, Headers: map[string]string{"X": "a\r\nInjected: 1"}},
	}
	for i, p := range bad {
		if _, err := buildProviders([]Provider{p}); err == nil {
			t.Errorf("case %d (%+v) should be rejected", i, p)
		}
	}
	if _, err := buildProviders([]Provider{{Name: "p", Upstream: "https://a.com", NoAuth: true}, {Name: "p", Upstream: "https://b.com", NoAuth: true}}); err == nil {
		t.Error("duplicate names must be rejected")
	}
	ok, err := buildProviders([]Provider{{Name: "openai", Upstream: "https://api.openai.com", KeyFile: "/run/secrets/k"}})
	if err != nil || ok["openai"].Header != "Authorization" || ok["openai"].Scheme != "Bearer" {
		t.Fatalf("defaults: %+v %v", ok, err)
	}
}

func TestNewRequiresController(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("controller is required")
	}
}
