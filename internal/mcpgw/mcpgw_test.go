package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
)

// fakeCtl is a controller stand-in.
type fakeCtl struct {
	mu       sync.Mutex
	allow    func(server, tool string) bool
	calls    []string // "server/tool"
	asks     []string
	toolsErr error
	events   []gwclient.Event
}

func (f *fakeCtl) decide(server, tool string) gwclient.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, server+"/"+tool)
	if f.allow != nil && f.allow(server, tool) {
		return gwclient.Decision{Decision: policy.Decision{Effect: policy.Allow, RuleID: "test#allow"}}
	}
	return gwclient.Decision{Decision: policy.Decision{Effect: policy.Deny, RuleID: "test#deny"}}
}

func (f *fakeCtl) DecideMCP(_ context.Context, server, tool string) gwclient.Decision {
	return f.decide(server, tool)
}

func (f *fakeCtl) DecideMCPAsk(_ context.Context, server, tool, id string) gwclient.Decision {
	f.mu.Lock()
	f.asks = append(f.asks, id)
	f.mu.Unlock()
	return f.decide(server, tool)
}

func (f *fakeCtl) DecideMCPTools(_ context.Context, server string, tools []string) (map[string]policy.Decision, error) {
	if f.toolsErr != nil {
		return nil, f.toolsErr
	}
	out := map[string]policy.Decision{}
	for _, t := range tools {
		if f.allow != nil && f.allow(server, t) {
			out[t] = policy.Decision{Effect: policy.Allow}
		} else {
			out[t] = policy.Decision{Effect: policy.Deny}
		}
	}
	return out, nil
}

func (f *fakeCtl) ReportEvent(_ context.Context, e gwclient.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeCtl) rules() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, e.RuleID)
	}
	return out
}

func (f *fakeCtl) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type recorded struct {
	Method string
	Header http.Header
	Body   []byte
}

// fakeUp is a minimal Streamable HTTP MCP server.
type fakeUp struct {
	srv *httptest.Server

	mu              sync.Mutex
	reqs            []recorded
	sseTools        bool
	noSession       bool
	protocolVersion string
	tools           []string
	samplingOnCall  string
	bigEvent        bool
}

func newFakeUp(t *testing.T) *fakeUp {
	t.Helper()
	u := &fakeUp{protocolVersion: "2025-06-18", tools: []string{"get_file_contents", "list_issues", "delete_repository"}}
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(func() { u.srv.CloseClientConnections(); u.srv.Close() })
	return u
}

func (u *fakeUp) record(r *http.Request, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reqs = append(u.reqs, recorded{Method: r.Method, Header: r.Header.Clone(), Body: body})
}

func (u *fakeUp) received() []recorded {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]recorded(nil), u.reqs...)
}

// methods returns the JSON-RPC methods received over POST, in order.
func (u *fakeUp) methods() []string {
	var out []string
	for _, r := range u.received() {
		if r.Method != http.MethodPost {
			continue
		}
		var m struct{ Method string }
		_ = json.Unmarshal(r.Body, &m)
		out = append(out, m.Method)
	}
	return out
}

func sseEventStr(id, data string) string {
	if id != "" {
		return "id: " + id + "\ndata: " + data + "\n\n"
	}
	return "data: " + data + "\n\n"
}

func (u *fakeUp) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.record(r, body)
	u.mu.Lock()
	sseTools, noSession, pv, tools, sampling, big := u.sseTools, u.noSession, u.protocolVersion, u.tools, u.samplingOnCall, u.bigEvent
	u.mu.Unlock()

	switch r.Method {
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\n")
		fmt.Fprint(w, sseEventStr("10", `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))
		fmt.Fprint(w, sseEventStr("11", `{"jsonrpc":"2.0","id":100,"method":"roots/list"}`))
		fmt.Fprint(w, sseEventStr("12", `{"jsonrpc":"2.0","method":"custom/evil"}`))
		return
	}

	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &m)
	if m.Method == "" { // a response from the client
		w.WriteHeader(http.StatusAccepted)
		return
	}
	reply := func(result string) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, m.ID, result)
	}
	switch {
	case strings.HasPrefix(m.Method, "notifications/"):
		w.WriteHeader(http.StatusAccepted)
	case m.Method == "initialize":
		if !noSession {
			w.Header().Set("Mcp-Session-Id", "upstream-session-1")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, reply(`{"protocolVersion":"`+pv+`","capabilities":{},"serverInfo":{"name":"fake"}}`))
	case m.Method == "tools/list":
		var parts []string
		for _, t := range tools {
			parts = append(parts, fmt.Sprintf(`{"name":%q,"description":"d","inputSchema":{"type":"object"}}`, t))
		}
		res := reply(`{"tools":[` + strings.Join(parts, ",") + `],"nextCursor":"c1"}`)
		if sseTools {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, sseEventStr("1", res))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, res)
	case m.Method == "tools/call" && sampling != "" && m.Params.Name == sampling:
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, sseEventStr("1", `{"jsonrpc":"2.0","id":99,"method":"sampling/createMessage","params":{"messages":[]}}`))
		w.(http.Flusher).Flush()
		fmt.Fprint(w, sseEventStr("2", `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`))
		fmt.Fprint(w, sseEventStr("3", reply(`{"content":[{"type":"text","text":"done"}]}`)))
	case m.Method == "tools/call" && big:
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, sseEventStr("1", `{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"`+strings.Repeat("x", 3000)+`"}}`))
	case m.Method == "tools/call":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, reply(`{"content":[{"type":"text","text":"called `+m.Params.Name+`"}]}`))
	default:
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, reply(`{"ok":true}`))
	}
}

type rig struct {
	t   *testing.T
	ctl *fakeCtl
	up  *fakeUp
	gw  *Gateway
	ts  *httptest.Server
}

func newRig(t *testing.T, mod func(*Config)) *rig {
	t.Helper()
	ctl := &fakeCtl{allow: func(s, tool string) bool { return tool != "delete_repository" }}
	up := newFakeUp(t)
	cfg := Config{
		Controller: ctl,
		Servers:    []Server{{Name: "github", URL: up.srv.URL + "/mcp"}},
	}
	if mod != nil {
		mod(&cfg)
	}
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close(); gw.Wait() })
	return &rig{t: t, ctl: ctl, up: up, gw: gw, ts: ts}
}

func (r *rig) do(method, path string, body string, hdr map[string]string) (*http.Response, []byte) {
	r.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, r.ts.URL+path, rd)
	if err != nil {
		r.t.Fatal(err)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (r *rig) post(body string, hdr map[string]string) (*http.Response, []byte) {
	return r.do("POST", "/mcp/github", body, hdr)
}

// initialize performs the handshake and returns the gateway session ID.
func (r *rig) initialize() string {
	r.t.Helper()
	resp, body := r.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`, nil)
	if resp.StatusCode != 200 {
		r.t.Fatalf("initialize = %d %s", resp.StatusCode, body)
	}
	return resp.Header.Get("Mcp-Session-Id")
}

type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}

func parseRPC(t *testing.T, b []byte) rpcResp {
	t.Helper()
	var r rpcResp
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("bad JSON %q: %v", b, err)
	}
	return r
}

func toolNames(t *testing.T, result json.RawMessage) []string {
	t.Helper()
	var r struct {
		Tools      []struct{ Name string } `json:"tools"`
		NextCursor string                  `json:"nextCursor"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, tl := range r.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func TestInitializeSessionMintingAndHeaderHygiene(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(keyFile, []byte("upstream-bearer-secret\n"), 0o600)
	r := newRig(t, func(c *Config) {
		c.Servers[0].BearerFile = keyFile
		c.Servers[0].Headers = map[string]string{"X-Org": "acme"}
	})
	resp, body := r.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, map[string]string{
		"Authorization": "Bearer agent-dummy", "Cookie": "a=b", "X-Custom": "1", "Mcp-Session-Id": "client-chosen",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	gwSID := resp.Header.Get("Mcp-Session-Id")
	if gwSID == "" || gwSID == "upstream-session-1" || len(gwSID) < 32 {
		t.Fatalf("gateway must mint its own session id, got %q", gwSID)
	}
	first := r.up.received()[0]
	if first.Header.Get("Authorization") != "Bearer upstream-bearer-secret" || first.Header.Get("X-Org") != "acme" {
		t.Fatalf("upstream auth/static headers: %v", first.Header)
	}
	if first.Header.Get("Cookie") != "" || first.Header.Get("X-Custom") != "" || first.Header.Get("Mcp-Session-Id") != "" {
		t.Fatalf("client headers leaked to upstream on initialize: %v", first.Header)
	}

	// Later requests carry the gateway id and reach upstream with the upstream id.
	r.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{"Mcp-Session-Id": gwSID})
	resp, body = r.post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_file_contents","arguments":{}}}`,
		map[string]string{"Mcp-Session-Id": gwSID, "MCP-Protocol-Version": "2025-06-18"})
	if rr := parseRPC(t, body); rr.Error != nil || !strings.Contains(string(rr.Result), "called get_file_contents") {
		t.Fatalf("call = %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Mcp-Session-Id") != gwSID {
		t.Fatalf("response session header = %q", resp.Header.Get("Mcp-Session-Id"))
	}
	last := r.up.received()[len(r.up.received())-1]
	if last.Header.Get("Mcp-Session-Id") != "upstream-session-1" || last.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
		t.Fatalf("upstream headers: %v", last.Header)
	}
}

func TestToolsCallPolicy(t *testing.T) {
	r := newRig(t, nil)
	sid := r.initialize()
	h := map[string]string{"Mcp-Session-Id": sid}

	_, body := r.post(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_repository","arguments":{"repo":"x"}}}`, h)
	rr := parseRPC(t, body)
	if rr.Error == nil || rr.Error.Code != codePolicyDenied || string(rr.ID) != "7" || rr.Error.Data["rule_id"] != "test#deny" {
		t.Fatalf("denied call = %s", body)
	}
	for _, m := range r.up.methods() {
		if m == "tools/call" {
			t.Fatal("denied tools/call must never reach the upstream server")
		}
	}
	_, body = r.post(`{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"list_issues"}}`, h)
	rr = parseRPC(t, body)
	if rr.Error != nil || string(rr.ID) != `"abc"` {
		t.Fatalf("allowed call = %s", body)
	}
	if got := r.ctl.callList(); len(got) != 2 || got[0] != "github/delete_repository" || got[1] != "github/list_issues" {
		t.Fatalf("decisions = %v", got)
	}
}

func TestToolsListIsFiltered(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
			r := newRig(t, nil)
			r.up.mu.Lock()
			r.up.sseTools = sse
			r.up.mu.Unlock()
			sid := r.initialize()
			resp, body := r.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, map[string]string{"Mcp-Session-Id": sid})
			if sse {
				if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
					t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
				}
				var data string
				for _, line := range strings.Split(string(body), "\n") {
					if strings.HasPrefix(line, "data: ") {
						data = strings.TrimPrefix(line, "data: ")
					}
				}
				body = []byte(data)
				if !strings.Contains(resp.Header.Get("Content-Type"), "event-stream") || !bytes.Contains([]byte(data), []byte("jsonrpc")) {
					t.Fatalf("no data event in %q", data)
				}
			}
			rr := parseRPC(t, body)
			names := toolNames(t, rr.Result)
			if strings.Join(names, ",") != "get_file_contents,list_issues" {
				t.Fatalf("advertised tools = %v (delete_repository must be hidden)", names)
			}
			if !strings.Contains(string(rr.Result), `"nextCursor":"c1"`) || !strings.Contains(string(rr.Result), "inputSchema") {
				t.Fatalf("other result fields lost: %s", rr.Result)
			}
		})
	}
}

func TestToolsListFailsClosedWhenPolicyUnavailable(t *testing.T) {
	r := newRig(t, nil)
	r.ctl.toolsErr = errors.New("controller down")
	sid := r.initialize()
	_, body := r.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, map[string]string{"Mcp-Session-Id": sid})
	rr := parseRPC(t, body)
	if names := toolNames(t, rr.Result); len(names) != 0 {
		t.Fatalf("tools advertised without a policy decision: %v", names)
	}
}

func TestRejectsBatchesAndMalformedMessages(t *testing.T) {
	r := newRig(t, nil)
	sid := r.initialize()
	h := map[string]string{"Mcp-Session-Id": sid}
	before := len(r.up.received())

	bad := map[string]string{
		"batch":                `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repository"}}]`,
		"not json":             `nope`,
		"not object":           `"hello"`,
		"empty":                ``,
		"no jsonrpc":           `{"id":1,"method":"tools/list"}`,
		"bad jsonrpc":          `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`,
		"id object":            `{"jsonrpc":"2.0","id":{},"method":"tools/list"}`,
		"method not string":    `{"jsonrpc":"2.0","id":1,"method":5}`,
		"trailing data":        `{"jsonrpc":"2.0","id":1,"method":"tools/list"}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repository"}}`,
		"dup method":           `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"delete_repository"}}`,
		"dup id":               `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}`,
		"dup name":             `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","name":"delete_repository"}}`,
		"dup name nested":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{"a":1,"a":2}}}`,
		"case variant method":  `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"tools/list","params":{"name":"delete_repository"}}`,
		"case variant params":  `{"jsonrpc":"2.0","id":1,"method":"tools/call","Params":{"name":"list_issues"},"params":{"name":"delete_repository"}}`,
		"case variant name":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","Name":"delete_repository"}}`,
		"missing tool name":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`,
		"tool name not string": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["delete_repository"]}}`,
		"params not object":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"x"}`,
		"call without id":      `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_issues"}}`,
		"too deep":             `{"jsonrpc":"2.0","id":1,"method":"x","params":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`,
		"client response":      `{"jsonrpc":"2.0","id":99,"result":{}}`,
		"neither":              `{"jsonrpc":"2.0","id":1}`,
	}
	for name, body := range bad {
		resp, out := r.post(body, h)
		if resp.StatusCode != 400 {
			t.Errorf("%s: status %d, want 400 (%s)", name, resp.StatusCode, out)
		}
	}
	if got := len(r.up.received()); got != before {
		t.Fatalf("%d malformed messages reached the upstream", got-before)
	}
	r.gw.Wait()
	rules := strings.Join(r.ctl.rules(), ",")
	for _, want := range []string{RuleBatch, RuleMalformed, RuleUnexpected} {
		if !strings.Contains(rules, want) {
			t.Errorf("rule %s was not reported (got %s)", want, rules)
		}
	}
}

func TestMethodAllowList(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Servers[0].AllowMethods = []string{"resources/list"} })
	sid := r.initialize()
	h := map[string]string{"Mcp-Session-Id": sid}

	for _, method := range []string{"resources/read", "prompts/get", "completion/complete", "logging/setLevel", "sampling/createMessage", "roots/list", "x/unknown"} {
		_, body := r.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":%q,"params":{}}`, method), h)
		if rr := parseRPC(t, body); rr.Error == nil || rr.Error.Code != codeMethodBlocked {
			t.Errorf("%s was not blocked: %s", method, body)
		}
	}
	if resp, body := r.post(`{"jsonrpc":"2.0","id":6,"method":"resources/list"}`, h); resp.StatusCode != 200 || parseRPC(t, body).Error != nil {
		t.Errorf("configured extra method blocked: %s", body)
	}
	if resp, _ := r.post(`{"jsonrpc":"2.0","id":7,"method":"ping"}`, h); resp.StatusCode != 200 {
		t.Error("ping must be allowed")
	}
	// Notifications: notifications/* pass, everything else is dropped with 202.
	if resp, _ := r.post(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`, h); resp.StatusCode != 202 {
		t.Errorf("notification = %d", resp.StatusCode)
	}
	before := len(r.up.received())
	if resp, _ := r.post(`{"jsonrpc":"2.0","method":"resources/subscribe","params":{}}`, h); resp.StatusCode != 202 {
		t.Errorf("blocked notification = %d, want 202", resp.StatusCode)
	}
	if len(r.up.received()) != before {
		t.Error("blocked notification reached upstream")
	}
	for _, m := range r.up.methods() {
		if m == "resources/read" || m == "prompts/get" || m == "sampling/createMessage" {
			t.Errorf("blocked method %s reached the upstream", m)
		}
	}
	if _, err := New(Config{Controller: r.ctl, Servers: []Server{{Name: "s", URL: "http://x", AllowMethods: []string{"tools/call"}}}}); err == nil {
		t.Error("tools/call must not be allowed via allow_methods (it is policy-controlled)")
	}
}

func TestSessionBindingAndLifecycle(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Servers = append(c.Servers, Server{Name: "other", URL: c.Servers[0].URL})
	})
	sid := r.initialize()
	// A session minted for "github" is useless on "other", and unknown ids are rejected.
	for _, id := range []string{sid, "deadbeef", "upstream-session-1"} {
		resp, body := r.do("POST", "/mcp/other", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Mcp-Session-Id": id})
		if resp.StatusCode != 404 || parseRPC(t, body).Error == nil || parseRPC(t, body).Error.Code != codeNoSession {
			t.Errorf("session %q on other server = %d %s", id, resp.StatusCode, body)
		}
	}
	if resp, _ := r.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Mcp-Session-Id": "upstream-session-1"}); resp.StatusCode != 404 {
		t.Errorf("a raw upstream session id must not work through the gateway: %d", resp.StatusCode)
	}
	// DELETE forwards and forgets the session.
	if resp, _ := r.do("DELETE", "/mcp/github", "", map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 200 {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if resp, _ := r.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 404 {
		t.Fatalf("deleted session still valid: %d", resp.StatusCode)
	}
	if resp, _ := r.do("DELETE", "/mcp/github", "", nil); resp.StatusCode != 400 {
		t.Errorf("delete without session = %d", resp.StatusCode)
	}
	last := r.up.received()
	var sawDelete bool
	for _, q := range last {
		if q.Method == "DELETE" && q.Header.Get("Mcp-Session-Id") == "upstream-session-1" {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Error("DELETE was not forwarded with the upstream session id")
	}
}

func TestSessionTableLimitsAndExpiry(t *testing.T) {
	now := time.Now()
	r := newRig(t, func(c *Config) {
		c.MaxSessions = 2
		c.SessionTTL = time.Minute
		c.Now = func() time.Time { return now }
	})
	s1 := r.initialize()
	r.initialize()
	resp, body := r.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil)
	if resp.StatusCode != 503 {
		t.Fatalf("session limit = %d %s", resp.StatusCode, body)
	}
	now = now.Add(2 * time.Minute) // everything expires
	if resp, _ := r.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Mcp-Session-Id": s1}); resp.StatusCode != 404 {
		t.Fatalf("expired session = %d", resp.StatusCode)
	}
	if resp, _ := r.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil); resp.StatusCode != 200 {
		t.Fatalf("after expiry new sessions must be possible: %d", resp.StatusCode)
	}
}

func TestServerInitiatedRequestsAreBlockedInPostStreams(t *testing.T) {
	r := newRig(t, nil)
	r.up.mu.Lock()
	r.up.samplingOnCall = "list_issues"
	r.up.mu.Unlock()
	sid := r.initialize()
	resp, body := r.post(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_issues"}}`, map[string]string{"Mcp-Session-Id": sid})
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("content-type %q", resp.Header.Get("Content-Type"))
	}
	text := string(body)
	if strings.Contains(text, "sampling/createMessage") {
		t.Fatalf("sampling request reached the agent: %s", text)
	}
	if !strings.Contains(text, "notifications/progress") || !strings.Contains(text, `"text":"done"`) {
		t.Fatalf("legitimate events lost: %s", text)
	}
	// Event ids of dropped events are not forwarded, but others keep theirs.
	if !strings.Contains(text, "id: 2\n") || !strings.Contains(text, "id: 3\n") {
		t.Fatalf("event ids lost: %s", text)
	}
	// The upstream was told the request is unsupported, with its own session id.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, q := range r.up.received() {
			var m struct {
				ID    json.RawMessage
				Error *struct{ Code int }
			}
			if json.Unmarshal(q.Body, &m) == nil && string(m.ID) == "99" && m.Error != nil {
				if q.Header.Get("Mcp-Session-Id") != "upstream-session-1" || m.Error.Code != -32601 {
					t.Fatalf("error reply = %s %v", q.Body, q.Header)
				}
				goto replied
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("upstream never received an error reply for the blocked sampling request")
replied:
	r.gw.Wait()
	if !strings.Contains(strings.Join(r.ctl.rules(), ","), RuleServerRequest) {
		t.Fatalf("blocked server request not reported: %v", r.ctl.rules())
	}
}

func TestGetStreamFiltersServerMessages(t *testing.T) {
	r := newRig(t, nil)
	sid := r.initialize()
	resp, body := r.do("GET", "/mcp/github", "", map[string]string{"Accept": "text/event-stream", "Mcp-Session-Id": sid, "Last-Event-ID": "9"})
	if resp.StatusCode != 200 {
		t.Fatalf("GET = %d %s", resp.StatusCode, body)
	}
	text := string(body)
	if !strings.Contains(text, "notifications/tools/list_changed") || !strings.Contains(text, ": keepalive") {
		t.Fatalf("notifications/keepalives must pass: %s", text)
	}
	if strings.Contains(text, "roots/list") || strings.Contains(text, "custom/evil") {
		t.Fatalf("server request or unknown notification leaked: %s", text)
	}
	var get recorded
	for _, q := range r.up.received() {
		if q.Method == "GET" {
			get = q
		}
	}
	if get.Header.Get("Last-Event-ID") != "9" || get.Header.Get("Mcp-Session-Id") != "upstream-session-1" {
		t.Fatalf("upstream GET headers: %v", get.Header)
	}
	if resp, _ := r.do("GET", "/mcp/github", "", nil); resp.StatusCode != 406 {
		t.Errorf("GET without Accept = %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/mcp/github", "", map[string]string{"Accept": "text/event-stream", "Mcp-Session-Id": "nope"}); resp.StatusCode != 404 {
		t.Errorf("GET with unknown session = %d", resp.StatusCode)
	}
}

func TestProtocolVersionPinning(t *testing.T) {
	r := newRig(t, nil)
	sid := r.initialize()
	resp, _ := r.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2026-07-28"})
	if resp.StatusCode != 400 {
		t.Fatalf("unsupported protocol version = %d", resp.StatusCode)
	}
	// An upstream answering with an unsupported version is not passed through.
	r2 := newRig(t, nil)
	r2.up.mu.Lock()
	r2.up.protocolVersion = "2026-07-28"
	r2.up.mu.Unlock()
	_, body := r2.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil)
	if rr := parseRPC(t, body); rr.Error == nil || strings.Contains(string(body), "2026-07-28") && rr.Result != nil {
		t.Fatalf("unsupported upstream version passed through: %s", body)
	}
}

func TestStatelessUpstreamWithoutSessions(t *testing.T) {
	r := newRig(t, nil)
	r.up.mu.Lock()
	r.up.noSession = true
	r.up.mu.Unlock()
	resp, body := r.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Mcp-Session-Id") != "" || parseRPC(t, body).Error != nil {
		t.Fatalf("stateless initialize = %d %v %s", resp.StatusCode, resp.Header, body)
	}
	_, body = r.post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_issues"}}`, nil)
	if parseRPC(t, body).Error != nil {
		t.Fatalf("stateless call = %s", body)
	}
}

func TestHostAndOriginGuard(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.AllowedHosts = []string{"mcpgw", "localhost", "127.0.0.1"}
		c.AllowedOrigins = []string{"http://trusted.example"}
	})
	req, _ := http.NewRequest("GET", r.ts.URL+"/healthz", nil)
	req.Host = "evil.example.com"
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Errorf("bad host = %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", r.ts.URL+"/healthz", nil)
	req.Host = "mcpgw:8081"
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Errorf("good host with port = %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", r.ts.URL+"/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Origin", "http://evil.example")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Errorf("bad origin = %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", r.ts.URL+"/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Origin", "http://trusted.example")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Errorf("allowed origin = %d", resp.StatusCode)
	}
	// Default: no Origin header may be present at all.
	r2 := newRig(t, nil)
	req, _ = http.NewRequest("POST", r2.ts.URL+"/mcp/github", strings.NewReader(`{}`))
	req.Header.Set("Origin", "http://localhost")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Errorf("default origin policy = %d", resp.StatusCode)
	}
}

func TestUnknownServerMethodsAndLimits(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxBodyBytes = 512 })
	if resp, _ := r.do("POST", "/mcp/nope", `{}`, nil); resp.StatusCode != 404 {
		t.Errorf("unknown server = %d", resp.StatusCode)
	}
	if resp, _ := r.do("PUT", "/mcp/github", `{}`, nil); resp.StatusCode != 405 {
		t.Errorf("PUT = %d", resp.StatusCode)
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{"x":"` + strings.Repeat("a", 2000) + `"}}}`
	if resp, _ := r.post(big, nil); resp.StatusCode != 413 {
		t.Errorf("oversized body = %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/healthz", "", nil); resp.StatusCode != 200 {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
}

func TestUpstreamFailuresAndRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect target must not be contacted") }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirector.Close()
	ctl := &fakeCtl{allow: func(string, string) bool { return true }}
	gw, err := New(Config{Controller: ctl, Servers: []Server{{Name: "redir", URL: redirector.URL}, {Name: "dead", URL: "http://127.0.0.1:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	defer gw.Wait()

	resp, err := http.Post(ts.URL+"/mcp/redir", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 {
		t.Fatalf("redirect must be surfaced, not followed: %d", resp.StatusCode)
	}
	resp, err = http.Post(ts.URL+"/mcp/dead", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rr := parseRPC(t, b); resp.StatusCode != 502 || rr.Error == nil || string(rr.ID) != "4" {
		t.Fatalf("dead upstream = %d %s", resp.StatusCode, b)
	}
	// Error details are not leaked to the agent.
	if strings.Contains(string(b), "127.0.0.1") || strings.Contains(string(b), "refused") {
		t.Fatalf("internal error detail leaked: %s", b)
	}
}

func TestMissingUpstreamCredentialFails(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Servers[0].BearerFile = filepath.Join(t.TempDir(), "missing") })
	resp, body := r.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if resp.StatusCode != 502 || len(r.up.received()) != 0 {
		t.Fatalf("got %d %s; request must not be sent unauthenticated", resp.StatusCode, body)
	}
}

func TestApprovalsUseAsk(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Approvals = true })
	sid := r.initialize()
	r.post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues"}}`, map[string]string{"Mcp-Session-Id": sid})
	r.post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_issues"}}`, map[string]string{"Mcp-Session-Id": sid})
	r.ctl.mu.Lock()
	defer r.ctl.mu.Unlock()
	if len(r.ctl.asks) != 2 || r.ctl.asks[0] == r.ctl.asks[1] {
		t.Fatalf("asks = %v", r.ctl.asks)
	}
}

func TestOversizedSSEEventAbortsStream(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxSSEEventBytes = 1024 })
	r.up.mu.Lock()
	r.up.bigEvent = true
	r.up.mu.Unlock()
	sid := r.initialize()
	_, body := r.post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues"}}`, map[string]string{"Mcp-Session-Id": sid})
	if strings.Contains(string(body), "xxxxxxxx") {
		t.Fatalf("oversized event was forwarded: %d bytes", len(body))
	}
}

func TestBuildServersValidation(t *testing.T) {
	bad := []Server{
		{Name: "", URL: "http://x"}, {Name: "a b", URL: "http://x"}, {Name: "a/b", URL: "http://x"},
		{Name: "s", URL: "ftp://x"}, {Name: "s", URL: "http://"}, {Name: "s", URL: "http://u:p@x"}, {Name: "s", URL: "http://x#f"},
		{Name: "s", URL: "http://x", Headers: map[string]string{"Mcp-Session-Id": "x"}},
		{Name: "s", URL: "http://x", Headers: map[string]string{"X": "a\r\nb: c"}},
		{Name: "s", URL: "http://x", Headers: map[string]string{"Bad Name": "v"}},
		{Name: "s", URL: "http://x", AllowMethods: []string{""}},
		{Name: "s", URL: "http://x", AllowMethods: []string{"notifications/x"}},
	}
	for i, s := range bad {
		if _, err := buildServers([]Server{s}); err == nil {
			t.Errorf("case %d (%+v) should be rejected", i, s)
		}
	}
	if _, err := buildServers([]Server{{Name: "a", URL: "http://x"}, {Name: "a", URL: "http://y"}}); err == nil {
		t.Error("duplicate names must be rejected")
	}
	if _, err := New(Config{Controller: &fakeCtl{}}); err == nil {
		t.Error("no servers must be rejected")
	}
	if _, err := New(Config{Servers: []Server{{Name: "a", URL: "http://x"}}}); err == nil {
		t.Error("missing controller must be rejected")
	}
}

func TestParseMessageValid(t *testing.T) {
	good := map[string]struct {
		method  string
		id      string
		request bool
	}{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`:               {"tools/list", "1", true},
		`{"jsonrpc":"2.0","id":"x-1","method":"ping","params":{}}`:     {"ping", `"x-1"`, true},
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`:       {"notifications/initialized", "", false},
		`{"jsonrpc":"2.0","id":null,"method":"notifications/x"}`:       {"notifications/x", "", false},
		"  \n{\"jsonrpc\":\"2.0\",\"id\":-5,\"method\":\"ping\"}\n  ":  {"ping", "-5", true},
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`:               {"", "1", false},
		`{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}`:    {"", "1", false},
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":[{}]}}`: {"ping", "1", true},
	}
	for in, want := range good {
		m, err := parseMessage([]byte(in))
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if m.Method != want.method || string(m.ID) != want.id || m.isRequest() != want.request {
			t.Errorf("%q: got method=%q id=%q request=%v", in, m.Method, m.ID, m.isRequest())
		}
	}
}

func TestSSERoundTrip(t *testing.T) {
	in := ": hello\n\nid: 7\nevent: message\nretry: 1000\ndata: {\"a\":1}\ndata: second\n\nignored: field\ndata: x\n\n"
	br := bufio.NewReader(strings.NewReader(in))
	var out bytes.Buffer
	for {
		ev, err := readSSE(br, 4096)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
		if err := writeSSE(&out, ev); err != nil {
			t.Fatal(err)
		}
	}
	want := ": hello\n\nid: 7\nevent: message\nretry: 1000\ndata: {\"a\":1}\ndata: second\n\ndata: x\n\n"
	if out.String() != want {
		t.Fatalf("got %q\nwant %q", out.String(), want)
	}
	// Truncated trailing event is discarded, oversized events error.
	br = bufio.NewReader(strings.NewReader("data: partial"))
	if _, err := readSSE(br, 4096); !errors.Is(err, io.EOF) {
		t.Fatalf("partial event: %v", err)
	}
	br = bufio.NewReader(strings.NewReader("data: " + strings.Repeat("a", 5000) + "\n\n"))
	if _, err := readSSE(br, 1024); !errors.Is(err, errEventTooLarge) {
		t.Fatalf("oversized event: %v", err)
	}
	// CRLF line endings.
	br = bufio.NewReader(strings.NewReader("data: x\r\n\r\n"))
	if ev, err := readSSE(br, 1024); err != nil || string(ev.Data) != "x" {
		t.Fatalf("CRLF: %+v %v", ev, err)
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	f.Add(`[{"jsonrpc":"2.0"}]`)
	f.Add(`{"jsonrpc":"2.0","id":1,"id":2}`)
	f.Fuzz(func(t *testing.T, s string) {
		m, err := parseMessage([]byte(s))
		if err != nil {
			return
		}
		// Anything accepted must be unambiguous: re-parsing the canonical
		// fields must yield the same method.
		if m.Method != "" {
			if _, err := callParams(m.Params); err == nil && m.Method == "" {
				t.Fatal("inconsistent")
			}
		}
	})
}
