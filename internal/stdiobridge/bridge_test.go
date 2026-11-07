package stdiobridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/mcpgw"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
)

const token = "bridge-token-0123456789abcdef-0123456789"

func TestMain(m *testing.M) {
	if os.Getenv("STDIOBRIDGE_HELPER") == "1" {
		helperServer()
		return
	}
	os.Exit(m.Run())
}

// helperServer is a tiny stdio MCP server driven by the tests.
func helperServer() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 8<<20)
	out := bufio.NewWriter(os.Stdout)
	send := func(v any) {
		b, _ := json.Marshal(v)
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}
	var initCount, initialized, cancelled int
	for in.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					Text string `json:"text"`
				} `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(in.Bytes(), &m) != nil || m.Method == "" {
			continue
		}
		reply := func(result any) { send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result}) }
		text := func(s string) { reply(map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}) }
		switch m.Method {
		case "initialize":
			initCount++
			reply(map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "helper"}})
		case "notifications/initialized":
			initialized++
		case "notifications/cancelled":
			cancelled++
		case "tools/list":
			var tools []map[string]any
			for _, n := range []string{"echo", "noise", "sample", "crash", "slow", "stats", "env", "delete_everything"} {
				tools = append(tools, map[string]any{"name": n, "description": n, "inputSchema": map[string]any{"type": "object"}})
			}
			reply(map[string]any{"tools": tools})
		case "tools/call":
			switch m.Params.Name {
			case "echo":
				text(m.Params.Arguments.Text)
			case "noise":
				fmt.Fprintln(os.Stdout, "log: hello from a sloppy server")
				fmt.Fprintln(os.Stdout, "{not json")
				text("noisy")
			case "sample":
				send(map[string]any{"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": map[string]any{}})
				got := "none"
				for in.Scan() {
					var r struct {
						ID    json.RawMessage `json:"id"`
						Error *struct {
							Code int `json:"code"`
						} `json:"error"`
						Result json.RawMessage `json:"result"`
					}
					if json.Unmarshal(in.Bytes(), &r) == nil && string(r.ID) == `"srv-1"` {
						if r.Error != nil {
							got = fmt.Sprintf("error:%d", r.Error.Code)
						} else {
							got = "result:" + string(r.Result)
						}
						break
					}
				}
				text("sampling " + got)
			case "crash":
				os.Exit(3)
			case "slow":
				time.Sleep(5 * time.Second)
				text("slow done")
			case "stats":
				text(fmt.Sprintf("init=%d initialized=%d cancelled=%d", initCount, initialized, cancelled))
			case "env":
				tok := "unset"
				if os.Getenv("AGENTBOX_BRIDGE_TOKEN") != "" || os.Getenv("BRIDGE_SECRET_SHOULD_NOT_LEAK") != "" {
					tok = "LEAKED"
				}
				text("token=" + tok + " extra=" + os.Getenv("EXTRA_VAR"))
			default:
				text("unknown tool")
			}
		default:
			if len(m.ID) > 0 {
				reply(map[string]any{})
			}
		}
	}
}

func newBridge(t *testing.T, mod func(*Config)) (*Bridge, *httptest.Server) {
	t.Helper()
	cfg := Config{
		Command: []string{os.Args[0]},
		Env:     []string{"STDIOBRIDGE_HELPER=1", "EXTRA_VAR=hello"},
		Token:   token,
	}
	if mod != nil {
		mod(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(b.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close(); b.Close() })
	return b, ts
}

func call(t *testing.T, ts *httptest.Server, method, path, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func initSession(t *testing.T, ts *httptest.Server, id int) string {
	t.Helper()
	resp, body := call(t, ts, "POST", "/mcp", fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{}}`, id), nil)
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize = %d %s", resp.StatusCode, body)
	}
	call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{"Mcp-Session-Id": sid})
	return sid
}

func toolText(t *testing.T, body []byte) string {
	t.Helper()
	var r struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			Content []struct{ Text string } `json:"content"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("bad body %q: %v", body, err)
	}
	if r.Error != nil {
		return "ERROR:" + r.Error.Message
	}
	if len(r.Result.Content) == 0 {
		return ""
	}
	return r.Result.Content[0].Text
}

func callTool(t *testing.T, ts *httptest.Server, sid string, id int, name, text string) string {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{"text":%q}}}`, id, name, text)
	resp, out := call(t, ts, "POST", "/mcp", body, map[string]string{"Mcp-Session-Id": sid})
	if resp.StatusCode != 200 {
		t.Fatalf("tools/call %s = %d %s", name, resp.StatusCode, out)
	}
	return toolText(t, out)
}

func TestAuthAndHost(t *testing.T) {
	_, ts := newBridge(t, func(c *Config) { c.AllowedHosts = []string{"bridge", "127.0.0.1"} })
	for name, hdr := range map[string]map[string]string{
		"none":  {"Authorization": ""},
		"wrong": {"Authorization": "Bearer wrong-token-wrong-token-wrong-token-xx"},
		"basic": {"Authorization": "Basic abc"},
	} {
		if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, hdr); resp.StatusCode != 401 {
			t.Errorf("%s token = %d, want 401", name, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", ts.URL+"/healthz", nil)
	req.Host = "evil.example.com"
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Errorf("bad host = %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", ts.URL+"/healthz", nil)
	req.Host = "bridge:9000"
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Errorf("good host = %d", resp.StatusCode)
	}
	if resp, _ := call(t, ts, "PUT", "/mcp", "", nil); resp.StatusCode != 405 {
		t.Errorf("PUT = %d", resp.StatusCode)
	}
}

func TestNewValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no command":  {Token: token},
		"short token": {Command: []string{"x"}, Token: "short"},
		"bad env":     {Command: []string{"x"}, Token: token, Env: []string{"NOEQUALS"}},
		"empty key":   {Command: []string{"x"}, Token: token, Env: []string{"=v"}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	b, _ := New(Config{Command: []string{"/definitely/not/a/binary"}, Token: token})
	if err := b.Start(); err == nil {
		t.Error("Start must fail for a missing binary")
	}
}

func TestHandshakeAndCall(t *testing.T) {
	_, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)
	if got := callTool(t, ts, sid, 2, "echo", "hi there"); got != "hi there" {
		t.Fatalf("echo = %q", got)
	}
	// Requests need a session.
	if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, nil); resp.StatusCode != 404 {
		t.Errorf("no session = %d", resp.StatusCode)
	}
	if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, map[string]string{"Mcp-Session-Id": "nope"}); resp.StatusCode != 404 {
		t.Errorf("bad session = %d", resp.StatusCode)
	}
	for _, bad := range []string{``, `[]`, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, `"x"`, `{bad`} {
		if resp, _ := call(t, ts, "POST", "/mcp", bad, map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 400 {
			t.Errorf("body %q = %d, want 400", bad, resp.StatusCode)
		}
	}
	// DELETE ends the session.
	if resp, _ := call(t, ts, "DELETE", "/mcp", "", map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 200 {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":9,"method":"ping"}`, map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 404 {
		t.Errorf("deleted session = %d", resp.StatusCode)
	}
	if resp, _ := call(t, ts, "DELETE", "/mcp", "", map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 404 {
		t.Errorf("double delete = %d", resp.StatusCode)
	}
}

func TestServerSeesOneHandshakeForManySessions(t *testing.T) {
	_, ts := newBridge(t, nil)
	s1 := initSession(t, ts, 1)
	s2 := initSession(t, ts, 1)
	s3 := initSession(t, ts, 1)
	if s1 == s2 || s2 == s3 {
		t.Fatal("each HTTP session needs its own id")
	}
	if got := callTool(t, ts, s3, 5, "stats", ""); got != "init=1 initialized=1 cancelled=0" {
		t.Fatalf("server saw %q; it must see exactly one initialize", got)
	}
}

func TestRequestIDsAreNamespaced(t *testing.T) {
	_, ts := newBridge(t, nil)
	s1 := initSession(t, ts, 1)
	s2 := initSession(t, ts, 1)
	var wg sync.WaitGroup
	errs := make(chan string, 40)
	for i := 0; i < 20; i++ {
		for _, s := range []string{s1, s2} {
			wg.Add(1)
			go func(s string, i int) {
				defer wg.Done()
				// Every client uses the same JSON-RPC id (7) on purpose.
				want := fmt.Sprintf("msg-%s-%d", s[:6], i)
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"text":%q}}}`, want)
				_, out := call(t, ts, "POST", "/mcp", body, map[string]string{"Mcp-Session-Id": s})
				var r struct {
					ID json.RawMessage `json:"id"`
				}
				_ = json.Unmarshal(out, &r)
				if got := toolText(t, out); got != want || string(r.ID) != "7" {
					errs <- fmt.Sprintf("want %q id 7, got %q id %s", want, got, r.ID)
				}
			}(s, i)
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestNoisyStdoutIsQuarantined(t *testing.T) {
	b, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)
	if got := callTool(t, ts, sid, 2, "noise", ""); got != "noisy" {
		t.Fatalf("noise = %q", got)
	}
	if got := callTool(t, ts, sid, 3, "echo", "still works"); got != "still works" {
		t.Fatalf("after noise = %q", got)
	}
	if b.noiseLines.Load() != 2 {
		t.Fatalf("quarantined lines = %d, want 2", b.noiseLines.Load())
	}
}

func TestChildEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("BRIDGE_SECRET_SHOULD_NOT_LEAK", "s3cret")
	t.Setenv("AGENTBOX_BRIDGE_TOKEN", token)
	_, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)
	if got := callTool(t, ts, sid, 2, "env", ""); got != "token=unset extra=hello" {
		t.Fatalf("env = %q (bridge secrets must not reach the MCP server)", got)
	}
}

func TestServerRequestsReachClientStreamAndRepliesFlowBack(t *testing.T) {
	_, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)

	req, _ := http.NewRequest("GET", ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", sid)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if line, _ := br.ReadString('\n'); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("first line = %q", line)
	}
	br.ReadString('\n')

	result := make(chan string, 1)
	go func() { result <- callTool(t, ts, sid, 2, "sample", "") }()

	var data string
	deadline := time.After(5 * time.Second)
	lines := make(chan string)
	go func() {
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				close(lines)
				return
			}
			lines <- strings.TrimRight(l, "\r\n")
		}
	}()
loop:
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream closed")
			}
			if strings.HasPrefix(l, "data: ") {
				data = strings.TrimPrefix(l, "data: ")
				break loop
			}
		case <-deadline:
			t.Fatal("server request never arrived on the stream")
		}
	}
	if !strings.Contains(data, "sampling/createMessage") || !strings.Contains(data, `"srv-1"`) {
		t.Fatalf("stream data = %s", data)
	}
	// The client answers via POST; the server receives it unchanged.
	if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":"srv-1","error":{"code":-32601,"message":"no"}}`, map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 202 {
		t.Fatalf("reply = %d", resp.StatusCode)
	}
	select {
	case got := <-result:
		if got != "sampling error:-32601" {
			t.Fatalf("tool result = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tool call never completed")
	}
}

func TestServerRequestWithNoStreamGetsErrorReply(t *testing.T) {
	_, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)
	// No GET stream is open: the bridge itself must answer the server's request.
	if got := callTool(t, ts, sid, 2, "sample", ""); got != "sampling error:-32601" {
		t.Fatalf("got %q; the server would otherwise hang forever", got)
	}
}

func TestRequestTimeoutCancelsUpstream(t *testing.T) {
	_, ts := newBridge(t, func(c *Config) { c.RequestTimeout = 300 * time.Millisecond })
	sid := initSession(t, ts, 1)
	start := time.Now()
	resp, body := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"slow"}}`, map[string]string{"Mcp-Session-Id": sid})
	if resp.StatusCode != 504 || !strings.Contains(string(body), `"id":4`) {
		t.Fatalf("timeout = %d %s", resp.StatusCode, body)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not time out promptly")
	}
}

func TestChildCrashFailsClosed(t *testing.T) {
	b, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)
	resp, body := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"crash"}}`, map[string]string{"Mcp-Session-Id": sid})
	if resp.StatusCode != 503 {
		t.Fatalf("crash during request = %d %s", resp.StatusCode, body)
	}
	select {
	case <-b.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Done never closed after the child exited")
	}
	if b.Err() == nil {
		t.Error("exit error not recorded")
	}
	if resp, _ := call(t, ts, "GET", "/healthz", "", nil); resp.StatusCode != 503 {
		t.Errorf("healthz after crash = %d", resp.StatusCode)
	}
	if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":6,"method":"ping"}`, map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 503 {
		t.Errorf("request after crash = %d", resp.StatusCode)
	}
}

func TestSessionLimit(t *testing.T) {
	_, ts := newBridge(t, func(c *Config) { c.MaxSessions = 2 })
	initSession(t, ts, 1)
	initSession(t, ts, 1)
	if resp, _ := call(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, nil); resp.StatusCode != 503 {
		t.Fatalf("session limit = %d", resp.StatusCode)
	}
}

func TestBodyLimit(t *testing.T) {
	_, ts := newBridge(t, func(c *Config) { c.MaxBodyBytes = 256 })
	sid := initSession(t, ts, 1)
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"` + strings.Repeat("a", 1000) + `"}}}`
	if resp, _ := call(t, ts, "POST", "/mcp", big, map[string]string{"Mcp-Session-Id": sid}); resp.StatusCode != 413 {
		t.Fatalf("oversized = %d", resp.StatusCode)
	}
}

func TestMultilineJSONIsCompactedBeforeStdio(t *testing.T) {
	_, ts := newBridge(t, nil)
	sid := initSession(t, ts, 1)
	body := "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 2,\n  \"method\": \"tools/call\",\n  \"params\": {\"name\": \"echo\",\n   \"arguments\": {\"text\": \"multi\"}}\n}"
	_, out := call(t, ts, "POST", "/mcp", body, map[string]string{"Mcp-Session-Id": sid})
	if toolText(t, out) != "multi" {
		t.Fatalf("pretty-printed request broke stdio framing: %s", out)
	}
}

// End to end: agent-facing MCP gateway -> bridge -> stdio server.

type e2eCtl struct{}

func (e2eCtl) allowed(tool string) bool { return tool != "delete_everything" && tool != "sample" }
func (c e2eCtl) DecideMCP(_ context.Context, _, tool string) gwclient.Decision {
	if c.allowed(tool) {
		return gwclient.Decision{Decision: policy.Decision{Effect: policy.Allow, RuleID: "e2e#allow"}}
	}
	return gwclient.Decision{Decision: policy.Decision{Effect: policy.Deny, RuleID: "e2e#deny"}}
}
func (c e2eCtl) DecideMCPAsk(ctx context.Context, s, tool, _ string) gwclient.Decision {
	return c.DecideMCP(ctx, s, tool)
}
func (c e2eCtl) DecideMCPTools(_ context.Context, _ string, tools []string) (map[string]policy.Decision, error) {
	out := map[string]policy.Decision{}
	for _, t := range tools {
		if c.allowed(t) {
			out[t] = policy.Decision{Effect: policy.Allow}
		} else {
			out[t] = policy.Decision{Effect: policy.Deny}
		}
	}
	return out, nil
}
func (e2eCtl) ReportEvent(context.Context, gwclient.Event) error { return nil }

func TestEndToEndThroughMCPGateway(t *testing.T) {
	_, bts := newBridge(t, nil)
	tokFile := t.TempDir() + "/bridge-token"
	if err := os.WriteFile(tokFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	gw, err := mcpgw.New(mcpgw.Config{
		Controller: e2eCtl{},
		Servers:    []mcpgw.Server{{Name: "files", URL: bts.URL + "/mcp", BearerFile: tokFile}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gts := httptest.NewServer(gw.Handler())
	defer func() { gts.CloseClientConnections(); gts.Close(); gw.Wait() }()

	post := func(body string, sid string) (*http.Response, []byte) {
		req, _ := http.NewRequest("POST", gts.URL+"/mcp/files", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	resp, body := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize = %d %s", resp.StatusCode, body)
	}
	post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, sid)

	// tools/list hides policy-denied tools.
	_, body = post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, sid)
	if strings.Contains(string(body), "delete_everything") || !strings.Contains(string(body), `"echo"`) {
		t.Fatalf("tools/list = %s", body)
	}
	// Allowed call works end to end; denied call never reaches the server.
	_, body = post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"through everything"}}}`, sid)
	if toolText(t, body) != "through everything" {
		t.Fatalf("echo = %s", body)
	}
	_, body = post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_everything"}}`, sid)
	if !strings.Contains(string(body), "blocked by AgentBox policy") {
		t.Fatalf("denied call = %s", body)
	}
	_, body = post(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"stats"}}`, sid)
	if got := toolText(t, body); got != "init=1 initialized=1 cancelled=0" {
		t.Fatalf("stats = %q", got)
	}
	// The agent holds neither the bridge token nor the real session id.
	if bytes.Contains(body, []byte(token)) {
		t.Fatal("bridge token leaked to the agent")
	}
}
