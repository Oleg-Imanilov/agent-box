package mcpgw_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/controller"
	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/mcpgw"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

const adminToken = "0123456789abcdef0123456789abcdef-admin"

func TestRealControllerApprovalsAndFiltering(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	al := audit.NewLogger(st, audit.Options{FlushInterval: 5 * time.Millisecond})
	csrv, err := controller.New(controller.Config{AdminToken: adminToken, AllowedHosts: []string{"localhost", "127.0.0.1"}}, st, policy.NewEngine(), al)
	if err != nil {
		t.Fatal(err)
	}
	cts := httptest.NewServer(csrv.Handler())
	t.Cleanup(func() { cts.CloseClientConnections(); cts.Close(); _ = al.Close(ctx); _ = st.Close() })

	admin := func(method, path, body string, out any) {
		t.Helper()
		req, _ := http.NewRequest(method, cts.URL+path, strings.NewReader(body))
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
		if out != nil {
			if err := json.Unmarshal(b, out); err != nil {
				t.Fatal(err)
			}
		}
	}
	var created struct {
		Token string `json:"gateway_token"`
	}
	admin("POST", "/v1/sessions", `{"agent":"hermes"}`, &created)
	admin("PUT", "/v1/policies/global", "mcp:\n  files:\n    allow_tools: [read_file]", nil)

	var mu sync.Mutex
	var called []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct{ Name string }
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		w.Header().Set("Content-Type", "application/json")
		switch m.Method {
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read_file"},{"name":"write_file"},{"name":"delete_file"}]}}`, m.ID)
		case "tools/call":
			mu.Lock()
			called = append(called, m.Params.Name)
			mu.Unlock()
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ran %s"}]}}`, m.ID, m.Params.Name)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, m.ID)
		}
	}))
	defer upstream.Close()

	client, err := gwclient.New(cts.URL, created.Token, gwclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := mcpgw.New(mcpgw.Config{Controller: client, Approvals: true, Servers: []mcpgw.Server{{Name: "files", URL: upstream.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	gts := httptest.NewServer(gw.Handler())
	defer func() { gts.CloseClientConnections(); gts.Close(); gw.Wait() }()

	post := func(body string) []byte {
		resp, err := http.Post(gts.URL+"/mcp/files", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}

	// tools/list shows only what policy allows.
	list := string(post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if !strings.Contains(list, "read_file") || strings.Contains(list, "write_file") || strings.Contains(list, "delete_file") {
		t.Fatalf("tools/list = %s", list)
	}
	// An allowed tool runs immediately.
	if out := string(post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`)); !strings.Contains(out, "ran read_file") {
		t.Fatalf("allowed = %s", out)
	}

	// An unlisted tool is held for approval and runs only after the decision.
	result := make(chan string, 1)
	go func() {
		result <- string(post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file"}}`))
	}()
	var pending struct{ Approvals []store.Approval }
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(pending.Approvals) == 0 {
		admin("GET", "/v1/approvals", "", &pending)
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending.Approvals) != 1 || pending.Approvals[0].Kind != "mcp" || pending.Approvals[0].Subject != "files/write_file" {
		t.Fatalf("pending = %+v", pending.Approvals)
	}
	mu.Lock()
	for _, c := range called {
		if c == "write_file" {
			t.Fatal("tool executed before approval")
		}
	}
	mu.Unlock()
	body, _ := json.Marshal(map[string]string{"request_id": pending.Approvals[0].RequestID, "decision": "session"})
	admin("POST", "/v1/approvals/decide", string(body), nil)
	select {
	case out := <-result:
		if !strings.Contains(out, "ran write_file") {
			t.Fatalf("after approval = %s", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("approved call never completed")
	}
	// The session-scoped rule now covers it, and tools/list reflects it.
	if out := string(post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file"}}`)); !strings.Contains(out, "ran write_file") {
		t.Fatalf("second call = %s", out)
	}
	if list := string(post(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)); !strings.Contains(list, "write_file") || strings.Contains(list, "delete_file") {
		t.Fatalf("tools/list after approval = %s", list)
	}

	// Deny leaves the tool unexecuted.
	go func() {
		result <- string(post(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delete_file"}}`))
	}()
	pending.Approvals = nil
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(pending.Approvals) == 0 {
		admin("GET", "/v1/approvals", "", &pending)
		time.Sleep(10 * time.Millisecond)
	}
	body, _ = json.Marshal(map[string]string{"request_id": pending.Approvals[0].RequestID, "decision": "deny"})
	admin("POST", "/v1/approvals/decide", string(body), nil)
	if out := <-result; !strings.Contains(out, "blocked by AgentBox policy") {
		t.Fatalf("denied = %s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, c := range called {
		if c == "delete_file" {
			t.Fatal("denied tool executed")
		}
	}
}
