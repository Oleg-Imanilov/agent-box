package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

type askResult struct {
	d      DecisionResponse
	status int
}

// askNetwork sends an ask=true decision request in the background.
func (e *env) askNetwork(tok, host string, port int, reqID string) <-chan askResult {
	ch := make(chan askResult, 1)
	go func() {
		resp, out := e.do("POST", "/v1/gw/decide/network", tok,
			map[string]any{"host": host, "port": port, "ask": true, "request_id": reqID}, nil)
		var d DecisionResponse
		_ = json.Unmarshal(out, &d)
		ch <- askResult{d: d, status: resp.StatusCode}
	}()
	return ch
}

func (e *env) askMCP(tok, server, tool, reqID string) <-chan askResult {
	ch := make(chan askResult, 1)
	go func() {
		resp, out := e.do("POST", "/v1/gw/decide/mcp", tok,
			map[string]any{"server": server, "tool": tool, "ask": true, "request_id": reqID}, nil)
		var d DecisionResponse
		_ = json.Unmarshal(out, &d)
		ch <- askResult{d: d, status: resp.StatusCode}
	}()
	return ch
}

// waitPending polls until n approvals are pending and returns them.
func (e *env) waitPending(n int) []store.Approval {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, out := e.admin("GET", "/v1/approvals", nil)
		list := decode[struct{ Approvals []store.Approval }](e.t, out).Approvals
		if len(list) == n {
			return list
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("timed out waiting for %d pending approvals", n)
	return nil
}

func (e *env) decideApproval(requestID, decision string) (*http.Response, []byte) {
	return e.admin("POST", "/v1/approvals/decide", map[string]string{"request_id": requestID, "decision": decision})
}

func result(t *testing.T, ch <-chan askResult) askResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("decision request did not return")
		return askResult{}
	}
}

func TestApprovalOnce(t *testing.T) {
	e := newEnv(t, Config{AllowCacheTTL: 5 * time.Second})
	id, tok := e.createSession("hermes")
	ch := e.askNetwork(tok, "New.Example.com", 443, "req-0000-0001")
	p := e.waitPending(1)[0]
	if p.Kind != "network" || p.Subject != "new.example.com:443" || p.SessionID != id || p.RequestID != id+"/req-0000-0001" {
		t.Fatalf("pending = %+v", p)
	}
	select {
	case <-ch:
		t.Fatal("request must be held until decided")
	case <-time.After(100 * time.Millisecond):
	}
	if resp, out := e.decideApproval(p.RequestID, "once"); resp.StatusCode != 200 {
		t.Fatalf("decide = %d %s", resp.StatusCode, out)
	}
	r := result(t, ch)
	if r.d.Effect != policy.Allow || !strings.HasPrefix(r.d.RuleID, "approval:") || !strings.HasSuffix(r.d.RuleID, ":once") || r.d.CacheTTLSeconds != 0 {
		t.Fatalf("once = %+v", r.d)
	}
	// "once" does not create a rule: the same destination needs a new approval.
	_, out := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "new.example.com", "port": 443}, nil)
	if decode[DecisionResponse](t, out).Effect != policy.Deny {
		t.Fatal("once must not persist a rule")
	}
	if _, err := e.st.GetPolicy(context.Background(), "agent:hermes"); err == nil {
		t.Fatal("no policy should have been written")
	}
	// The same request id is idempotent: replays the stored decision without re-prompting.
	r = result(t, e.askNetwork(tok, "new.example.com", 443, "req-0000-0001"))
	if r.d.Effect != policy.Allow || !strings.HasSuffix(r.d.RuleID, ":once") {
		t.Fatalf("replay = %+v", r.d)
	}
	if _, out := e.admin("GET", "/v1/approvals", nil); len(decode[struct{ Approvals []store.Approval }](t, out).Approvals) != 0 {
		t.Fatal("replay must not create a new pending approval")
	}

	e.flush()
	events, _ := e.st.ListEvents(context.Background(), store.EventFilter{Kind: "approval", Limit: 10})
	var ops []string
	for _, ev := range events {
		ops = append(ops, ev.Operation)
	}
	if strings.Join(ops, ",") != "approval.requested,approval.decided" {
		t.Fatalf("approval audit events = %v", ops)
	}
}

func TestApprovalSessionRule(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	_, tok2 := e.createSession("hermes") // another session of the same agent
	ch := e.askNetwork(tok, "api.example.com", 443, "req-0000-0002")
	p := e.waitPending(1)[0]
	e.decideApproval(p.RequestID, "session")
	if r := result(t, ch); r.d.Effect != policy.Allow || !strings.HasSuffix(r.d.RuleID, ":session") {
		t.Fatalf("session = %+v", r.d)
	}
	decide := func(token string) DecisionResponse {
		_, out := e.do("POST", "/v1/gw/decide/network", token, map[string]any{"host": "api.example.com", "port": 443}, nil)
		return decode[DecisionResponse](t, out)
	}
	if d := decide(tok); d.Effect != policy.Allow || d.RuleID != "session:"+id+"#network.allow[0]" {
		t.Fatalf("later request in session = %+v", d)
	}
	if d := decide(tok2); d.Effect != policy.Deny {
		t.Fatalf("session rule leaked to another session: %+v", d)
	}
	e.admin("POST", "/v1/sessions/"+id+"/end", nil)
	if d := e.eng.EvaluateNetwork(policy.Subject{Agent: "hermes", Session: id}, "api.example.com", 443); d.Allowed() {
		t.Fatal("session rule must die with the session")
	}
}

func TestApprovalPersistRuleIsAgentScoped(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	_, tokOther := e.createSession("codex")
	_, tokSame := e.createSession("hermes")
	ch := e.askNetwork(tok, "pypi.org", 443, "req-0000-0003")
	e.decideApproval(e.waitPending(1)[0].RequestID, "persist")
	if r := result(t, ch); !strings.HasSuffix(r.d.RuleID, ":persist") || r.d.Effect != policy.Allow {
		t.Fatalf("persist = %+v", r.d)
	}
	rec, err := e.st.GetPolicy(context.Background(), "agent:hermes")
	if err != nil || !strings.Contains(string(rec.RuleJSON), "pypi.org:443") {
		t.Fatalf("agent policy = %+v %v", rec, err)
	}
	hist, _ := e.st.PolicyHistory(context.Background(), "agent:hermes", 1)
	if hist[0].Actor != "approval" {
		t.Fatalf("actor = %q", hist[0].Actor)
	}
	check := func(token string) policy.Effect {
		_, out := e.do("POST", "/v1/gw/decide/network", token, map[string]any{"host": "pypi.org", "port": 443}, nil)
		return decode[DecisionResponse](t, out).Effect
	}
	if check(tokSame) != policy.Allow {
		t.Fatal("persisted rule must apply to new sessions of the same agent")
	}
	if check(tokOther) != policy.Deny {
		t.Fatal("persisted rule must not apply to other agents")
	}
	// Asking again for an already-allowed destination never creates an approval.
	_, out := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "pypi.org", "port": 443, "ask": true, "request_id": "req-0000-0004"}, nil)
	if decode[DecisionResponse](t, out).Effect != policy.Allow {
		t.Fatal("allowed destination must not be re-asked")
	}
	// Rules appended by approvals keep existing policy content.
	e.putPolicy("agent:hermes", "network:\n  allow: [pypi.org:443, keep.example.com:443]")
	ch = e.askNetwork(tok, "other.example.com", 443, "req-0000-0005")
	e.decideApproval(e.waitPending(1)[0].RequestID, "persist")
	result(t, ch)
	rec, _ = e.st.GetPolicy(context.Background(), "agent:hermes")
	if !strings.Contains(string(rec.RuleJSON), "keep.example.com:443") || !strings.Contains(string(rec.RuleJSON), "other.example.com:443") {
		t.Fatalf("existing rules lost: %s", rec.RuleJSON)
	}
}

func TestApprovalDeny(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	ch := e.askNetwork(tok, "evil.example.com", 443, "req-0000-0006")
	e.decideApproval(e.waitPending(1)[0].RequestID, "deny")
	r := result(t, ch)
	if r.d.Effect != policy.Deny || !strings.HasSuffix(r.d.RuleID, ":deny") {
		t.Fatalf("deny = %+v", r.d)
	}
}

func TestApprovalTimeoutDenies(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	if err := e.st.SetSetting(context.Background(), SettingApprovalTimeoutNetwork, "1"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := result(t, e.askNetwork(tok, "slow.example.com", 443, "req-0000-0007"))
	if r.d.Effect != policy.Deny || r.d.RuleID != RuleApprovalTimeout {
		t.Fatalf("timeout = %+v", r.d)
	}
	if el := time.Since(start); el < 900*time.Millisecond || el > 4*time.Second {
		t.Fatalf("timeout took %v", el)
	}
	if list := e.waitPending(0); len(list) != 0 {
		t.Fatalf("expired approval still pending: %+v", list)
	}
	// A late decision on an expired approval is rejected.
	_, out := e.admin("GET", "/v1/approvals?status=expired", nil)
	exp := decode[struct{ Approvals []store.Approval }](t, out).Approvals
	if len(exp) != 1 {
		t.Fatalf("expired list = %+v", exp)
	}
	if resp, _ := e.decideApproval(exp[0].RequestID, "once"); resp.StatusCode != 409 {
		t.Fatalf("late decision = %d, want 409", resp.StatusCode)
	}
}

func TestApprovalTimeoutsPerEntityType(t *testing.T) {
	e := newEnv(t, Config{})
	if e.srv.approvalTimeout("network") != 60*time.Second || e.srv.approvalTimeout("mcp") != 120*time.Second {
		t.Fatalf("defaults: %v %v", e.srv.approvalTimeout("network"), e.srv.approvalTimeout("mcp"))
	}
	resp, out := e.admin("PUT", "/v1/settings", map[string]any{"approval_timeout_network_seconds": 30, "approval_timeout_mcp_seconds": 300})
	if resp.StatusCode != 200 {
		t.Fatalf("put = %d %s", resp.StatusCode, out)
	}
	if e.srv.approvalTimeout("network") != 30*time.Second || e.srv.approvalTimeout("mcp") != 300*time.Second {
		t.Fatal("per-entity timeouts not applied")
	}
	_, out = e.admin("GET", "/v1/settings", nil)
	if s := decode[map[string]any](t, out); s["approval_timeout_network_seconds"] != float64(30) || s["approval_timeout_mcp_seconds"] != float64(300) {
		t.Fatalf("settings = %v", s)
	}
	for _, bad := range []map[string]any{{"approval_timeout_network_seconds": 1}, {"approval_timeout_mcp_seconds": 601}} {
		if resp, _ := e.admin("PUT", "/v1/settings", bad); resp.StatusCode != 400 {
			t.Errorf("bad timeout %v = %d", bad, resp.StatusCode)
		}
	}
}

func TestExplicitDenyCannotBeApproved(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	e.putPolicy("global", "network:\n  deny: ['*.evil.com:*']\nmcp:\n  gh:\n    deny_tools: [delete_repo]")
	_, out := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "x.evil.com", "port": 443, "ask": true, "request_id": "req-0000-0008"}, nil)
	if d := decode[DecisionResponse](t, out); d.Effect != policy.Deny || d.RuleID != "global#network.deny[0]" {
		t.Fatalf("explicit deny must not escalate: %+v", d)
	}
	_, out = e.do("POST", "/v1/gw/decide/mcp", tok, map[string]any{"server": "gh", "tool": "delete_repo", "ask": true, "request_id": "req-0000-0009"}, nil)
	if d := decode[DecisionResponse](t, out); d.Effect != policy.Deny || !strings.Contains(d.RuleID, "deny_tools") {
		t.Fatalf("explicit mcp deny must not escalate: %+v", d)
	}
	if list, _ := e.st.ListApprovals(context.Background(), "", 10); len(list) != 0 {
		t.Fatalf("approvals created for explicit denies: %+v", list)
	}
}

func TestAskRequiresValidRequestID(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	for _, id := range []string{"", "short", "has space in it 123", strings.Repeat("a", 65), "a/b/c/d/e/f/g/h"} {
		resp, _ := e.do("POST", "/v1/gw/decide/network", tok, map[string]any{"host": "a.com", "port": 443, "ask": true, "request_id": id}, nil)
		if resp.StatusCode != 400 {
			t.Errorf("request_id %q = %d, want 400", id, resp.StatusCode)
		}
	}
}

func TestApprovalRequestIDConflictAndNamespacing(t *testing.T) {
	e := newEnv(t, Config{})
	_, tokA := e.createSession("hermes")
	_, tokB := e.createSession("hermes")
	chA := e.askNetwork(tokA, "a.example.com", 443, "same-id-0001")
	e.waitPending(1)
	// Same client request id in another session is a different approval (namespaced).
	chB := e.askNetwork(tokB, "b.example.com", 443, "same-id-0001")
	pend := e.waitPending(2)
	if pend[0].RequestID == pend[1].RequestID {
		t.Fatal("request ids must be namespaced per session")
	}
	// Reusing an id in the same session for a different destination is rejected.
	r := result(t, e.askNetwork(tokA, "different.example.com", 443, "same-id-0001"))
	if r.d.Effect != policy.Deny || r.d.RuleID != RuleApprovalConflict {
		t.Fatalf("conflict = %+v", r.d)
	}
	for _, p := range pend {
		e.decideApproval(p.RequestID, "deny")
	}
	result(t, chA)
	result(t, chB)
}

func TestConcurrentWaitersShareOneApproval(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	var chans []<-chan askResult
	for i := 0; i < 3; i++ {
		chans = append(chans, e.askNetwork(tok, "shared.example.com", 443, "shared-req-01"))
	}
	p := e.waitPending(1)[0]
	time.Sleep(50 * time.Millisecond)
	e.decideApproval(p.RequestID, "once")
	for _, ch := range chans {
		if r := result(t, ch); r.d.Effect != policy.Allow {
			t.Fatalf("waiter = %+v", r.d)
		}
	}
}

func TestApprovalQueueLimit(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	exp := time.Now().Add(time.Minute)
	for i := 0; i < maxPendingApprovalsPerSession; i++ {
		_, err := e.st.CreateApproval(context.Background(), store.Approval{
			RequestID: id + "/fill-" + strings.Repeat("x", 8) + string(rune('a'+i)), SessionID: id, Kind: "network", Subject: "h:1", ExpiresAt: &exp})
		if err != nil {
			t.Fatal(err)
		}
	}
	r := result(t, e.askNetwork(tok, "one-too-many.example.com", 443, "req-0000-0010"))
	if r.d.Effect != policy.Deny || r.d.RuleID != RuleApprovalQueueFull {
		t.Fatalf("queue limit = %+v", r.d)
	}
}

func TestSessionEndReleasesWaiters(t *testing.T) {
	e := newEnv(t, Config{})
	id, tok := e.createSession("hermes")
	ch := e.askNetwork(tok, "a.example.com", 443, "req-0000-0011")
	e.waitPending(1)
	e.admin("POST", "/v1/sessions/"+id+"/end", nil)
	r := result(t, ch)
	if r.d.Effect != policy.Deny {
		t.Fatalf("held request must be denied when the session ends: %+v", r.d)
	}
	e.waitPending(0)
}

func TestClientCancelDeniesWaiter(t *testing.T) {
	e := newEnv(t, Config{})
	id, _ := e.createSession("hermes")
	sess, _ := e.st.GetSession(context.Background(), id)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan policy.Decision, 1)
	go func() {
		done <- e.srv.askApproval(ctx, sess, "network", "a.example.com:443", "req-0000-0012", policy.Decision{Effect: policy.Deny, RuleID: policy.RuleDefaultDeny})
	}()
	e.waitPending(1)
	cancel()
	select {
	case d := <-done:
		if d.Effect != policy.Deny || d.RuleID != RuleApprovalCancelled {
			t.Fatalf("cancel = %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}
}

func TestDecideApprovalValidation(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	if resp, _ := e.do("POST", "/v1/approvals/decide", tok, `{"request_id":"x","decision":"once"}`, nil); resp.StatusCode != 401 {
		t.Errorf("gateway token on approvals = %d, want 401", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/v1/approvals/decide", "", `{"request_id":"x","decision":"once"}`, nil); resp.StatusCode != 401 {
		t.Errorf("unauthenticated = %d, want 401", resp.StatusCode)
	}
	if resp, _ := e.decideApproval("nope", "once"); resp.StatusCode != 404 {
		t.Errorf("unknown = %d, want 404", resp.StatusCode)
	}
	if resp, _ := e.decideApproval("nope", "forever"); resp.StatusCode != 400 {
		t.Errorf("bad decision = %d, want 400", resp.StatusCode)
	}
	if resp, _ := e.admin("GET", "/v1/approvals?status=bogus", nil); resp.StatusCode != 400 {
		t.Errorf("bad status = %d, want 400", resp.StatusCode)
	}
	ch := e.askNetwork(tok, "a.example.com", 443, "req-0000-0013")
	p := e.waitPending(1)[0]
	if resp, _ := e.decideApproval(p.RequestID, "deny"); resp.StatusCode != 200 {
		t.Fatal("first decision must succeed")
	}
	if resp, _ := e.decideApproval(p.RequestID, "once"); resp.StatusCode != 409 {
		t.Errorf("second decision = %d, want 409 (decisions are never overwritten)", resp.StatusCode)
	}
	result(t, ch)
}

func TestApprovalMCPPersistAndToolsEndpoint(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok := e.createSession("hermes")
	e.putPolicy("global", "mcp:\n  github:\n    allow_tools: [get_file_contents]\n    deny_tools: [delete_repository]")
	ch := e.askMCP(tok, "github", "create_issue", "req-0000-0014")
	p := e.waitPending(1)[0]
	if p.Kind != "mcp" || p.Subject != "github/create_issue" {
		t.Fatalf("pending = %+v", p)
	}
	e.decideApproval(p.RequestID, "persist")
	if r := result(t, ch); r.d.Effect != policy.Allow {
		t.Fatalf("mcp persist = %+v", r.d)
	}
	rec, _ := e.st.GetPolicy(context.Background(), "agent:hermes")
	if !strings.Contains(string(rec.RuleJSON), "create_issue") {
		t.Fatalf("agent policy = %s", rec.RuleJSON)
	}
	_, out := e.do("POST", "/v1/gw/decide/mcp", tok, map[string]any{"server": "github", "tool": "create_issue"}, nil)
	if decode[DecisionResponse](t, out).Effect != policy.Allow {
		t.Fatal("persisted mcp tool must be allowed")
	}

	// Bulk tool evaluation for tools/list filtering.
	resp, out := e.do("POST", "/v1/gw/decide/mcp/tools", tok,
		map[string]any{"server": "github", "tools": []string{"get_file_contents", "create_issue", "delete_repository", "unknown"}}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("tools = %d %s", resp.StatusCode, out)
	}
	got := map[string]policy.Effect{}
	for _, d := range decode[struct{ Decisions []toolDecision }](t, out).Decisions {
		got[d.Tool] = d.Effect
	}
	want := map[string]policy.Effect{"get_file_contents": policy.Allow, "create_issue": policy.Allow, "delete_repository": policy.Deny, "unknown": policy.Deny}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("tool %s = %s, want %s", k, got[k], v)
		}
	}
	e.flush()
	events, _ := e.st.ListEvents(context.Background(), store.EventFilter{Kind: "mcp", Query: "github", Limit: 50})
	var summary int
	for _, ev := range events {
		if ev.Operation == "tools/list" {
			summary++
			if ev.Decision != "info" || !strings.Contains(string(ev.Metadata), `"hidden":2`) {
				t.Errorf("tools/list summary event = %+v %s", ev, ev.Metadata)
			}
		}
	}
	if summary != 1 {
		t.Errorf("tools/list summary events = %d, want 1", summary)
	}
	if resp, _ := e.do("POST", "/v1/gw/decide/mcp/tools", tok, map[string]any{"server": "", "tools": []string{"a"}}, nil); resp.StatusCode != 400 {
		t.Errorf("empty server = %d", resp.StatusCode)
	}
}

func TestLoadStateExpiresStaleApprovals(t *testing.T) {
	e := newEnv(t, Config{})
	id, _ := e.createSession("hermes")
	exp := time.Now().Add(time.Hour)
	if _, err := e.st.CreateApproval(context.Background(), store.Approval{RequestID: id + "/stale-0001", SessionID: id, Kind: "network", Subject: "h:1", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.waitPending(0)
}

func TestApprovalHubNoLostWakeups(t *testing.T) {
	var h approvalHub
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		ch := h.channel("x")
		wg.Add(1)
		go func() { defer wg.Done(); <-ch }()
	}
	h.wake("x")
	wg.Wait()
	h.wake("x") // waking nothing is a no-op
	h.channel("p/1")
	h.channel("p/2")
	h.wakePrefix("p/")
	if len(h.chans) != 0 {
		t.Fatalf("chans left: %d", len(h.chans))
	}
}
