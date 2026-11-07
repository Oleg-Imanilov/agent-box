package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "agentbox.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestMigrateIdempotentAndVersion(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	v, err := s.SchemaVersion(ctx)
	if err != nil || v != 1 {
		t.Fatalf("SchemaVersion = %d, %v", v, err)
	}
	_ = s.Close()
	s2, err := Open(ctx, path) // reopen: migrations must not re-run
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if v, _ := s2.SchemaVersion(ctx); v != 1 {
		t.Fatalf("version after reopen = %d", v)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	sess := Session{ID: "s1", Agent: "hermes", Workspace: "/work", ImageDigest: "sha256:abc"}
	if err := s.CreateSession(ctx, sess, HashToken("tok1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, Session{ID: "s2", Agent: "hermes"}, HashToken("tok1")); err == nil {
		t.Fatal("duplicate token hash must be rejected")
	}
	got, err := s.SessionByTokenHash(ctx, HashToken("tok1"))
	if err != nil || got.ID != "s1" || !got.Active() {
		t.Fatalf("SessionByTokenHash = %+v, %v", got, err)
	}
	if _, err := s.SessionByTokenHash(ctx, HashToken("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	ended, err := s.EndSession(ctx, "s1", time.Time{})
	if err != nil || ended.Active() {
		t.Fatalf("EndSession = %+v, %v", ended, err)
	}
	first := *ended.EndedAt
	again, _ := s.EndSession(ctx, "s1", first.Add(time.Hour))
	if !again.EndedAt.Equal(first) {
		t.Fatal("EndSession must be idempotent")
	}
	if _, err := s.EndSession(ctx, "missing", time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	active, _ := s.ListSessions(ctx, true, 0)
	all, _ := s.ListSessions(ctx, false, 0)
	if len(active) != 0 || len(all) != 1 {
		t.Fatalf("active=%d all=%d", len(active), len(all))
	}
}

func ev(session, kind, decision, dest string, ts time.Time) Event {
	return Event{SessionID: session, TS: ts, Kind: kind, Decision: decision, Destination: dest, RuleID: "r", Metadata: json.RawMessage(`{"k":"v"}`)}
}

func TestEventsInsertAndFilter(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	base := time.Now().Add(-time.Hour)
	events := []Event{
		ev("s1", "network", "allow", "api.openai.com:443", base),
		ev("s1", "network", "deny", "evil.com:443", base.Add(time.Minute)),
		ev("s2", "mcp", "deny", "github/delete_repository", base.Add(2*time.Minute)),
		ev("s2", "mcp", "allow", "100%_literal", base.Add(3*time.Minute)),
	}
	if err := s.InsertEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	for i, e := range events {
		if e.ID == 0 || (i > 0 && e.ID <= events[i-1].ID) {
			t.Fatalf("ids not assigned monotonically: %+v", events)
		}
	}
	list := func(f EventFilter) []Event {
		out, err := s.ListEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if n := len(list(EventFilter{})); n != 4 {
		t.Fatalf("all = %d", n)
	}
	if n := len(list(EventFilter{SessionID: "s1"})); n != 2 {
		t.Fatalf("session = %d", n)
	}
	if n := len(list(EventFilter{Decision: "deny"})); n != 2 {
		t.Fatalf("deny = %d", n)
	}
	if n := len(list(EventFilter{Kind: "mcp", Decision: "deny"})); n != 1 {
		t.Fatalf("mcp deny = %d", n)
	}
	if n := len(list(EventFilter{Query: "openai"})); n != 1 {
		t.Fatalf("query = %d", n)
	}
	if n := len(list(EventFilter{Query: "%"})); n != 1 { // LIKE wildcards are escaped
		t.Fatalf("escaped query = %d", n)
	}
	if n := len(list(EventFilter{Query: "_"})); n != 2 { // literal underscore only
		t.Fatalf("escaped underscore = %d", n)
	}
	desc := list(EventFilter{Desc: true, Limit: 2})
	if len(desc) != 2 || desc[0].ID < desc[1].ID {
		t.Fatalf("desc order = %+v", desc)
	}
	after := list(EventFilter{AfterID: events[1].ID})
	if len(after) != 2 || after[0].ID != events[2].ID {
		t.Fatalf("after = %+v", after)
	}
	before := list(EventFilter{BeforeID: events[1].ID, Desc: true})
	if len(before) != 1 || before[0].ID != events[0].ID {
		t.Fatalf("before = %+v", before)
	}
	since := list(EventFilter{Since: base.Add(90 * time.Second)})
	if len(since) != 2 {
		t.Fatalf("since = %d", len(since))
	}
	if string(list(EventFilter{Limit: 1})[0].Metadata) != `{"k":"v"}` {
		t.Fatal("metadata not round-tripped")
	}
	n, err := s.PruneEvents(ctx, base.Add(90*time.Second))
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	if c, _ := s.CountEvents(ctx, ""); c != 2 {
		t.Fatalf("count after prune = %d", c)
	}
	if c, _ := s.CountEvents(ctx, "deny"); c != 1 {
		t.Fatalf("deny count = %d", c)
	}
}

func TestEventsInjectionSafe(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.InsertEvents(ctx, []Event{ev("s1", "network", "allow", "a", time.Now())}); err != nil {
		t.Fatal(err)
	}
	out, err := s.ListEvents(ctx, EventFilter{SessionID: "x' OR '1'='1", Query: "'; DROP TABLE events;--"})
	if err != nil || len(out) != 0 {
		t.Fatalf("got %v, %v", out, err)
	}
	if c, _ := s.CountEvents(ctx, ""); c != 1 {
		t.Fatal("events table affected")
	}
}

func TestPoliciesVersioningAndHistory(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if _, err := s.GetPolicy(ctx, "global"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	v1, err := s.PutPolicy(ctx, "global", []byte(`{"network":{"allow":["a.com:443"]}}`), "alice")
	if err != nil || v1 != 1 {
		t.Fatalf("v1 = %d, %v", v1, err)
	}
	v2, _ := s.PutPolicy(ctx, "global", []byte(`{}`), "bob")
	if v2 != 2 {
		t.Fatalf("v2 = %d", v2)
	}
	if _, err := s.PutPolicy(ctx, "agent:hermes", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPolicy(ctx, "global", []byte(`not json`), ""); err == nil {
		t.Fatal("invalid JSON must be rejected")
	}
	cur, _ := s.GetPolicy(ctx, "global")
	if cur.Version != 2 || string(cur.RuleJSON) != `{}` {
		t.Fatalf("current = %+v", cur)
	}
	hist, _ := s.PolicyHistory(ctx, "global", 0)
	if len(hist) != 2 || hist[0].Version != 2 || hist[0].Actor != "bob" || hist[1].Actor != "alice" {
		t.Fatalf("history = %+v", hist)
	}
	list, _ := s.ListPolicies(ctx)
	if len(list) != 2 {
		t.Fatalf("list = %d", len(list))
	}
}

func TestApprovals(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	exp := time.Now().Add(time.Minute)
	a, err := s.CreateApproval(ctx, Approval{RequestID: "r1", SessionID: "s1", Kind: "network", Subject: "x.com:443", ExpiresAt: &exp})
	if err != nil || a.Status != ApprovalPending {
		t.Fatalf("create = %+v, %v", a, err)
	}
	dup, _ := s.CreateApproval(ctx, Approval{RequestID: "r1", SessionID: "s1", Kind: "network", Subject: "different"})
	if dup.ID != a.ID || dup.Subject != "x.com:443" {
		t.Fatalf("duplicate request must be idempotent: %+v", dup)
	}
	if p, _ := s.ListPendingApprovals(ctx, 0); len(p) != 1 {
		t.Fatalf("pending = %d", len(p))
	}
	if _, err := s.DecideApproval(ctx, "r1", "bogus", "u", time.Time{}); err == nil {
		t.Fatal("invalid decision must be rejected")
	}
	d, err := s.DecideApproval(ctx, "r1", DecisionOnce, "alice", time.Time{})
	if err != nil || d.Status != ApprovalDecided || d.Decision != DecisionOnce || d.DecidedAt == nil {
		t.Fatalf("decide = %+v, %v", d, err)
	}
	if _, err := s.DecideApproval(ctx, "r1", DecisionDeny, "mallory", time.Time{}); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("want ErrAlreadyDecided, got %v", err)
	}
	if _, err := s.DecideApproval(ctx, "nope", DecisionOnce, "u", time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	past := time.Now().Add(-time.Second)
	if _, err := s.CreateApproval(ctx, Approval{RequestID: "r2", SessionID: "s1", Kind: "mcp", Subject: "gh/tool", ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideApproval(ctx, "r2", DecisionOnce, "u", time.Time{}); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("expired approval must not be decidable, got %v", err)
	}
	if n, _ := s.ExpireApprovals(ctx, time.Now()); n != 1 {
		t.Fatalf("expired = %d", n)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if _, err := s.GetSetting(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("want ErrNotFound")
	}
	_ = s.SetSetting(ctx, "k", "1")
	_ = s.SetSetting(ctx, "k", "2")
	if v, _ := s.GetSetting(ctx, "k"); v != "2" {
		t.Fatalf("v = %q", v)
	}
	if all, _ := s.AllSettings(ctx); len(all) != 1 {
		t.Fatalf("all = %v", all)
	}
}

// Policies and audit history must survive a restart (acceptance criterion).
func TestPersistenceAcrossReopen(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	_, _ = s.PutPolicy(ctx, "global", []byte(`{"network":{"allow":["a.com:443"]}}`), "t")
	_ = s.InsertEvents(ctx, []Event{ev("s1", "network", "deny", "x", time.Now())})
	_ = s.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if p, err := s2.GetPolicy(ctx, "global"); err != nil || p.Version != 1 {
		t.Fatalf("policy lost: %+v %v", p, err)
	}
	if n, _ := s2.CountEvents(ctx, ""); n != 1 {
		t.Fatalf("events lost: %d", n)
	}
}

func TestConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		go func() {
			var err error
			for i := 0; i < 25 && err == nil; i++ {
				err = s.InsertEvents(ctx, []Event{ev("s", "network", "allow", "d", time.Now())})
			}
			errs <- err
		}()
	}
	for g := 0; g < 8; g++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := s.CountEvents(ctx, ""); n != 200 {
		t.Fatalf("count = %d", n)
	}
}
