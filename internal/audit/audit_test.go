package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRedactString(t *testing.T) {
	r := Redactor{}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	secrets := map[string]string{
		"bearer":       "Authorization: Bearer abcdef1234567890xyz",
		"openai key":   "key is sk-abcdefghijklmnopqrstuvwx",
		"anthropic":    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
		"github pat":   "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"github fine":  "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwxyz",
		"aws":          "AKIAIOSFODNN7EXAMPLE",
		"slack":        "xoxb-123456789012-abcdefghij",
		"jwt":          "token " + jwt,
		"url userinfo": "https://user:hunter2hunter@example.com/path",
		"query token":  "https://example.com/cb?access_token=abc123def456&x=1",
		"env assign":   "OPENAI_API_KEY=abc123456789",
		"pem":          "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabcd\n-----END RSA PRIVATE KEY-----",
		"unterminated": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq",
	}
	needles := map[string]string{
		"bearer": "abcdef1234567890xyz", "openai key": "abcdefghijklmnopqrstuvwx", "anthropic": "abcdefghijklmnopqrstuvwxyz",
		"github pat": "abcdefghijklmnopqrstuvwxyz0123456789", "github fine": "abcdefghijklmnop", "aws": "IOSFODNN7EXAMPLE",
		"slack": "abcdefghij", "jwt": "dBjftJeZ4CVPmB92K27", "url userinfo": "hunter2hunter", "query token": "abc123def456",
		"env assign": "abc123456789", "pem": "MIIEow", "unterminated": "MIIEvQIBADANBgkq",
	}
	for name, in := range secrets {
		out := r.String(in)
		if strings.Contains(out, needles[name]) {
			t.Errorf("%s: secret leaked: %q", name, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s: no redaction marker: %q", name, out)
		}
	}
	// Ordinary text must be preserved.
	for _, in := range []string{"api.openai.com:443", "CONNECT", "github/list_issues", "tokenizer is fine", "monkey business"} {
		if got := r.String(in); got != in {
			t.Errorf("benign %q changed to %q", in, got)
		}
	}
}

func TestRedactMetadataKeysAndContent(t *testing.T) {
	r := Redactor{}
	meta := map[string]any{
		"direction":      "outbound",
		"Authorization":  "Bearer short",
		"x-api-key":      "abc",
		"Mcp-Session-Id": "sess123",
		"password":       "p",
		"client_secret":  "s",
		"prompt":         "summarize my private notes",
		"arguments": map[string]any{
			"path":    "/work/a.txt",
			"content": "file body here",
			"token":   "t",
			"nested":  []any{"ok", map[string]any{"api_key": "k"}},
		},
		"latency_ms": 12,
		"long":       strings.Repeat("a", 5000),
	}
	var got map[string]any
	if err := json.Unmarshal(r.Metadata(meta), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"Authorization", "x-api-key", "Mcp-Session-Id", "password", "client_secret"} {
		if got[k] != Redacted {
			t.Errorf("%s = %v, want redacted", k, got[k])
		}
	}
	if got["prompt"] != Omitted {
		t.Errorf("prompt = %v, want omitted", got["prompt"])
	}
	if got["direction"] != "outbound" || got["latency_ms"] != float64(12) {
		t.Errorf("benign fields altered: %v", got)
	}
	args := got["arguments"].(map[string]any)
	if args["content"] != Omitted || args["token"] != Redacted || args["path"] != "/work/a.txt" {
		t.Errorf("arguments = %v", args)
	}
	nested := args["nested"].([]any)[1].(map[string]any)
	if nested["api_key"] != Redacted {
		t.Errorf("nested = %v", nested)
	}
	if l := got["long"].(string); len(l) > 600 || !strings.HasSuffix(l, "[truncated]") {
		t.Errorf("long string not truncated: len=%d", len(l))
	}

	opt := Redactor{IncludeContent: true}
	var got2 map[string]any
	_ = json.Unmarshal(opt.Metadata(meta), &got2)
	if got2["prompt"] != "summarize my private notes" || got2["Authorization"] != Redacted {
		t.Errorf("IncludeContent must keep content but still redact secrets: %v", got2)
	}
}

func TestRedactLimits(t *testing.T) {
	r := Redactor{MaxBytes: 200}
	big := map[string]any{}
	for i := 0; i < 50; i++ {
		big[strings.Repeat("k", i+1)] = "value value value"
	}
	var got map[string]any
	_ = json.Unmarshal(r.Metadata(big), &got)
	if got["truncated"] != true {
		t.Errorf("oversized metadata not capped: %v", got)
	}
	deep := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": map[string]any{"f": map[string]any{"g": "x"}}}}}}}
	if s := string(Redactor{}.Metadata(deep)); !strings.Contains(s, "TRUNCATED_DEPTH") {
		t.Errorf("depth not limited: %s", s)
	}
	if s := string(Redactor{}.Metadata(nil)); s != "{}" {
		t.Errorf("nil metadata = %s", s)
	}
	if s := string(Redactor{}.Metadata(map[string]any{"c": make(chan int)})); !strings.Contains(s, "unencodable") {
		t.Errorf("unencodable = %s", s)
	}
	// UTF-8 safe truncation.
	out := Redactor{MaxString: 5}.String("héllo wörld")
	if !strings.HasPrefix(out, "héll") || strings.ContainsRune(out, '\uFFFD') {
		t.Errorf("bad truncation: %q", out)
	}
}

func TestLoggerPersistsRedactedAndPublishes(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	l := NewLogger(st, Options{FlushInterval: 10 * time.Millisecond})
	defer l.Close(ctx)

	sub, cancel := l.Subscribe(8, func(e store.Event) bool { return e.Decision == DecisionDeny })
	defer cancel()

	_ = l.Log(Entry{SessionID: "s1", Kind: KindNetwork, Destination: "a.com:443", Decision: DecisionAllow, RuleID: "r1"})
	if err := l.Log(Entry{
		SessionID: "s1", Kind: KindMCP, Destination: "github", Operation: "tools/call delete_repository", Decision: DecisionDeny,
		RuleID: "global#mcp.github.deny_tools[0]", PolicyVersion: "global@1",
		Metadata: map[string]any{"authorization": "Bearer abcdefgh12345678", "arguments": map[string]any{"repo": "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	events, _ := st.ListEvents(ctx, store.EventFilter{})
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	if strings.Contains(string(events[1].Metadata), "abcdefgh12345678") {
		t.Fatalf("secret persisted: %s", events[1].Metadata)
	}
	select {
	case e := <-sub:
		if e.ID == 0 || e.Decision != DecisionDeny || e.RuleID == "" {
			t.Fatalf("published = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no live event")
	}
	select {
	case e := <-sub:
		t.Fatalf("filter leaked %+v", e)
	default:
	}
	if st := l.Stats(); st.Written != 2 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestLoggerBatchesBySize(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	l := NewLogger(st, Options{BatchSize: 5, FlushInterval: time.Hour})
	defer l.Close(ctx)
	for i := 0; i < 5; i++ {
		_ = l.Log(Entry{SessionID: "s", Kind: KindNetwork, Decision: DecisionAllow})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := st.CountEvents(ctx, ""); n == 5 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("full batch was not flushed without waiting for the interval")
}

func TestLoggerQueueFullFailsClosed(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	// Tiny queue and a long interval so nothing drains while we fill it.
	l := NewLogger(st, Options{QueueSize: 2, BatchSize: 1000, FlushInterval: time.Hour})
	var sawFull bool
	for i := 0; i < 5000 && !sawFull; i++ {
		if err := l.Log(Entry{SessionID: "s", Kind: KindNetwork, Decision: DecisionAllow}); errors.Is(err, ErrQueueFull) {
			sawFull = true
		}
	}
	if !sawFull {
		t.Fatal("Log never reported a full queue")
	}
	if l.Stats().QueueFull == 0 {
		t.Fatal("QueueFull counter not incremented")
	}
	_ = l.Close(ctx)
}

func TestLoggerCloseDrainsAndRejects(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	l := NewLogger(st, Options{FlushInterval: time.Hour})
	sub, _ := l.Subscribe(4, nil)
	for i := 0; i < 20; i++ {
		_ = l.Log(Entry{SessionID: "s", Kind: KindNetwork, Decision: DecisionAllow})
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountEvents(ctx, ""); n != 20 {
		t.Fatalf("Close lost events: %d", n)
	}
	if err := l.Log(Entry{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	if err := l.Flush(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	for range sub { // channel must be closed
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal("second Close must be a no-op")
	}
}

func TestLoggerSlowSubscriberDoesNotBlock(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	l := NewLogger(st, Options{FlushInterval: time.Hour})
	defer l.Close(ctx)
	_, cancel := l.Subscribe(1, nil) // never read
	defer cancel()
	for i := 0; i < 10; i++ {
		_ = l.Log(Entry{SessionID: "s", Kind: KindNetwork, Decision: DecisionAllow})
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if l.Stats().SubscriberDrops == 0 {
		t.Fatal("expected subscriber drops")
	}
	if n, _ := st.CountEvents(ctx, ""); n != 10 {
		t.Fatalf("persisted %d", n)
	}
}

func TestLoggerConcurrentUse(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	l := NewLogger(st, Options{FlushInterval: 5 * time.Millisecond})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_ = l.Log(Entry{SessionID: "s", Kind: KindNetwork, Decision: DecisionAllow})
			}
		}()
	}
	wg.Wait()
	_ = l.Close(ctx)
	if n, _ := st.CountEvents(ctx, ""); n != 800 {
		t.Fatalf("persisted %d, want 800", n)
	}
}

func TestIncludeContentToggle(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	l := NewLogger(st, Options{FlushInterval: time.Hour})
	defer l.Close(ctx)
	_ = l.Log(Entry{SessionID: "s", Kind: KindMCP, Decision: DecisionAllow, Metadata: map[string]any{"prompt": "hello"}})
	l.SetIncludeContent(true)
	_ = l.Log(Entry{SessionID: "s", Kind: KindMCP, Decision: DecisionAllow, Metadata: map[string]any{"prompt": "hello"}})
	_ = l.Flush(ctx)
	ev, _ := st.ListEvents(ctx, store.EventFilter{})
	if !strings.Contains(string(ev[0].Metadata), Omitted) || !strings.Contains(string(ev[1].Metadata), "hello") {
		t.Fatalf("toggle not honored: %s / %s", ev[0].Metadata, ev[1].Metadata)
	}
}

func TestExportJSONLAndPrune(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	now := time.Now()
	var evs []store.Event
	for i := 0; i < 1200; i++ {
		evs = append(evs, store.Event{SessionID: "s", Kind: KindNetwork, Decision: DecisionAllow, TS: now.Add(-time.Duration(i) * time.Minute)})
	}
	if err := st.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := ExportJSONL(ctx, st, &buf, store.EventFilter{})
	if err != nil || n != 1200 {
		t.Fatalf("export n=%d err=%v", n, err)
	}
	sc := bufio.NewScanner(&buf)
	var last int64
	lines := 0
	for sc.Scan() {
		var e store.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad JSONL line: %v", err)
		}
		if e.ID <= last {
			t.Fatal("export not ascending by id")
		}
		last = e.ID
		lines++
	}
	if lines != 1200 {
		t.Fatalf("lines = %d", lines)
	}
	buf.Reset()
	if n, _ := ExportJSONL(ctx, st, &buf, store.EventFilter{Limit: 7}); n != 7 {
		t.Fatalf("limited export = %d", n)
	}

	if d, _ := Prune(ctx, st, 0, now); d != 0 {
		t.Fatal("retention 0 must keep everything")
	}
	// 1200 events, one per minute back from now; keep 1 day = last 1440 minutes → all kept.
	if d, _ := Prune(ctx, st, 1, now); d != 0 {
		t.Fatalf("pruned %d", d)
	}
	if d, _ := Prune(ctx, st, 1, now.Add(24*time.Hour)); d == 0 {
		t.Fatal("expected pruning after time passes")
	}
}

func TestRunRetentionStops(t *testing.T) {
	st := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunRetention(ctx, st, 5*time.Millisecond, func() int { return 1 }, nil)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRetention did not stop")
	}
}
