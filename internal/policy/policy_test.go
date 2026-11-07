package policy

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, src)
	}
	return p
}

func mustSet(t *testing.T, e *Engine, scope string, ver int, src string) {
	t.Helper()
	if err := e.Set(scope, ver, mustParse(t, src)); err != nil {
		t.Fatalf("Set(%s): %v", scope, err)
	}
}

func TestParseExample(t *testing.T) {
	p := mustParse(t, `
agent: hermes
workspace: {path: ./project, mode: read-write}
network:
  default: deny
  allow: [api.openai.com:443, ollama.internal:11434]
mcp:
  github:
    allow_tools: [get_file_contents, list_issues]
    deny_tools: [delete_repository]
audit: {enabled: true, redact_secrets: true}
`)
	if p.Agent != "hermes" || len(p.Network.Allow) != 2 || p.MCP["github"].DenyTools[0] != "delete_repository" {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if !p.Audit.RedactSecretsEnabled() || !p.Audit.AuditEnabled() {
		t.Fatal("audit flags should be enabled")
	}
}

func TestParseJSON(t *testing.T) {
	p := mustParse(t, `{"network":{"allow":["example.com:443"]}}`)
	if len(p.Network.Allow) != 1 {
		t.Fatalf("got %+v", p)
	}
}

func TestParseEmpty(t *testing.T) {
	p := mustParse(t, ``)
	if len(p.Network.Allow) != 0 {
		t.Fatal("empty policy should have no rules")
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field":      "bogus: 1",
		"unknown nested":     "network:\n  allowed: [a.com:1]",
		"default allow":      "network:\n  default: allow",
		"no port":            "network:\n  allow: [example.com]",
		"bad port":           "network:\n  allow: [example.com:99999]",
		"zero port":          "network:\n  allow: [example.com:0]",
		"reversed range":     "network:\n  allow: [example.com:90-80]",
		"bare wildcard":      "network:\n  allow: ['*:443']",
		"mid wildcard":       "network:\n  allow: ['a.*.com:443']",
		"unbracketed ipv6":   "network:\n  allow: ['::1:443']",
		"bad cidr":           "network:\n  allow: ['10.0.0.0/99:443']",
		"non ascii domain":   "network:\n  allow: ['bücher.de:443']",
		"empty label":        "network:\n  allow: ['a..com:443']",
		"bad tool pattern":   "mcp:\n  s:\n    allow_tools: ['bad tool']",
		"bad server name":    "mcp:\n  'a b':\n    allow_tools: [x]",
		"bad mode":           "workspace: {path: x, mode: rw}",
		"missing ws path":    "workspace: {mode: read-only}",
		"multiple docs":      "agent: a\n---\nagent: b",
		"bad agent":          "agent: 'Bad Agent'",
		"wrong type":         "network: [a]",
		"oversize":           strings.Repeat("#", MaxPolicyBytes+1),
		"too many entries":   "network:\n  allow: [" + strings.Repeat("a.com:1,", maxListEntries+1) + "]",
		"zone":               "network:\n  allow: ['[fe80::1%eth0]:443']",
		"unterminated brack": "network:\n  allow: ['[::1:443']",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNetworkMatching(t *testing.T) {
	e := NewEngine()
	mustSet(t, e, ScopeGlobal, 1, `
network:
  allow:
    - api.openai.com:443
    - "*.github.com:443"
    - 8.8.8.8:53
    - "10.1.0.0/16:8000-9000"
    - "[2001:db8::1]:443"
    - "[fd00::/8]:*"
    - ollama.internal:11434
`)
	s := Subject{}
	tests := []struct {
		host string
		port int
		want Effect
	}{
		{"api.openai.com", 443, Allow},
		{"API.OpenAI.com.", 443, Allow}, // case and trailing dot normalized
		{"api.openai.com", 80, Deny},
		{"evilapi.openai.com", 443, Deny},
		{"openai.com", 443, Deny},
		{"api.github.com", 443, Allow},
		{"a.b.github.com", 443, Allow},
		{"github.com", 443, Deny}, // wildcard does not match apex
		{"notgithub.com", 443, Deny},
		{"8.8.8.8", 53, Allow},
		{"8.8.8.9", 53, Deny},
		{"10.1.2.3", 8500, Allow},
		{"10.1.2.3", 7999, Deny},
		{"10.2.0.1", 8500, Deny},
		{"::ffff:10.1.2.3", 8500, Allow}, // IPv4-mapped normalized
		{"2001:db8::1", 443, Allow},
		{"[2001:db8::1]", 443, Allow},
		{"2001:db8::2", 443, Deny},
		{"fd12::1", 1234, Allow},
		{"fe80::1", 1234, Deny},
		{"api.openai.com", 0, Deny},
		{"api.openai.com", 70000, Deny},
		{"", 443, Deny},
		{"ollama.internal", 11434, Allow},
	}
	for _, tc := range tests {
		got := e.EvaluateNetwork(s, tc.host, tc.port)
		if got.Effect != tc.want {
			t.Errorf("%s:%d = %s (%s), want %s", tc.host, tc.port, got.Effect, got.RuleID, tc.want)
		}
	}
}

func TestNetworkRuleIDsAndVersion(t *testing.T) {
	e := NewEngine()
	mustSet(t, e, ScopeGlobal, 3, "network:\n  allow: [a.com:443, b.com:443]")
	d := e.EvaluateNetwork(Subject{}, "b.com", 443)
	if d.RuleID != "global#network.allow[1]" || d.PolicyVersion != "global@3" || !d.Allowed() {
		t.Fatalf("got %+v", d)
	}
	d = e.EvaluateNetwork(Subject{}, "c.com", 443)
	if d.RuleID != RuleDefaultDeny || d.Allowed() {
		t.Fatalf("got %+v", d)
	}
}

func TestDefaultDenyWithoutPolicies(t *testing.T) {
	e := NewEngine()
	if d := e.EvaluateNetwork(Subject{Agent: "hermes"}, "example.com", 443); d.Allowed() || d.PolicyVersion != "none" {
		t.Fatalf("got %+v", d)
	}
	if d := e.EvaluateMCPTool(Subject{}, "github", "list_issues"); d.Allowed() {
		t.Fatalf("got %+v", d)
	}
}

func TestScopeInheritanceAndDenyPrecedence(t *testing.T) {
	e := NewEngine()
	mustSet(t, e, ScopeGlobal, 1, "network:\n  allow: [llm.example.com:443]\n  deny: ['*.evil.com:*']")
	mustSet(t, e, AgentScope("hermes"), 2, "network:\n  allow: [pypi.org:443, x.evil.com:443]")
	mustSet(t, e, SessionScope("s1"), 4, "network:\n  allow: [temp.example.com:443]\n  deny: [pypi.org:443]")

	hermes := Subject{Agent: "hermes", Session: "s1"}
	other := Subject{Agent: "codex", Session: "s2"}

	if d := e.EvaluateNetwork(hermes, "llm.example.com", 443); !d.Allowed() || d.PolicyVersion != "global@1,agent:hermes@2,session:s1@4" {
		t.Fatalf("global allow inherited: %+v", d)
	}
	if d := e.EvaluateNetwork(hermes, "temp.example.com", 443); !d.Allowed() {
		t.Fatalf("session allow: %+v", d)
	}
	// Narrower-scope allow cannot override a deny in a broader scope.
	if d := e.EvaluateNetwork(hermes, "x.evil.com", 443); d.Allowed() || d.RuleID != "global#network.deny[0]" {
		t.Fatalf("global deny must win: %+v", d)
	}
	// Narrower-scope deny overrides broader-scope allow.
	if d := e.EvaluateNetwork(hermes, "pypi.org", 443); d.Allowed() || d.RuleID != "session:s1#network.deny[0]" {
		t.Fatalf("session deny must win: %+v", d)
	}
	// Other agents/sessions do not see hermes/session rules.
	if d := e.EvaluateNetwork(other, "pypi.org", 443); d.Allowed() {
		t.Fatalf("agent scope leaked: %+v", d)
	}
	if d := e.EvaluateNetwork(other, "llm.example.com", 443); !d.Allowed() || d.PolicyVersion != "global@1" {
		t.Fatalf("global should apply to everyone: %+v", d)
	}
}

func TestMCPEvaluation(t *testing.T) {
	e := NewEngine()
	mustSet(t, e, ScopeGlobal, 1, `
mcp:
  github:
    allow_tools: [get_file_contents, list_*]
    deny_tools: [delete_repository, "list_secrets*"]
  empty: {}
`)
	s := Subject{}
	tests := []struct {
		server, tool string
		want         Effect
		rule         string
	}{
		{"github", "get_file_contents", Allow, "global#mcp.github.allow_tools[0]"},
		{"github", "list_issues", Allow, "global#mcp.github.allow_tools[1]"},
		{"github", "delete_repository", Deny, "global#mcp.github.deny_tools[0]"},
		{"github", "list_secrets_all", Deny, "global#mcp.github.deny_tools[1]"}, // deny beats allow glob
		{"github", "create_issue", Deny, RuleDefaultDeny},
		{"github", "GET_FILE_CONTENTS", Deny, RuleDefaultDeny}, // case-sensitive
		{"empty", "anything", Deny, RuleDefaultDeny},
		{"unknown", "get_file_contents", Deny, RuleDefaultDeny},
		{"", "x", Deny, RuleInvalid},
		{"github", "", Deny, RuleInvalid},
	}
	for _, tc := range tests {
		d := e.EvaluateMCPTool(s, tc.server, tc.tool)
		if d.Effect != tc.want || d.RuleID != tc.rule {
			t.Errorf("%s/%s = %s %s, want %s %s", tc.server, tc.tool, d.Effect, d.RuleID, tc.want, tc.rule)
		}
	}
}

func TestLiveUpdateAndRemove(t *testing.T) {
	e := NewEngine()
	mustSet(t, e, ScopeGlobal, 1, "network:\n  allow: [a.com:443]")
	if !e.EvaluateNetwork(Subject{}, "a.com", 443).Allowed() {
		t.Fatal("want allow")
	}
	mustSet(t, e, ScopeGlobal, 2, "network:\n  allow: [b.com:443]")
	if e.EvaluateNetwork(Subject{}, "a.com", 443).Allowed() || !e.EvaluateNetwork(Subject{}, "b.com", 443).Allowed() {
		t.Fatal("update not applied")
	}
	e.Remove(ScopeGlobal)
	if e.EvaluateNetwork(Subject{}, "b.com", 443).Allowed() {
		t.Fatal("remove not applied")
	}
}

func TestSetRejectsInvalid(t *testing.T) {
	e := NewEngine()
	if err := e.Set("bogus", 1, &Policy{}); err == nil {
		t.Fatal("expected invalid scope error")
	}
	if err := e.Set("agent:Bad Name", 1, &Policy{}); err == nil {
		t.Fatal("expected invalid agent scope error")
	}
	bad := &Policy{Network: Network{Allow: []string{"nope"}}}
	if err := e.Set(ScopeGlobal, 1, bad); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		p, s string
		want bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"*", "", true},
		{"*", "anything", true},
		{"a*", "abc", true},
		{"*c", "abc", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "ab", false},
		{"a**c", "abbc", true},
		{"*a*b*", "xxaxxbxx", true},
		{"*a*b*", "xxbxxaxx", false},
		{"list_*", "list_", true},
		{"list_*", "list", false},
	}
	for _, tc := range tests {
		if got := globMatch(tc.p, tc.s); got != tc.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", tc.p, tc.s, got, tc.want)
		}
	}
}

func TestConcurrentEvaluateAndUpdate(t *testing.T) {
	e := NewEngine()
	mustSet(t, e, ScopeGlobal, 1, "network:\n  allow: [a.com:443]")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = e.Set(ScopeGlobal, i+2, &Policy{Network: Network{Allow: []string{"a.com:443"}}})
		}
	}()
	for i := 0; i < 2000; i++ {
		if !e.EvaluateNetwork(Subject{}, "a.com", 443).Allowed() {
			t.Fatal("decision flickered during update")
		}
	}
	<-done
}

func FuzzParse(f *testing.F) {
	f.Add("network:\n  allow: [a.com:443]")
	f.Add("mcp:\n  s:\n    allow_tools: [x*]")
	f.Add(`{"network":{"deny":["[::1]:1-2"]}}`)
	f.Fuzz(func(t *testing.T, src string) {
		p, err := Parse([]byte(src))
		if err != nil {
			return
		}
		e := NewEngine()
		if err := e.Set(ScopeGlobal, 1, p); err != nil {
			t.Fatalf("parsed policy rejected by engine: %v", err)
		}
		e.EvaluateNetwork(Subject{}, "a.com", 443)
		e.EvaluateMCPTool(Subject{}, "s", "x")
	})
}

func FuzzDestRule(f *testing.F) {
	f.Add("a.com:443", "a.com", 443)
	f.Add("[::1]:*", "::1", 1)
	f.Add("10.0.0.0/8:1-5", "10.1.1.1", 3)
	f.Fuzz(func(t *testing.T, rule, host string, port int) {
		r, err := parseDestRule(rule)
		if err != nil {
			return
		}
		r.matches(host, port)
	})
}

func FuzzGlob(f *testing.F) {
	f.Add("a*b", "aXb")
	f.Fuzz(func(t *testing.T, p, s string) {
		if len(p) > 64 || len(s) > 256 {
			return
		}
		globMatch(p, s)
	})
}
