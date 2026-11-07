package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Effect is the outcome of a policy evaluation.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Scope names. Evaluation order is global, agent, session.
const (
	ScopeGlobal = "global"

	scopeAgentPrefix   = "agent:"
	scopeSessionPrefix = "session:"

	// RuleDefaultDeny is the rule ID reported when nothing matched.
	RuleDefaultDeny = "default-deny"
	// RuleInvalid is reported for malformed evaluation input.
	RuleInvalid = "invalid-request"
)

var (
	agentNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sessionIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	errInvalidScp = fmt.Errorf("invalid scope")
)

// AgentScope returns the scope name for an agent policy.
func AgentScope(agent string) string { return scopeAgentPrefix + agent }

// SessionScope returns the scope name for a session policy.
func SessionScope(id string) string { return scopeSessionPrefix + id }

// ValidScope reports whether s is "global", "agent:<name>" or "session:<id>".
func ValidScope(s string) bool {
	switch {
	case s == ScopeGlobal:
		return true
	case strings.HasPrefix(s, scopeAgentPrefix):
		return agentNameRe.MatchString(s[len(scopeAgentPrefix):])
	case strings.HasPrefix(s, scopeSessionPrefix):
		return sessionIDRe.MatchString(s[len(scopeSessionPrefix):])
	}
	return false
}

// Subject identifies who a decision is for.
type Subject struct {
	Agent   string
	Session string
}

// Decision is the result of evaluating a request. Every decision carries the
// rule that produced it and the policy versions in force, for auditing.
type Decision struct {
	Effect        Effect `json:"effect"`
	RuleID        string `json:"rule_id"`
	PolicyVersion string `json:"policy_version"`
	Reason        string `json:"reason,omitempty"`
}

// Allowed reports whether the decision permits the operation.
func (d Decision) Allowed() bool { return d.Effect == Allow }

type mcpRules struct {
	allow []string
	deny  []string
}

type compiled struct {
	scope    string
	version  int
	netAllow []destRule
	netDeny  []destRule
	mcp      map[string]mcpRules
}

// Engine evaluates decisions against a set of scoped policies. It is safe for
// concurrent use; updates are applied atomically and affect only new
// evaluations.
type Engine struct {
	mu   sync.Mutex // serializes writers
	snap atomic.Pointer[map[string]*compiled]
}

// NewEngine returns an engine with no policies (everything is denied).
func NewEngine() *Engine {
	e := &Engine{}
	m := map[string]*compiled{}
	e.snap.Store(&m)
	return e
}

// Set compiles and installs the policy for scope at the given version.
func (e *Engine) Set(scope string, version int, p *Policy) error {
	if !ValidScope(scope) {
		return fmt.Errorf("%w %q", errInvalidScp, scope)
	}
	if p == nil {
		p = &Policy{}
	}
	if err := p.Validate(); err != nil {
		return err
	}
	c := &compiled{scope: scope, version: version, mcp: map[string]mcpRules{}}
	for _, s := range p.Network.Allow {
		r, _ := parseDestRule(s) // validated above
		c.netAllow = append(c.netAllow, r)
	}
	for _, s := range p.Network.Deny {
		r, _ := parseDestRule(s)
		c.netDeny = append(c.netDeny, r)
	}
	for name, srv := range p.MCP {
		c.mcp[name] = mcpRules{allow: append([]string(nil), srv.AllowTools...), deny: append([]string(nil), srv.DenyTools...)}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	next := e.cloneLocked()
	next[scope] = c
	e.snap.Store(&next)
	return nil
}

// Remove deletes the policy for scope, if present.
func (e *Engine) Remove(scope string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := e.cloneLocked()
	delete(next, scope)
	e.snap.Store(&next)
}

func (e *Engine) cloneLocked() map[string]*compiled {
	cur := *e.snap.Load()
	next := make(map[string]*compiled, len(cur)+1)
	for k, v := range cur {
		next[k] = v
	}
	return next
}

// effective returns the policies applying to s in evaluation order.
func (e *Engine) effective(s Subject) []*compiled {
	snap := *e.snap.Load()
	var out []*compiled
	if c := snap[ScopeGlobal]; c != nil {
		out = append(out, c)
	}
	if s.Agent != "" {
		if c := snap[AgentScope(s.Agent)]; c != nil {
			out = append(out, c)
		}
	}
	if s.Session != "" {
		if c := snap[SessionScope(s.Session)]; c != nil {
			out = append(out, c)
		}
	}
	return out
}

func versionString(cs []*compiled) string {
	if len(cs) == 0 {
		return "none"
	}
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.scope + "@" + strconv.Itoa(c.version)
	}
	return strings.Join(parts, ",")
}

// EvaluateNetwork decides whether the subject may connect to host:port.
// Deny rules in any scope take precedence over allow rules in any scope;
// anything not explicitly allowed is denied.
func (e *Engine) EvaluateNetwork(s Subject, host string, port int) Decision {
	cs := e.effective(s)
	ver := versionString(cs)
	if host == "" || port < 1 || port > 65535 {
		return Decision{Effect: Deny, RuleID: RuleInvalid, PolicyVersion: ver, Reason: "invalid destination"}
	}
	for _, c := range cs {
		for i, r := range c.netDeny {
			if r.matches(host, port) {
				return Decision{Effect: Deny, RuleID: fmt.Sprintf("%s#network.deny[%d]", c.scope, i), PolicyVersion: ver, Reason: "denied by rule"}
			}
		}
	}
	for _, c := range cs {
		for i, r := range c.netAllow {
			if r.matches(host, port) {
				return Decision{Effect: Allow, RuleID: fmt.Sprintf("%s#network.allow[%d]", c.scope, i), PolicyVersion: ver}
			}
		}
	}
	return Decision{Effect: Deny, RuleID: RuleDefaultDeny, PolicyVersion: ver, Reason: "no matching allow rule"}
}

// EvaluateMCPTool decides whether the subject may call tool on the named MCP
// server. A server or tool not explicitly allowed is denied.
func (e *Engine) EvaluateMCPTool(s Subject, server, tool string) Decision {
	cs := e.effective(s)
	ver := versionString(cs)
	if server == "" || tool == "" {
		return Decision{Effect: Deny, RuleID: RuleInvalid, PolicyVersion: ver, Reason: "invalid mcp request"}
	}
	for _, c := range cs {
		for i, pat := range c.mcp[server].deny {
			if globMatch(pat, tool) {
				return Decision{Effect: Deny, RuleID: fmt.Sprintf("%s#mcp.%s.deny_tools[%d]", c.scope, server, i), PolicyVersion: ver, Reason: "denied by rule"}
			}
		}
	}
	for _, c := range cs {
		for i, pat := range c.mcp[server].allow {
			if globMatch(pat, tool) {
				return Decision{Effect: Allow, RuleID: fmt.Sprintf("%s#mcp.%s.allow_tools[%d]", c.scope, server, i), PolicyVersion: ver}
			}
		}
	}
	return Decision{Effect: Deny, RuleID: RuleDefaultDeny, PolicyVersion: ver, Reason: "no matching allow rule"}
}
