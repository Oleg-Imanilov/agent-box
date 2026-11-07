// Package gwclient is the client the network and MCP gateways use to obtain
// policy decisions from the controller.
//
// It fails closed: any error (timeout, connection refused, bad status,
// malformed response) yields a deny decision. The only "allow" that can be
// returned without contacting the controller is a previously granted allow
// that is still within the cache TTL the controller itself specified.
package gwclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/policy"
)

// Rule IDs reported by the client when it denies on its own.
const (
	RuleControllerUnavailable = "controller-unavailable"
	RuleBadResponse           = "controller-bad-response"
)

const (
	maxResponseBytes = 64 << 10
	maxCacheEntries  = 4096
)

// Decision is the outcome of a decision request.
type Decision struct {
	policy.Decision
	// Cached is true if the decision was served from the local allow cache.
	Cached bool
	// Err is set when the client denied because of a failure.
	Err error
}

// Options configures a Client.
type Options struct {
	// Timeout bounds each request (default 3s).
	Timeout time.Duration
	// ApprovalWait bounds requests that wait for a human decision (default 11m,
	// above the controller's maximum approval timeout).
	ApprovalWait time.Duration
	// HTTPClient overrides the HTTP client for ordinary requests (tests).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Client talks to the controller's /v1/gw endpoints with a session token.
type Client struct {
	base  string
	token string
	hc    *http.Client
	askHC *http.Client
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	d       policy.Decision
	expires time.Time
}

// New creates a client for the controller at baseURL using a session token.
func New(baseURL, token string, opt Options) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("gwclient: invalid controller URL %q", baseURL)
	}
	if token == "" {
		return nil, errors.New("gwclient: empty token")
	}
	hc := opt.HTTPClient
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if hc == nil {
		to := opt.Timeout
		if to <= 0 {
			to = 3 * time.Second
		}
		// A controller response must never redirect the token elsewhere.
		hc = &http.Client{Timeout: to, CheckRedirect: noRedirect}
	}
	wait := opt.ApprovalWait
	if wait <= 0 {
		wait = 11 * time.Minute
	}
	askHC := &http.Client{Timeout: wait, CheckRedirect: noRedirect}
	if opt.HTTPClient != nil {
		askHC = opt.HTTPClient
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	return &Client{base: u.String(), token: token, hc: hc, askHC: askHC, now: now, cache: map[string]cached{}}, nil
}

type decisionBody struct {
	Effect          policy.Effect `json:"effect"`
	RuleID          string        `json:"rule_id"`
	PolicyVersion   string        `json:"policy_version"`
	Reason          string        `json:"reason"`
	CacheTTLSeconds int           `json:"cache_ttl_seconds"`
}

func denyOnError(rule string, err error) Decision {
	return Decision{
		Decision: policy.Decision{Effect: policy.Deny, RuleID: rule, PolicyVersion: "none", Reason: err.Error()},
		Err:      err,
	}
}

// DecideNetwork asks whether host:port may be contacted.
func (c *Client) DecideNetwork(ctx context.Context, host string, port int) Decision {
	key := "net|" + host + "|" + strconv.Itoa(port)
	if d, ok := c.lookup(key); ok {
		return d
	}
	return c.decide(ctx, c.hc, key, "/v1/gw/decide/network", map[string]any{"host": host, "port": port})
}

// DecideNetworkAsk is like DecideNetwork, but if the destination is denied
// only because no rule allows it, the controller asks a human and this call
// blocks until they answer (or the approval times out, which denies).
// requestID must be unique per logical request; use NewRequestID.
func (c *Client) DecideNetworkAsk(ctx context.Context, host string, port int, requestID string) Decision {
	key := "net|" + host + "|" + strconv.Itoa(port)
	if d, ok := c.lookup(key); ok {
		return d
	}
	return c.decide(ctx, c.askHC, key, "/v1/gw/decide/network",
		map[string]any{"host": host, "port": port, "ask": true, "request_id": requestID})
}

// DecideMCP asks whether tool may be called on the named MCP server.
func (c *Client) DecideMCP(ctx context.Context, server, tool string) Decision {
	key := "mcp|" + server + "|" + tool
	if d, ok := c.lookup(key); ok {
		return d
	}
	return c.decide(ctx, c.hc, key, "/v1/gw/decide/mcp", map[string]any{"server": server, "tool": tool})
}

// DecideMCPAsk is the approval-capable variant of DecideMCP.
func (c *Client) DecideMCPAsk(ctx context.Context, server, tool, requestID string) Decision {
	key := "mcp|" + server + "|" + tool
	if d, ok := c.lookup(key); ok {
		return d
	}
	return c.decide(ctx, c.askHC, key, "/v1/gw/decide/mcp",
		map[string]any{"server": server, "tool": tool, "ask": true, "request_id": requestID})
}

// DecideMCPTools evaluates many tool names at once (for tools/list
// filtering). On any error it returns an error and callers must treat every
// tool as denied.
func (c *Client) DecideMCPTools(ctx context.Context, server string, tools []string) (map[string]policy.Decision, error) {
	resp, err := c.post(ctx, c.hc, "/v1/gw/decide/mcp/tools", map[string]any{"server": server, "tools": tools})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return nil, fmt.Errorf("controller returned %d", resp.StatusCode)
	}
	var body struct {
		PolicyVersion string `json:"policy_version"`
		Decisions     []struct {
			Tool   string        `json:"tool"`
			Effect policy.Effect `json:"effect"`
			RuleID string        `json:"rule_id"`
		} `json:"decisions"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*maxResponseBytes)).Decode(&body); err != nil {
		return nil, err
	}
	out := make(map[string]policy.Decision, len(body.Decisions))
	for _, d := range body.Decisions {
		if d.Effect != policy.Allow && d.Effect != policy.Deny {
			return nil, fmt.Errorf("unknown effect %q", d.Effect)
		}
		out[d.Tool] = policy.Decision{Effect: d.Effect, RuleID: d.RuleID, PolicyVersion: body.PolicyVersion}
	}
	return out, nil
}

// NewRequestID returns a random identifier for approval requests.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("gwclient: entropy unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Event is an additional audit record a gateway can report.
type Event struct {
	Kind          string         `json:"kind"`
	Destination   string         `json:"destination,omitempty"`
	Operation     string         `json:"operation,omitempty"`
	Decision      string         `json:"decision"`
	RuleID        string         `json:"rule_id,omitempty"`
	PolicyVersion string         `json:"policy_version,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// ReportEvent sends an audit event. Callers should treat an error as "audit
// unavailable" and, for enforcement events, deny.
func (c *Client) ReportEvent(ctx context.Context, e Event) error {
	resp, err := c.post(ctx, c.hc, "/v1/gw/events", e)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("controller returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) post(ctx context.Context, hc *http.Client, path string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return hc.Do(req)
}

func (c *Client) decide(ctx context.Context, hc *http.Client, key, path string, body any) Decision {
	resp, err := c.post(ctx, hc, path, body)
	if err != nil {
		return denyOnError(RuleControllerUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return denyOnError(RuleControllerUnavailable, fmt.Errorf("controller returned %d", resp.StatusCode))
	}
	var db decisionBody
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := dec.Decode(&db); err != nil {
		return denyOnError(RuleBadResponse, err)
	}
	if db.Effect != policy.Allow && db.Effect != policy.Deny {
		return denyOnError(RuleBadResponse, fmt.Errorf("unknown effect %q", db.Effect))
	}
	d := policy.Decision{Effect: db.Effect, RuleID: db.RuleID, PolicyVersion: db.PolicyVersion, Reason: db.Reason}
	if d.Effect == policy.Allow && db.CacheTTLSeconds > 0 {
		c.store(key, d, time.Duration(db.CacheTTLSeconds)*time.Second)
	}
	return Decision{Decision: d}
}

func (c *Client) lookup(key string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok {
		return Decision{}, false
	}
	if !c.now().Before(e.expires) {
		delete(c.cache, key)
		return Decision{}, false
	}
	return Decision{Decision: e.d, Cached: true}, true
}

func (c *Client) store(key string, d policy.Decision, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= maxCacheEntries {
		c.cache = map[string]cached{}
	}
	c.cache[key] = cached{d: d, expires: c.now().Add(ttl)}
}
