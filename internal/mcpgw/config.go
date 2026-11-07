package mcpgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
)

// Controller is the part of the controller API the gateway uses.
// *gwclient.Client implements it.
type Controller interface {
	DecideMCP(ctx context.Context, server, tool string) gwclient.Decision
	DecideMCPAsk(ctx context.Context, server, tool, requestID string) gwclient.Decision
	DecideMCPTools(ctx context.Context, server string, tools []string) (map[string]policy.Decision, error)
	ReportEvent(ctx context.Context, e gwclient.Event) error
}

// Server describes one upstream MCP server (a remote MCP endpoint, or the
// Streamable HTTP endpoint of a stdio bridge sidecar).
type Server struct {
	// Name is the route name (/mcp/<name>) and the server name used in policy.
	Name string `json:"name"`
	// URL is the upstream MCP endpoint.
	URL string `json:"url"`
	// BearerFile holds an upstream bearer token (read on use, so it can rotate).
	BearerFile string `json:"bearer_file,omitempty"`
	// Headers are extra static headers sent upstream (never from the agent).
	Headers map[string]string `json:"headers,omitempty"`
	// AllowMethods lists additional request methods to forward (for example
	// "resources/list"). By default only the core methods are forwarded.
	AllowMethods []string `json:"allow_methods,omitempty"`
}

// Config configures a Gateway.
type Config struct {
	Controller Controller
	Servers    []Server
	// Approvals makes denied-by-default tool calls wait for a human decision.
	Approvals bool
	// AllowedHosts, if set, restricts the Host header (DNS-rebinding defense).
	AllowedHosts []string
	// AllowedOrigins lists permitted Origin values. Agents are not browsers,
	// so by default any request carrying an Origin header is rejected.
	AllowedOrigins []string
	// MaxBodyBytes bounds client request bodies (default 4 MiB).
	MaxBodyBytes int64
	// MaxResponseBytes bounds buffered JSON responses (default 8 MiB).
	MaxResponseBytes int64
	// MaxSSEEventBytes bounds one streamed event (default 1 MiB).
	MaxSSEEventBytes int
	// SessionTTL expires idle sessions (default 1h); MaxSessions bounds them.
	SessionTTL  time.Duration
	MaxSessions int
	// HTTPClient overrides the upstream client (tests).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now    func() time.Time
	Logger *slog.Logger
}

var serverNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// supportedVersions are the MCP protocol revisions the gateway understands.
// The 2026-07-28 stateless revision is not supported yet and is rejected
// rather than passed through unexamined.
var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

// defaultMethods are forwarded for every server. tools/call is handled
// separately by policy. Everything else (resources/*, prompts/*, completion/*,
// logging/*) is blocked unless a server lists it in AllowMethods.
var defaultMethods = map[string]bool{
	"initialize": true,
	"ping":       true,
	"tools/list": true,
}

type upstream struct {
	Server
	url     *url.URL
	allowed map[string]bool
}

func buildServers(list []Server) (map[string]*upstream, error) {
	out := map[string]*upstream{}
	for _, s := range list {
		if !serverNameRe.MatchString(s.Name) {
			return nil, fmt.Errorf("server %q: invalid name", s.Name)
		}
		if _, dup := out[s.Name]; dup {
			return nil, fmt.Errorf("server %q: duplicate", s.Name)
		}
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("server %q: url must be an http(s) URL without credentials or fragment", s.Name)
		}
		for k, v := range s.Headers {
			if k == "" || strings.ContainsAny(k, " :\r\n") || strings.ContainsAny(v, "\r\n") {
				return nil, fmt.Errorf("server %q: invalid header %q", s.Name, k)
			}
			switch strings.ToLower(k) {
			case "mcp-session-id", "content-type", "accept", "mcp-protocol-version", "host", "content-length":
				return nil, fmt.Errorf("server %q: header %q is managed by the gateway", s.Name, k)
			}
		}
		allowed := map[string]bool{}
		for m := range defaultMethods {
			allowed[m] = true
		}
		for _, m := range s.AllowMethods {
			if m == "" || len(m) > maxMethodLen || m == "tools/call" || strings.HasPrefix(m, "notifications/") {
				return nil, fmt.Errorf("server %q: invalid allow_methods entry %q", s.Name, m)
			}
			allowed[m] = true
		}
		out[s.Name] = &upstream{Server: s, url: u, allowed: allowed}
	}
	return out, nil
}

// Compile-time check that the real client satisfies the gateway's interface.
var _ Controller = (*gwclient.Client)(nil)

var errNoServers = errors.New("mcpgw: at least one server is required")
