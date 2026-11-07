package netgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/bgtask"
	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
)

// Controller is the part of the controller API the gateway uses.
// *gwclient.Client implements it.
type Controller interface {
	DecideNetwork(ctx context.Context, host string, port int) gwclient.Decision
	DecideNetworkAsk(ctx context.Context, host string, port int, requestID string) gwclient.Decision
	ReportEvent(ctx context.Context, e gwclient.Event) error
}

// Compile-time check that the real client satisfies the gateway's interface.
var _ Controller = (*gwclient.Client)(nil)

// Resolver resolves host names to IP addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a connection to an already validated IP:port address.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config configures a Gateway.
type Config struct {
	Controller Controller
	// Resolver defaults to the system resolver.
	Resolver Resolver
	// DialContext overrides how validated addresses are dialed (tests). The
	// default dialer re-validates the connected address at the socket level.
	DialContext DialFunc
	// Approvals makes denied-by-default destinations wait for a human decision.
	Approvals bool
	// Providers are the LLM reverse-proxy routes served under /llm/<name>/.
	Providers []Provider
	// MaxConns bounds concurrent proxied connections (default 512).
	MaxConns int
	// IdleTimeout closes tunnels with no traffic (default 5m).
	IdleTimeout time.Duration
	// DialTimeout bounds each connection attempt (default 10s).
	DialTimeout time.Duration
	// ResolveTimeout bounds name resolution (default 5s).
	ResolveTimeout time.Duration
	Logger         *slog.Logger
}

// Gateway is the network gateway.
type Gateway struct {
	cfg       Config
	log       *slog.Logger
	resolver  Resolver
	sem       chan struct{}
	providers map[string]*provider

	bg bgtask.Group // background event reporting
}

// New validates cfg and creates a Gateway.
func New(cfg Config) (*Gateway, error) {
	if cfg.Controller == nil {
		return nil, errors.New("netgw: controller is required")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 512
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.ResolveTimeout <= 0 {
		cfg.ResolveTimeout = 5 * time.Second
	}
	g := &Gateway{cfg: cfg, log: cfg.Logger, resolver: cfg.Resolver, sem: make(chan struct{}, cfg.MaxConns)}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	if g.resolver == nil {
		g.resolver = net.DefaultResolver
	}
	ps, err := buildProviders(cfg.Providers)
	if err != nil {
		return nil, err
	}
	g.providers = ps
	return g, nil
}

// Wait blocks until background event reports have finished.
func (g *Gateway) Wait() { g.bg.Wait() }

// DeniedError reports that policy (or an address guard) refused a destination.
type DeniedError struct {
	Decision policy.Decision
	Reason   string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("destination denied (rule %s): %s", e.Decision.RuleID, e.Reason)
}

// Rule IDs reported by the gateway itself.
const (
	RuleBlockedAddress = "netgw#blocked-address"
	RuleBadHost        = "netgw#bad-host"
)

func (g *Gateway) decide(ctx context.Context, host string, port int) gwclient.Decision {
	if g.cfg.Approvals {
		return g.cfg.Controller.DecideNetworkAsk(ctx, host, port, gwclient.NewRequestID())
	}
	return g.cfg.Controller.DecideNetwork(ctx, host, port)
}

// Dial authorizes host:port with the controller, resolves the name, validates
// the resulting addresses and connects to a validated IP.
//
// It returns *DeniedError when the destination is refused, and other errors
// for resolution or connection failures.
func (g *Gateway) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, &DeniedError{Decision: policy.Decision{Effect: policy.Deny, RuleID: RuleBadHost}, Reason: "invalid port"}
	}
	clean, literal, err := cleanHost(host)
	if err != nil {
		return nil, &DeniedError{Decision: policy.Decision{Effect: policy.Deny, RuleID: RuleBadHost}, Reason: err.Error()}
	}

	d := g.decide(ctx, clean, port)
	if !d.Allowed() {
		return nil, &DeniedError{Decision: d.Decision, Reason: denyReason(d)}
	}

	var ips []netip.Addr
	if literal.IsValid() {
		// The decision above already covered this exact address.
		ips = []netip.Addr{literal}
	} else {
		ips, err = g.resolve(ctx, clean)
		if err != nil {
			g.reportAsync(gwclient.Event{Kind: "dns", Destination: clean, Operation: "dns.resolve", Decision: "error",
				RuleID: d.RuleID, PolicyVersion: d.PolicyVersion, Metadata: map[string]any{"error": err.Error()}})
			return nil, fmt.Errorf("resolve %s: %w", clean, err)
		}
	}

	permitted, skipped, lastDeny := g.filterAddresses(ctx, ips, literal.IsValid(), port)
	if len(skipped) > 0 {
		g.reportAsync(gwclient.Event{Kind: "dns", Destination: clean, Operation: "dns.blocked-address", Decision: "deny",
			RuleID: RuleBlockedAddress, PolicyVersion: d.PolicyVersion,
			Metadata: map[string]any{"blocked": skipped, "kept": len(permitted)}})
	}
	if len(permitted) == 0 {
		dec := lastDeny
		if dec.RuleID == "" {
			dec = policy.Decision{Effect: policy.Deny, RuleID: RuleBlockedAddress, PolicyVersion: d.PolicyVersion}
		}
		return nil, &DeniedError{Decision: dec, Reason: "name resolves only to restricted addresses"}
	}
	return g.dialAny(ctx, permitted, port)
}

func denyReason(d gwclient.Decision) string {
	if d.Err != nil {
		return "policy service unavailable"
	}
	if d.Reason != "" {
		return d.Reason
	}
	return "not allowed by policy"
}

// filterAddresses keeps public addresses and restricted addresses that a
// policy rule explicitly allows for this port. It returns the kept addresses,
// a description of dropped ones, and the last deny decision.
func (g *Gateway) filterAddresses(ctx context.Context, ips []netip.Addr, literal bool, port int) ([]netip.Addr, []string, policy.Decision) {
	var (
		permitted []netip.Addr
		skipped   []string
		lastDeny  policy.Decision
	)
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		cat := Classify(ip)
		if cat == "" || literal {
			permitted = append(permitted, ip)
			continue
		}
		// Restricted address reached through a name: require an explicit rule
		// for the IP itself, in addition to the rule for the name.
		d := g.decide(ctx, ip.String(), port)
		if d.Allowed() {
			permitted = append(permitted, ip)
			continue
		}
		lastDeny = d.Decision
		skipped = append(skipped, ip.String()+" ("+cat+")")
	}
	return permitted, skipped, lastDeny
}

func (g *Gateway) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.ResolveTimeout)
	defer cancel()
	ips, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses")
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	return ips, nil
}

func (g *Gateway) dialAny(ctx context.Context, ips []netip.Addr, port int) (net.Conn, error) {
	dial := g.cfg.DialContext
	if dial == nil {
		dial = g.defaultDial(ips)
	}
	var lastErr error
	for _, ip := range ips {
		actx, cancel := context.WithTimeout(ctx, g.cfg.DialTimeout)
		c, err := dial(actx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("connect: %w", lastErr)
}

// defaultDial dials an IP literal and re-checks, at the socket level, that the
// address being connected is one that was validated.
func (g *Gateway) defaultDial(allowed []netip.Addr) DialFunc {
	set := make(map[netip.Addr]bool, len(allowed))
	for _, a := range allowed {
		set[a.Unmap()] = true
	}
	d := &net.Dialer{
		Timeout: g.cfg.DialTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !set[ap.Addr().Unmap()] {
				return errors.New("netgw: refusing to connect to unvalidated address")
			}
			return nil
		},
	}
	return d.DialContext
}

func (g *Gateway) reportAsync(e gwclient.Event) {
	g.bg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.cfg.Controller.ReportEvent(ctx, e); err != nil {
			g.log.Warn("event report failed", "op", e.Operation, "err", err)
		}
	})
}
