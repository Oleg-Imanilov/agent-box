package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type destKind int

const (
	destDomain   destKind = iota // exact domain
	destWildcard                 // *.suffix (subdomains only)
	destIP                       // single IP
	destCIDR                     // IP prefix
)

// destRule is a parsed "host:port" rule.
type destRule struct {
	kind   destKind
	host   string // domain (exact) or suffix (wildcard, without "*.")
	addr   netip.Addr
	prefix netip.Prefix
	portLo int
	portHi int
}

// parseDestRule parses "host:port". IPv6 hosts and CIDRs must be bracketed,
// e.g. "[::1]:443" or "[fd00::/8]:*".
func parseDestRule(s string) (destRule, error) {
	var r destRule
	if s == "" || len(s) > 300 {
		return r, errors.New("invalid destination rule")
	}
	var host, port string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end+1 >= len(s) || s[end+1] != ':' {
			return r, fmt.Errorf("invalid destination %q: expected [host]:port", s)
		}
		host, port = s[1:end], s[end+2:]
	} else {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			return r, fmt.Errorf("invalid destination %q: port is required (use host:port)", s)
		}
		host, port = s[:i], s[i+1:]
		if strings.Contains(host, ":") {
			return r, fmt.Errorf("invalid destination %q: IPv6 hosts must be bracketed", s)
		}
	}
	lo, hi, err := parsePortRange(port)
	if err != nil {
		return r, fmt.Errorf("invalid destination %q: %w", s, err)
	}
	r.portLo, r.portHi = lo, hi

	if host == "" {
		return r, fmt.Errorf("invalid destination %q: empty host", s)
	}
	if strings.Contains(host, "/") {
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return r, fmt.Errorf("invalid destination %q: bad CIDR", s)
		}
		r.kind = destCIDR
		r.prefix = unmapPrefix(p).Masked()
		return r, nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return r, fmt.Errorf("invalid destination %q: IPv6 zones are not allowed", s)
		}
		r.kind, r.addr = destIP, a.Unmap()
		return r, nil
	}
	h := normalizeHost(host)
	if strings.HasPrefix(h, "*.") {
		h = h[2:]
		if err := validateDomain(h); err != nil {
			return r, fmt.Errorf("invalid destination %q: %w", s, err)
		}
		r.kind, r.host = destWildcard, h
		return r, nil
	}
	if err := validateDomain(h); err != nil {
		return r, fmt.Errorf("invalid destination %q: %w", s, err)
	}
	r.kind, r.host = destDomain, h
	return r, nil
}

// unmapPrefix converts an IPv4-mapped IPv6 prefix to plain IPv4.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

func parsePortRange(s string) (int, int, error) {
	if s == "*" {
		return 1, 65535, nil
	}
	loS, hiS, isRange := strings.Cut(s, "-")
	lo, err := parsePort(loS)
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return lo, lo, nil
	}
	hi, err := parsePort(hiS)
	if err != nil {
		return 0, 0, err
	}
	if hi < lo {
		return 0, 0, errors.New("port range is reversed")
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, errors.New("invalid port")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid port")
		}
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, errors.New("port out of range")
	}
	return n, nil
}

// normalizeHost lowercases and strips a single trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// validateDomain accepts ASCII LDH labels (plus underscore). IDNs must be given
// in punycode so that matching is unambiguous.
func validateDomain(h string) error {
	if h == "" || len(h) > 253 {
		return errors.New("invalid domain length")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid domain label")
		}
		for _, c := range label {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return fmt.Errorf("invalid character %q in domain", c)
			}
		}
	}
	return nil
}

// matches reports whether the rule covers host:port. host may be a domain
// name or an IP literal (IPv6 may be bracketed).
func (r destRule) matches(host string, port int) bool {
	if port < r.portLo || port > r.portHi {
		return false
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.WithZone("").Unmap()
		switch r.kind {
		case destIP:
			return r.addr == a
		case destCIDR:
			return r.prefix.Contains(a)
		}
		return false
	}
	host = normalizeHost(host)
	switch r.kind {
	case destDomain:
		return host == r.host
	case destWildcard:
		return strings.HasSuffix(host, "."+r.host)
	}
	return false
}

// globMatch matches s against a pattern where "*" matches any (possibly empty)
// sequence of characters.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
