// Package netgw implements the AgentBox network gateway: an HTTP proxy with
// CONNECT support, policy-checked name resolution, and credential-injecting
// reverse-proxy routes for LLM providers.
//
// Every outbound connection is authorized by the controller (via gwclient)
// before it is made, destination addresses are validated after name
// resolution, and the connection is dialed to the validated IP (pinned), so a
// hostile DNS answer cannot redirect an allowed name to an internal address.
// The gateway fails closed: any error in authorization denies the request.
package netgw

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Address categories that are never reachable unless a policy rule explicitly
// allows the destination IP address (or CIDR). A domain allow rule is not
// enough: it must not be possible to reach an internal address by pointing an
// allowed name at it (DNS rebinding / SSRF).
var reservedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this" network
	"100.64.0.0/10",   // carrier-grade NAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved + broadcast
	"64:ff9b::/96",    // NAT64
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard-only
	"2001::/32",       // Teredo
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4
)

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Classify returns "" for an ordinary public unicast address, otherwise the
// reason it is restricted (loopback, private, link-local, ...).
func Classify(ip netip.Addr) string {
	ip = ip.Unmap().WithZone("")
	switch {
	case !ip.IsValid():
		return "invalid"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast():
		return "link-local" // includes 169.254.169.254 (cloud metadata)
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast():
		return "multicast"
	}
	for _, p := range reservedPrefixes {
		if p.Contains(ip) {
			return "reserved"
		}
	}
	return ""
}

// ErrBadHost is returned for destinations that cannot be interpreted safely.
var ErrBadHost = errors.New("invalid destination host")

// cleanHost normalizes and validates a destination host. It returns the
// canonical host and, if the host is an IP literal, the parsed address.
//
// Ambiguous numeric notations that resolvers accept but netip does not
// ("127.1", "2130706433", "0x7f.0.0.1") are rejected, because they would let a
// request reach loopback or private addresses under an innocuous-looking name.
func cleanHost(h string) (string, netip.Addr, error) {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "" || len(h) > 253 {
		return "", netip.Addr{}, fmt.Errorf("%w: empty or too long", ErrBadHost)
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return "", netip.Addr{}, fmt.Errorf("%w: IPv6 zones are not allowed", ErrBadHost)
		}
		a = a.Unmap()
		return a.String(), a, nil
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", netip.Addr{}, fmt.Errorf("%w: bad label", ErrBadHost)
		}
		for _, c := range l {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return "", netip.Addr{}, fmt.Errorf("%w: invalid character", ErrBadHost)
			}
		}
		if strings.HasPrefix(l, "0x") {
			return "", netip.Addr{}, fmt.Errorf("%w: ambiguous numeric address", ErrBadHost)
		}
	}
	if isAllDigits(labels[len(labels)-1]) {
		return "", netip.Addr{}, fmt.Errorf("%w: ambiguous numeric address", ErrBadHost)
	}
	return h, netip.Addr{}, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
