// Package handoff is the engine's side of the address hand-off of a
// connect-only setup code (CONTRACT.md, Setup from your laptop, The engine
// and a connect-only code; Connect, The address hand-off). The engine
// collects the address of the database the person's setup ran in from the
// connect service, checks it itself, probes it with a login bound to fail,
// and logs in with the agent's real password only after the person
// confirmed that database in the chat.
package handoff

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// Resolver looks up a host name. *net.Resolver's LookupNetIP is one, and
// lib/sysdns's outside tests.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// refusedPrefixes are the ranges the engine never connects a collected
// address to, IPv4 and IPv6: the connect service's own (CONTRACT.md,
// Connect, Where the runner connects). An address must also be global
// unicast.
var refusedPrefixes = mustPrefixes(
	// IPv4.
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, cloud metadata
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"192.88.99.0/24",  // 6to4 relay anycast
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, and broadcast
	// IPv6.
	"::/96",           // unspecified, loopback, IPv4-compatible
	"::ffff:0:0/96",   // IPv4-mapped
	"::ffff:0:0:0/96", // IPv4-translated (SIIT)
	"64:ff9b::/96",    // NAT64
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard
	"2001::/23",       // IETF protocol assignments, Teredo (2001::/32), benchmarking, ORCHID
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4
	"3fff::/20",       // documentation
	"5f00::/16",       // segment routing
	"fc00::/7",        // unique local
	"fe80::/10",       // link-local
	"fec0::/10",       // site-local
	"ff00::/8",        // multicast
)

var globalUnicast6 = netip.MustParsePrefix("2000::/3")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Allowed reports whether the engine may connect a collected address to a.
func Allowed(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || !a.IsGlobalUnicast() {
		return false
	}
	// IPv6: only the global unicast block IANA allocates from; Go's
	// IsGlobalUnicast also passes 1::/16, 4000::/2 and the like.
	if a.Is6() && !globalUnicast6.Contains(a) {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range refusedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// RefusedPrefixes is a copy of the ranges Allowed refuses.
func RefusedPrefixes() []netip.Prefix { return slices.Clone(refusedPrefixes) }

// errUnresolved is a host that resolves to nothing: the database cannot be
// reached from the bot's machine.
var errUnresolved = errors.New("the database's host does not resolve")

// Pick resolves host once and returns the address to connect to: every
// address the name resolves to must be allowed (setupcode.ErrAddressInvalid
// otherwise), and IPv4 is preferred. An IP literal is checked as it is.
func Pick(ctx context.Context, r Resolver, host string) (netip.Addr, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		addrs, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			return netip.Addr{}, errUnresolved
		}
	}
	var v4, v6 netip.Addr
	for _, a := range addrs {
		if !Allowed(a) {
			return netip.Addr{}, setupcode.ErrAddressInvalid
		}
		switch {
		case a.Is4() && !v4.IsValid():
			v4 = a
		case a.Is6() && !v6.IsValid():
			v6 = a
		}
	}
	if v4.IsValid() {
		return v4, nil
	}
	return v6, nil
}
