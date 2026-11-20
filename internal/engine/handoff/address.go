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
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Address is a collected database address: never a password.
type Address struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	SupabaseRef string `json:"supabaseRef,omitempty"`
}

// The shape limits of a collected address (CONTRACT.md, The engine and a
// connect-only code, Checking the address itself).
const (
	maxHost = 253
	maxPort = 65535
)

var (
	hostShape     = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	databaseShape = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)
	refShape      = regexp.MustCompile(`^[a-z0-9]{20}$`)
)

// ErrAddressInvalid is an address the engine refuses: its shape, or a host
// that resolves to an address outside global unicast (problem
// ADDRESS_INVALID). Its text names nothing of the address, which whoever
// ran the setup chose.
var ErrAddressInvalid = errors.New("the address the connect service handed over was refused")

// Check refuses an address whose host, port, database or Supabase ref is
// not of the contract's shape, before anything of it is shown or used.
func (a Address) Check() error {
	switch {
	case !hostShape.MatchString(a.Host) || len(a.Host) > maxHost || strings.HasPrefix(a.Host, "-") || strings.Contains(a.Host, ".."),
		a.Port < 1 || a.Port > maxPort,
		!databaseShape.MatchString(a.Database),
		a.SupabaseRef != "" && !refShape.MatchString(a.SupabaseRef):
		return ErrAddressInvalid
	}
	return a.checkRef()
}

// checkRef ties a Supabase ref to the host, since Name shows the ref in
// place of the host and the person confirms what Name says: the project's
// own host db.<ref>.supabase.co, or Supabase's pooler, where the agent logs
// in as <role>.<ref> and the pooler routes the login to that project.
func (a Address) checkRef() error {
	if a.SupabaseRef == "" {
		return nil
	}
	host := strings.ToLower(a.Host)
	if host == "db."+a.SupabaseRef+supabaseDirect || strings.HasSuffix(host, supabasePooler) {
		return nil
	}
	return ErrAddressInvalid
}

// supabaseDirect is the host suffix of a Supabase project's own database.
const supabaseDirect = ".supabase.co"

// Name is the database as the agent names it to the person: "Supabase
// project <ref>, database <db>" or "<host>:<port>, database <db>".
func (a Address) Name() string {
	if a.SupabaseRef != "" {
		return "Supabase project " + a.SupabaseRef + ", database " + a.Database
	}
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) + ", database " + a.Database
}

// String names the database, as Name.
func (a Address) String() string { return a.Name() }

// Resolver looks up a host name. *net.Resolver's LookupNetIP is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SystemResolver resolves with the system's DNS. It asks for A and AAAA
// records separately, so an A record is an IPv4 address.
type SystemResolver struct{ R *net.Resolver }

// LookupNetIP returns the A addresses and then the AAAA addresses of host.
func (s SystemResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	r := s.R
	if r == nil {
		r = net.DefaultResolver
	}
	v4, err4 := r.LookupNetIP(ctx, "ip4", host)
	v6, err6 := r.LookupNetIP(ctx, "ip6", host)
	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("resolve the database's host: %w", errors.Join(err4, err6))
	}
	out := make([]netip.Addr, 0, len(v4)+len(v6))
	for _, a := range v4 {
		out = append(out, a.Unmap())
	}
	return append(out, v6...), nil
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

// errUnresolved is a host that resolves to nothing: the database cannot be
// reached from the bot's machine.
var errUnresolved = errors.New("the database's host does not resolve")

// pick resolves host once and returns the address to connect to: every
// address the name resolves to must be allowed (ErrAddressInvalid
// otherwise), and IPv4 is preferred. An IP literal is checked as it is.
func pick(ctx context.Context, r Resolver, host string) (netip.Addr, error) {
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
			return netip.Addr{}, ErrAddressInvalid
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
