// Package sysdns resolves host names with the system's DNS, IPv4 first.
package sysdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Resolver resolves with the system's DNS (net.DefaultResolver when R is
// nil). It asks for A and AAAA records separately, so an A record is an
// IPv4 address.
type Resolver struct{ R *net.Resolver }

// LookupNetIP returns the A addresses and then the AAAA addresses of host.
func (s Resolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
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
