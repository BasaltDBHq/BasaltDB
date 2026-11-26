// Package handoffnet is the address hand-off's reach into the network: the
// read of the chain a database presents (handoff.Prober's ReadChain). The
// system's DNS (handoff.Resolver) is lib/sysdns, which pkg/setup shares.
package handoffnet

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"strconv"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
)

// ReadChain reads the certificate chain host presents at ip and port with
// the TLS handshake alone (trustpin.Fetch). It dials ip, whatever address
// is asked for: the one the host resolved to and the checks passed; over
// dial when it is set, the system's TCP otherwise.
func ReadChain(ctx context.Context, dial trustpin.Dial, ip netip.Addr, host string, port int) ([]*x509.Certificate, error) {
	return trustpin.Fetch(ctx, dialTo(dial, ip, port), host, port)
}

func dialTo(dial trustpin.Dial, ip netip.Addr, port int) trustpin.Dial {
	to := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		if dial != nil {
			return dial(ctx, network, to)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}
}
