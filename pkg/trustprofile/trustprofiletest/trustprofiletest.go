// Package trustprofiletest is a stand-in for a database whose certificate
// chains to a trust profile's root, in tests: a test CA playing the root, and a
// Postgres server that completes TLS
// with a certificate that CA signed and then refuses the password. A client
// that gets the refusal (28P01) verified the certificate.
//
// It forwards to the engine's own test kit, so other modules' tests use the
// same stand-in.
package trustprofiletest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/testkit/trusttest"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Chain is a test CA and a server certificate for host it signed.
func Chain(t *testing.T, host string) (*x509.Certificate, tls.Certificate) {
	return trusttest.Chain(t, host)
}

// Serve runs the server with cert until the test ends and returns a dialer
// that reaches it whatever address is asked for (pgx's DialFunc).
func Serve(t *testing.T, cert tls.Certificate) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return trusttest.Serve(t, cert)
}

// PEM is cas as one PEM file.
func PEM(cas ...*x509.Certificate) []byte { return trusttest.PEM(cas...) }

// Profile is a profile called name of origin, matching match, whose one
// roots file holds cas, loaded through trustprofile.Parse.
func Profile(t testing.TB, origin trustprofile.Origin, name string, match []string, cas ...*x509.Certificate) *trustprofile.Profile {
	return trusttest.Profile(t, origin, name, match, cas...)
}

// Set is the built-in profiles with each named one's roots replaced by
// cas (a test CA standing in for the provider's roots), and operator.
func Set(t testing.TB, replace map[string][]*x509.Certificate, operator ...*trustprofile.Profile) *trustprofile.Set {
	return trusttest.Set(t, replace, operator...)
}
