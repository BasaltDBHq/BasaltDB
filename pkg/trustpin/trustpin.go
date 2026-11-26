// Package trustpin reads the certificate chain a Postgres server presents,
// with nothing but the TLS handshake, and checks it, so a person can pin
// the chain's top for that one host (CONTRACT.md, Trust profiles, Pinning
// on first use). It sends Postgres's SSLRequest and completes a TLS
// handshake that does not verify the certificate, only to read it, then
// closes the connection: no startup message, no user name, no password.
//
// This package is the public Go API for other modules: its types are
// aliases and its functions forwards to the engine's own code, so a
// certificate authority the person trusted on the connect page is checked
// the same way on both sides (Approved; CONTRACT.md, Pinning from the
// connect page).
package trustpin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	core "github.com/basaltdbhq/basaltdb/internal/core/trustpin"
	"github.com/basaltdbhq/basaltdb/internal/lib/certroots"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgtls"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Dial opens the TCP connection; nil is a plain net.Dialer.
type Dial = pgtls.Dial

// ErrNoTLS: the server answered the SSLRequest with no.
var ErrNoTLS = pgtls.ErrNoTLS

// Fetch is the chain host:port presents, leaf first, read with the TLS
// handshake alone. The certificate is not verified here: Check does that.
func Fetch(ctx context.Context, dial Dial, host string, port int) ([]*x509.Certificate, error) {
	return pgtls.Fetch(ctx, dial, host, port)
}

// Seen is what Check found in a chain for a host.
type Seen = core.Seen

// Check is what chain, leaf first, proves for host, against the system's
// trust store (trustprofile.SystemRoots) and, for Public, the public roots
// the binary carries as well (trustprofile.PublicRoots).
func Check(chain []*x509.Certificate, host string, now time.Time) Seen {
	return core.Check(chain, host, now, certroots.Store{})
}

// SubjectOf is c's subject as Subject gives a chain top's: RFC 2253,
// cleaned and cut to 512 characters.
func SubjectOf(c *x509.Certificate) string { return core.SubjectOf(c) }

// ErrMismatch: the chain's top is not the certificate the person approved.
var ErrMismatch = core.ErrMismatch

// ErrPublic: the chain is, or chains to, an authority in the system's
// trust store, so it is never pinned (Seen.Public).
var ErrPublic = core.ErrPublic

// ErrNotPinnable: the chain does not verify against its own top, with or
// without the host name, so no pin can hold it.
var ErrNotPinnable = core.ErrNotPinnable

// ValidSHA256 reports whether fp is a SHA-256 as an approval carries it:
// 64 lowercase hex digits.
func ValidSHA256(fp string) bool { return core.ValidSHA256(fp) }

// Approved is what chain proves for host against approved, the SHA-256 the
// person approved: the pin for its top (verify: ca when the leaf does not
// name the host), only when that top's SHA-256 is approved (ErrMismatch,
// also for a malformed approved) and the chain verifies against it
// (ErrNotPinnable). A public chain is never pinned (ErrPublic), whatever
// the approval. The approval is never trusted on its own: the chain is the
// caller's own reading.
func Approved(chain []*x509.Certificate, host string, now time.Time, approved string) (Seen, *trustprofile.Profile, error) {
	return core.Approved(chain, host, now, approved, certroots.Store{})
}

// Name is a certificate authority's short name, as the confirm step shows
// it (CONTRACT.md, The install of a real database, Is this your
// database?): the subject's common name, else its first organization, else
// the whole subject (RFC 2253), cleaned as Subject is and cut to 128
// characters. The server chooses it: it names, it proves nothing.
func Name(n pkix.Name) string { return core.Name(n) }

// IssuerOf is the name of the authority at the top of a TLS connection's
// chain: the root of the chain it verified against, else the highest
// certificate the server sent (a pin checked in a VerifyConnection leaves
// no verified chain): that certificate itself when it is self-signed, else
// its issuer. "" when the server sent no certificate.
func IssuerOf(cs tls.ConnectionState) string { return core.IssuerOf(cs) }
