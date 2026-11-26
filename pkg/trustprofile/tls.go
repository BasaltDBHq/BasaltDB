package trustprofile

import (
	"crypto/tls"

	core "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
)

// TrustTLS makes host's TLS config t, when it verifies the host name and
// one of set's profiles matches host, trust that profile's roots as well as
// the system's authorities. t is the caller's own config, with the TLS
// settings its connection string or client options gave it; for a Postgres
// connection, sslmode=verify-full is the mode that verifies the host name.
// A config that already has roots (for Postgres, sslrootcert,
// PGSSLROOTCERT, a service file or ~/.postgresql/root.crt) keeps them: the
// person named the root. The host name check stays on; a config that does
// not verify the host name is left as the caller built it. A connection
// with several hosts calls it once for each host and its own TLS config,
// so each profile's roots are trusted only for that profile's hosts. Call
// it once per config: on a copy for each new connection of a pool.
func TrustTLS(host string, t *tls.Config, set *Set) { core.Trust(host, t, set) }

// Applies says what verifies a host's certificate.
type Applies = core.Applies

// What verifies a host's certificate.
const (
	// AppliesRootCert: the connection names its own roots (sslrootcert).
	AppliesRootCert = core.AppliesRootCert
	// AppliesProfile: a trust profile's roots and the system's.
	AppliesProfile = core.AppliesProfile
	// AppliesSystem: the system's authorities alone.
	AppliesSystem = core.AppliesSystem
	// AppliesNotVerified: the connection does not verify the host name
	// (sslmode below verify-full), so no profile applies.
	AppliesNotVerified = core.AppliesNotVerified
)

// Applied is what verifies one host of a connection: Profile is set
// exactly when Applies is AppliesProfile.
type Applied = core.Applied

// ExplainTLS is what verifies host with TLS config t, a config built
// without TrustTLS.
func ExplainTLS(host string, t *tls.Config, set *Set) Applied { return core.Explain(host, t, set) }

// CertificateNotVerified reports whether err is a server certificate that
// did not verify: an unknown authority, a name that does not match, or a
// certificate that is not valid.
func CertificateNotVerified(err error) bool { return core.CertificateNotVerified(err) }
