package trustprofile

import (
	"crypto/tls"

	"github.com/jackc/pgx/v5/pgconn"

	core "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
)

// Trust makes every TLS config of cfg that verifies the host name
// (sslmode=verify-full) for a host one of set's profiles matches trust that
// profile's roots as well as the system's authorities. Each host is matched
// on its own, so a multi-host connection string trusts each profile's roots
// only for that profile's hosts. A config that already has roots
// (sslrootcert, PGSSLROOTCERT, a service file or ~/.postgresql/root.crt)
// keeps them: the person named the root. The host name check stays on;
// verify-ca, require and weaker modes are left as pgx built them. Call it
// once per parsed config: on a copy for each new connection of a pool.
func Trust(cfg *pgconn.Config, set *Set) {
	core.Trust(set, cfg.Host, cfg.TLSConfig, cfg.Fallbacks, fallbackHost)
}

// fallbackHost is a fallback's host and TLS config, as core.Trust takes it.
func fallbackHost(fb *pgconn.FallbackConfig) (string, *tls.Config) { return fb.Host, fb.TLSConfig }

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

// Explain is what verifies cfg's first host, a config parsed without Trust.
func Explain(cfg *pgconn.Config, set *Set) Applied { return core.Explain(cfg.Host, cfg.TLSConfig, set) }

// CertificateNotVerified reports whether err is a server certificate that
// did not verify: an unknown authority, a name that does not match, or a
// certificate that is not valid.
func CertificateNotVerified(err error) bool { return core.CertificateNotVerified(err) }
