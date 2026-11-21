package trustprofile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
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
	apply := func(host string, t *tls.Config) {
		if !verifiesHost(t) || t.RootCAs != nil {
			return
		}
		p := set.For(host)
		switch {
		case p == nil:
		case p.VerifiesCA():
			// As pgx does for sslmode=verify-ca: the chain is checked here,
			// against the pin's roots alone, and the name is not.
			t.InsecureSkipVerify = true
			t.VerifyConnection = chainTo(p.OwnPool())
		default:
			t.RootCAs = p.Pool()
		}
	}
	apply(cfg.Host, cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		apply(fb.Host, fb.TLSConfig)
	}
}

// verifiesHost reports whether t verifies the server's certificate and its
// host name, as pgx builds it for sslmode=verify-full.
func verifiesHost(t *tls.Config) bool { return t != nil && !t.InsecureSkipVerify }

// Applies says what verifies a host's certificate.
type Applies string

// What verifies a host's certificate.
const (
	// AppliesRootCert: the connection names its own roots (sslrootcert).
	AppliesRootCert Applies = "SSLROOTCERT"
	// AppliesProfile: a trust profile's roots and the system's.
	AppliesProfile Applies = "PROFILE"
	// AppliesSystem: the system's authorities alone.
	AppliesSystem Applies = "SYSTEM"
	// AppliesNotVerified: the connection does not verify the host name
	// (sslmode below verify-full), so no profile applies.
	AppliesNotVerified Applies = "NOT_VERIFIED"
)

// Applied is what verifies one host of a connection: Profile is set
// exactly when Applies is AppliesProfile.
type Applied struct {
	Host    string
	Applies Applies
	Profile *Profile
}

// Explain is what verifies cfg's first host, a config parsed without Trust.
func Explain(cfg *pgconn.Config, set *Set) Applied {
	a := Applied{Host: cfg.Host}
	t := cfg.TLSConfig
	switch {
	case !verifiesHost(t):
		a.Applies = AppliesNotVerified
	case t.RootCAs != nil:
		a.Applies = AppliesRootCert
	default:
		a.Applies = AppliesSystem
		if p := set.For(cfg.Host); p != nil {
			a.Applies, a.Profile = AppliesProfile, p
		}
	}
	return a
}

// CertificateNotVerified reports whether err is a server certificate that
// did not verify: an unknown authority, a name that does not match, or a
// certificate that is not valid.
func CertificateNotVerified(err error) bool {
	var (
		verify  *tls.CertificateVerificationError
		host    x509.HostnameError
		unknown x509.UnknownAuthorityError
		invalid x509.CertificateInvalidError
	)
	return errors.As(err, &verify) || errors.As(err, &host) || errors.As(err, &unknown) || errors.As(err, &invalid)
}

// chainTo verifies the server's chain against roots alone, the host name
// not checked. It is a VerifyConnection, which runs on every handshake, a
// resumed session's included.
func chainTo(roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		certs := cs.PeerCertificates
		if len(certs) == 0 {
			return &tls.CertificateVerificationError{Err: errors.New("the server sent no certificate")}
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
		return nil
	}
}
