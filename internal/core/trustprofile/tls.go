package trustprofile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// Trust makes host's TLS config t, when it verifies the host name
// (sslmode=verify-full) and one of set's profiles matches host, trust that
// profile's roots as well as the system's authorities. A config that
// already has roots keeps them; verify-ca, require and weaker modes are
// left as they are. It takes the host and its TLS config, not a driver's
// config, so this package imports no driver: a connection with several
// hosts calls it once for each host.
func Trust(host string, t *tls.Config, set *Set) {
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

// Explain is what verifies host with TLS config t, a config built without
// Trust.
func Explain(host string, t *tls.Config, set *Set) Applied {
	a := Applied{Host: host}
	switch {
	case !verifiesHost(t):
		a.Applies = AppliesNotVerified
	case t.RootCAs != nil:
		a.Applies = AppliesRootCert
	default:
		a.Applies = AppliesSystem
		if p := set.For(host); p != nil {
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
