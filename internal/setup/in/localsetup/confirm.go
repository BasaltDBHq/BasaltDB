package localsetup

import (
	"context"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The confirm step of an install of a real database, "Is this your
// database?" (CONTRACT.md, The install of a real database): the check's
// answer names the database, its host and port, the role the admin string
// logged in as and what verified the certificate. None of it is the
// string or its password.

// ConfirmCertificate is the database's certificate as the confirm step
// shows it: kind PUBLIC, PROVIDER, OWN, NOT_VERIFIED or NONE, and the
// issuer's short name (the provider's for PROVIDER; none for NOT_VERIFIED
// and NONE).
type ConfirmCertificate struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer,omitempty"`
}

// The kinds of ConfirmCertificate.
const (
	// certPublic: an authority of the system's trust store.
	certPublic = "PUBLIC"
	// certProvider: a built-in trust profile (Amazon RDS, Supabase).
	certProvider = "PROVIDER"
	// certOwn: a root this host was given: a pin the person trusted, an
	// operator's trust profile or the string's sslrootcert.
	certOwn = "OWN"
	// certNotVerified: TLS without a check of the certificate (sslmode
	// below verify-full).
	certNotVerified = "NOT_VERIFIED"
)

// confirmFacts are the confirm step's fields of a check's answer.
type confirmFacts struct {
	host        string
	port        int
	sessionUser string
	certificate ConfirmCertificate
}

// readConfirm reads the confirm step's facts of conn, the admin connection
// open reached with dsn; pinned is the pin it logged in against, or nil.
func (s *Service) readConfirm(ctx context.Context, tx Tx, conn Conn, dsn string, pinned *pin) (confirmFacts, error) {
	user, err := s.be.SessionUser(ctx, tx.Port())
	if err != nil {
		return confirmFacts{}, s.setupFailed("read the admin user", err)
	}
	kind, provider := certOwn, ""
	if pinned == nil {
		kind, provider = s.certificateKind(dsn)
	}
	shown, issuer := s.be.ConnCertificate(conn, kind, provider)
	host, port, ok := hostPort(dsn)
	if !ok { // a key=value string, or one with several hosts: where it went
		h, p := s.be.ConnHost(conn)
		host, port = trustprofile.NormalizeHost(h), p
	}
	return confirmFacts{host: host, port: port, sessionUser: user, certificate: ConfirmCertificate{Kind: shown, Issuer: issuer}}, nil
}

// certificateKind is what verifies dsn's certificate as the engine dials it
// (trustprofile.Explain with the profiles in force): a built-in profile is
// the provider's, an operator's profile (a pin among them) or the string's
// sslrootcert is a root this host was given, and below verify-full nothing
// verifies it.
func (s *Service) certificateKind(dsn string) (string, string) {
	a, err := s.be.ExplainTrust(dsn, s.opts.Profiles())
	if err != nil {
		return certNotVerified, ""
	}
	switch a.Applies {
	case trustprofile.AppliesNotVerified:
		return certNotVerified, ""
	case trustprofile.AppliesRootCert:
		return certOwn, ""
	case trustprofile.AppliesProfile:
		if a.Profile.Origin == trustprofile.BuiltIn {
			return certProvider, a.Profile.Name
		}
		return certOwn, ""
	case trustprofile.AppliesSystem:
	}
	return certPublic, ""
}

// apply sets the confirm step's fields of out.
func (f confirmFacts) apply(out *CheckAnswer) {
	out.Host, out.Port, out.SessionUser = f.host, f.port, f.sessionUser
	c := f.certificate
	out.Certificate = &c
}
