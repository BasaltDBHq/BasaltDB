package localsetup

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
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

// confirmFacts are the confirm step's fields of a check's answer.
type confirmFacts struct {
	host        string
	port        int
	sessionUser string
	certificate ConfirmCertificate
}

// readConfirm reads the confirm step's facts of conn, the admin connection
// open reached with dsn; pinned is the pin it logged in against, or nil.
func (s *Service) readConfirm(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, dsn string, pinned *pin) (confirmFacts, error) {
	var user string
	// A SQL keyword squirrel cannot express.
	if err := tx.QueryRow(ctx, `SELECT session_user::text`).Scan(&user); err != nil {
		return confirmFacts{}, err
	}
	kind, provider := setup.CertificateOwn, ""
	if pinned == nil {
		kind, provider = s.certificateKind(dsn)
	}
	c := setup.CertificateOf(conn, kind, provider)
	host, port, ok := hostPort(dsn)
	if !ok { // a key=value string, or one with several hosts: where it went
		host, port = trustprofile.NormalizeHost(conn.Config().Host), int(conn.Config().Port)
	}
	return confirmFacts{host: host, port: port, sessionUser: user, certificate: ConfirmCertificate{Kind: string(c.Kind), Issuer: c.Issuer}}, nil
}

// certificateKind is what verifies dsn's certificate as the engine dials it
// (trustprofile.Explain with the profiles in force): a built-in profile is
// the provider's, an operator's profile (a pin among them) or the string's
// sslrootcert is a root this host was given, and below verify-full nothing
// verifies it.
func (s *Service) certificateKind(dsn string) (setup.CertificateKind, string) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return setup.CertificateNotVerified, ""
	}
	a := trustprofile.Explain(cfg, s.opts.Profiles())
	switch a.Applies {
	case trustprofile.AppliesNotVerified:
		return setup.CertificateNotVerified, ""
	case trustprofile.AppliesRootCert:
		return setup.CertificateOwn, ""
	case trustprofile.AppliesProfile:
		if a.Profile.Origin == trustprofile.BuiltIn {
			return setup.CertificateProvider, a.Profile.Name
		}
		return setup.CertificateOwn, ""
	case trustprofile.AppliesSystem:
	}
	return setup.CertificatePublic, ""
}

// apply sets the confirm step's fields of out.
func (f confirmFacts) apply(out *CheckAnswer) {
	out.Host, out.Port, out.SessionUser = f.host, f.port, f.sessionUser
	c := f.certificate
	out.Certificate = &c
}
