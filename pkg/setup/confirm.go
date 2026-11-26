package setup

import (
	"context"
	"crypto/tls"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The confirm step, "Is this your database?" (CONTRACT.md, The connect page,
// Is this your database?): what a page shows the person right after the admin
// connection string is accepted. None of it is secret; none of it is the
// string or its password.

// CertificateKind is what verified the database's certificate.
type CertificateKind string

// The kinds of Certificate.
const (
	// CertificatePublic: an authority of the system's trust store.
	CertificatePublic CertificateKind = "PUBLIC"
	// CertificateProvider: a built-in trust profile (Amazon RDS, Supabase).
	CertificateProvider CertificateKind = "PROVIDER"
	// CertificateOwn: a root this host was given: a pin the person
	// trusted, an operator's trust profile or the string's sslrootcert.
	CertificateOwn CertificateKind = "OWN"
	// CertificateNotVerified: TLS without a check of the certificate
	// (sslmode below verify-full).
	CertificateNotVerified CertificateKind = "NOT_VERIFIED"
	// CertificateNone: no TLS.
	CertificateNone CertificateKind = "NONE"
)

// Certificate is the database's certificate as the confirm step shows it:
// Kind and the issuer's short name (trustpin.Name), the provider's name for
// CertificateProvider, "" for NOT_VERIFIED and NONE. The issuer is text the
// server chose, except a provider's name.
type Certificate struct {
	Kind   CertificateKind
	Issuer string
}

// CertificateOf is conn's certificate for the confirm step. kind is what the
// caller's dial verified it with (it built the TLS config, conn does not
// say); provider is the built-in profile's name with CertificateProvider. A
// connection without TLS is CertificateNone whatever kind says.
func CertificateOf(conn *pgx.Conn, kind CertificateKind, provider string) Certificate {
	tc, ok := conn.PgConn().Conn().(*tls.Conn)
	switch {
	case !ok:
		return Certificate{Kind: CertificateNone}
	case kind == CertificateNotVerified:
		return Certificate{Kind: kind}
	case kind == CertificateProvider:
		return Certificate{Kind: kind, Issuer: trustprofile.ProviderName(provider)}
	}
	return Certificate{Kind: kind, Issuer: trustpin.IssuerOf(tc.ConnectionState())}
}

// Connected is the database and the role a connection reached, as the
// server says them: current_database() and session_user, never a name read
// from the connection string.
type Connected struct {
	Database, User string
}

// ConnectedAs is what conn reached (Connected).
func ConnectedAs(ctx context.Context, conn *pgx.Conn) (Connected, error) {
	var c Connected
	var err error
	c.Database, c.User, err = store.ConnectedAs(ctx, setupstore.Port(conn))
	return c, err
}
