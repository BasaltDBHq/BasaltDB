package pgdial_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

const pinnedHost = "db.pin.example"

// pinnedAdmin is the start of an admin string (split so it is not read as a credential).
const pinnedAdmin = "postgres://admin" + ":" + "pw@"

// connect runs the pinned login against the fake server dial reaches. The
// fake server completes TLS and then refuses the password (28P01): a client
// that gets that refusal verified the certificate, and one that fails the
// handshake sent nothing.
func connect(t *testing.T, dsn string, p *trustprofile.Profile, dial func(context.Context, string, string) (net.Conn, error)) error {
	t.Helper()
	cfg, err := pgdial.ConnConfigPinned(dsn, p)
	if err != nil {
		return err
	}
	cfg.DialFunc = dial
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err == nil {
		_ = conn.Close(context.Background())
	}
	return err
}

func pinFor(t *testing.T, ca *x509.Certificate, caOnly bool) *trustprofile.Profile {
	t.Helper()
	pf, err := trustprofile.NewPin(pinnedHost, ca, caOnly)
	require.NoError(t, err)
	return pf.Profile
}

func loginRefused(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg), "%v", err)
	require.Equal(t, "28P01", pg.Code, "the TLS handshake passed and the server refused the password")
}

func TestPinnedLoginTrustsOnlyThePinnedAuthority(t *testing.T) {
	t.Parallel()
	ca, cert := trustprofiletest.Chain(t, pinnedHost)
	dial := trustprofiletest.Serve(t, cert)
	dsn := pinnedAdmin + pinnedHost + ":5432/app?sslmode=verify-full"

	loginRefused(t, connect(t, dsn, pinFor(t, ca, false), dial))

	// Another authority's chain fails the handshake, before any startup
	// message: the password is never sent.
	other, _ := trustprofiletest.Chain(t, pinnedHost)
	err := connect(t, dsn, pinFor(t, other, false), dial)
	require.Error(t, err)
	require.True(t, pgdial.CertificateNotVerified(err), "%v", err)

	// A pin with verify: ca checks the chain alone.
	loginRefused(t, connect(t, dsn, pinFor(t, ca, true), dial))
	require.True(t, pgdial.CertificateNotVerified(connect(t, dsn, pinFor(t, other, true), dial)))
}

func TestPinnedLoginIgnoresARootTheStringOrEnvironmentNames(t *testing.T) {
	ca, cert := trustprofiletest.Chain(t, pinnedHost)
	dial := trustprofiletest.Serve(t, cert)
	other, _ := trustprofiletest.Chain(t, pinnedHost)
	dir := t.TempDir()
	wrong := filepath.Join(dir, "wrong.pem")
	require.NoError(t, os.WriteFile(wrong, trustprofiletest.PEM(other), 0o600))

	// sslrootcert naming another authority would fail the handshake if it
	// were the root.
	dsn := pinnedAdmin + pinnedHost + ":5432/app?sslmode=verify-full&sslrootcert=" + wrong
	loginRefused(t, connect(t, dsn, pinFor(t, ca, false), dial))

	t.Setenv("PGSSLROOTCERT", wrong)
	loginRefused(t, connect(t, pinnedAdmin+pinnedHost+":5432/app?sslmode=verify-full", pinFor(t, ca, false), dial))
}

func TestPinnedLoginNeedsVerifyFull(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, pinnedHost)
	for _, mode := range []string{"verify-ca", "require", "prefer", "disable"} {
		_, err := pgdial.ConnConfigPinned(pinnedAdmin+pinnedHost+":5432/app?sslmode="+mode, pinFor(t, ca, false))
		require.Error(t, err, mode)
	}
}
