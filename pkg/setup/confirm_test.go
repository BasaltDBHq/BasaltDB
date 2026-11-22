package setup_test

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// TestCertificateOfAndSessionUser: the confirm step's facts of an open
// connection. A connection without TLS is NONE whatever the dial says, and
// session_user is the role the string logged in as.
func TestCertificateOfAndSessionUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t)
	if _, ok := d.Admin.PgConn().Conn().(*tls.Conn); ok {
		t.Skip("the test server's connection uses TLS")
	}
	for _, kind := range []setup.CertificateKind{setup.CertificatePublic, setup.CertificateProvider, setup.CertificateOwn} {
		require.Equal(t, setup.Certificate{Kind: setup.CertificateNone}, setup.CertificateOf(d.Admin, kind, "supabase"))
	}
	user, err := setup.SessionUser(ctx, d.Admin)
	require.NoError(t, err)
	require.Equal(t, d.Admin.Config().User, user)
}
