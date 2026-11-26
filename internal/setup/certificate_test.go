package setup_test

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The confirm step's certificate: no TLS is NONE whatever the dial said,
// NOT_VERIFIED names no issuer, and PROVIDER names the built-in profile.
func TestCertificateOfTheConfirmStep(t *testing.T) {
	t.Parallel()
	shown, issuer := setup.CertificateOf(nil, "PUBLIC", "")
	require.Equal(t, "NONE", shown)
	require.Empty(t, issuer)
	state := &tls.ConnectionState{}
	shown, issuer = setup.CertificateOf(state, "NOT_VERIFIED", "")
	require.Equal(t, "NOT_VERIFIED", shown)
	require.Empty(t, issuer)
	shown, issuer = setup.CertificateOf(state, "PROVIDER", "supabase")
	require.Equal(t, "PROVIDER", shown)
	require.Equal(t, trustprofile.ProviderName("supabase"), issuer)
}
