package setup_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

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

// A connection verified against a public root or its own pinned certificate shows its kind and
// the name of the authority at the top of the chain the server sent; the
// same chain shows no issuer when it was not verified.
func TestCertificateOfNamesTheChainsAuthority(t *testing.T) {
	t.Parallel()
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{selfSigned(t, "Example Root CA")}}
	for _, kind := range []string{"PUBLIC", "OWN"} {
		shown, issuer := setup.CertificateOf(state, kind, "")
		require.Equal(t, kind, shown)
		require.Equal(t, "Example Root CA", issuer)
	}
	shown, issuer := setup.CertificateOf(state, "NOT_VERIFIED", "")
	require.Equal(t, "NOT_VERIFIED", shown)
	require.Empty(t, issuer)
}

// selfSigned is a self-signed certificate whose subject's common name is cn.
func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(0, 0).Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
