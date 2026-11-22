package localsetup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// ca makes a CA certificate named name with key, signed by parent (itself
// when parent is nil).
func ca(t *testing.T, name string, serial int64, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

func caKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// TestSameIssuerIsTheKeyNeverTheName: a renewal with the pinned key, or a
// certificate the pinned one signed, is the same issuer; another key under
// the very same name is not.
func TestSameIssuerIsTheKeyNeverTheName(t *testing.T) {
	t.Parallel()
	oldKey := caKey(t)
	pinned := ca(t, "Google Cloud SQL Server CA", 1, oldKey, nil, nil)
	pin := &trustprofile.Profile{Files: []trustprofile.RootFile{{Certs: []*x509.Certificate{pinned}}}}

	renewed := ca(t, "Google Cloud SQL Server CA", 2, oldKey, nil, nil)
	require.True(t, sameIssuer(pin, renewed), "the same key, renewed")
	signed := ca(t, "Google Cloud SQL Server CA 2026", 3, caKey(t), pinned, oldKey)
	require.True(t, sameIssuer(pin, signed), "signed by the pinned certificate")
	impostor := ca(t, "Google Cloud SQL Server CA", 4, caKey(t), nil, nil)
	require.False(t, sameIssuer(pin, impostor), "the same name with another key")
	require.False(t, sameIssuer(pin, nil))
}
