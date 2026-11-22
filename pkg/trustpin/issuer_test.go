package trustpin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
)

func TestNameIsTheShortNameOfAnAuthority(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Google Cloud SQL Server CA", trustpin.Name(pkix.Name{CommonName: "Google Cloud SQL Server CA", Organization: []string{"Google, Inc"}}))
	require.Equal(t, "Acme Corp", trustpin.Name(pkix.Name{Organization: []string{"Acme Corp"}}))
	require.Equal(t, "C=US", trustpin.Name(pkix.Name{Country: []string{"US"}}))
	require.Equal(t, "evil", trustpin.Name(pkix.Name{CommonName: "e\u202ev\x00il"}), "controls and bidi controls are removed")
	require.Len(t, []rune(trustpin.Name(pkix.Name{CommonName: strings.Repeat("é", 300)})), 128)
}

// handshake is the client's state of a TLS handshake with a server that
// presents chain, verified against roots (nil: not verified).
func handshake(t *testing.T, chain []*x509.Certificate, key *ecdsa.PrivateKey, roots *x509.CertPool) tls.ConnectionState {
	t.Helper()
	cert := tls.Certificate{PrivateKey: key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	go func() {
		s := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		_ = s.Handshake()
	}()
	cfg := &tls.Config{ServerName: "db.example", RootCAs: roots, InsecureSkipVerify: roots == nil, MinVersion: tls.VersionTLS12}
	c := tls.Client(client, cfg)
	require.NoError(t, c.Handshake())
	return c.ConnectionState()
}

func cert(t *testing.T, name string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !ca {
		tmpl.DNSNames = []string{"db.example"}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c, key
}

// TestIssuerOfNamesTheRootOfTheChain: the verified chain's root; without
// one, the top the server sent, or the root that signed it when the server
// sends no root.
func TestIssuerOfNamesTheRootOfTheChain(t *testing.T) {
	t.Parallel()
	root, rootKey := cert(t, "Example Root CA", true, nil, nil)
	leaf, leafKey := cert(t, "db.example", false, root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	require.Equal(t, "Example Root CA", trustpin.IssuerOf(handshake(t, []*x509.Certificate{leaf}, leafKey, roots)), "verified: the root it verified against")
	require.Equal(t, "Example Root CA", trustpin.IssuerOf(handshake(t, []*x509.Certificate{leaf}, leafKey, nil)), "unverified, no root sent: the leaf's issuer")
	require.Equal(t, "Example Root CA", trustpin.IssuerOf(handshake(t, []*x509.Certificate{leaf, root}, leafKey, nil)), "unverified, root sent: the root")
	require.Empty(t, trustpin.IssuerOf(tls.ConnectionState{}))
}
