package trustpin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// recorder is a Postgres server that answers the SSLRequest, completes TLS
// with cert, and records every byte the client sends after the handshake.
type recorder struct {
	mu    sync.Mutex
	after []byte
	done  chan struct{}
}

func serve(t *testing.T, cert tls.Certificate) (*recorder, trustpin.Dial) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	r := &recorder{done: make(chan struct{})}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer close(r.done)
		defer c.Close()
		var req [8]byte
		if _, err := io.ReadFull(c, req[:]); err != nil || binary.BigEndian.Uint32(req[4:]) != 80877103 {
			return
		}
		_, _ = c.Write([]byte{'S'})
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if tc.Handshake() != nil {
			return
		}
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(tc)
		r.mu.Lock()
		r.after = b
		r.mu.Unlock()
	}()
	addr := ln.Addr().String()
	return r, func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// Fetch reads the chain and sends nothing after the TLS handshake: no
// startup message, no user, no password.
func TestFetchSendsOnlyTheHandshake(t *testing.T) {
	t.Parallel()
	const host = "db.internal.example.com"
	ca, cert := trustprofiletest.Chain(t, host)
	rec, dial := serve(t, cert)
	chain, err := trustpin.Fetch(context.Background(), dial, host, 5432)
	require.NoError(t, err)
	<-rec.done
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Empty(t, rec.after, "nothing but the handshake")
	seen := trustpin.Check(append(chain, ca), host, time.Now())
	require.Equal(t, trustprofile.DERSHA256(ca), seen.SHA256)
	require.True(t, seen.Full)
	require.False(t, seen.System)
	require.False(t, seen.NameOnly)
}

// A leaf that does not name the host verifies against the top only without
// the name: NameOnly, the one case verify: ca is offered for.
func TestCheckNameOnly(t *testing.T) {
	t.Parallel()
	ca, cert := trustprofiletest.Chain(t, "other.example.com")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	seen := trustpin.Check([]*x509.Certificate{leaf, ca}, "203.0.113.7", time.Now())
	require.False(t, seen.Full)
	require.True(t, seen.NameOnly)

	other, _ := trustprofiletest.Chain(t, "x")
	seen = trustpin.Check([]*x509.Certificate{leaf, other}, "203.0.113.7", time.Now())
	require.False(t, seen.Full)
	require.False(t, seen.NameOnly, "a chain that does not end at its top is no name-only failure")
}

// A server that refuses TLS is ErrNoTLS.
func TestFetchNoTLS(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		var req [8]byte
		_, _ = io.ReadFull(c, req[:])
		_, _ = c.Write([]byte{'N'})
		_ = c.Close()
	}()
	addr := ln.Addr().String()
	_, err = trustpin.Fetch(context.Background(), func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}, "db.example.com", 5432)
	require.ErrorIs(t, err, trustpin.ErrNoTLS)
}

var _ = selfSigned

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

// Approved pins only the top the person approved, and only one the chain
// verifies against: verify-full when the leaf names the host, ca when not.
func TestApproved(t *testing.T) {
	t.Parallel()
	const host = "db.example.com"
	ca, cert := trustprofiletest.Chain(t, host)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	chain := []*x509.Certificate{leaf, ca}
	fp := trustprofile.DERSHA256(ca)

	seen, pin, err := trustpin.Approved(chain, host, time.Now(), fp)
	require.NoError(t, err)
	require.Equal(t, fp, seen.SHA256)
	require.Equal(t, trustprofile.PinName(host), pin.Name)
	require.Equal(t, []string{"=" + host}, pin.Match)
	require.NotEqual(t, trustprofile.VerifyCA, pin.Verify)

	_, pin, err = trustpin.Approved(chain, "203.0.113.7", time.Now(), fp)
	require.NoError(t, err, "a leaf that does not name the host pins with verify: ca")
	require.Equal(t, trustprofile.VerifyCA, pin.Verify)

	other, _ := trustprofiletest.Chain(t, host)
	for name, approved := range map[string]string{
		"another root": trustprofile.DERSHA256(other),
		"upper case":   strings.ToUpper(fp),
		"with colons":  fp[:2] + ":" + fp[2:],
		"empty":        "",
	} {
		_, pin, err := trustpin.Approved(chain, host, time.Now(), approved)
		require.ErrorIs(t, err, trustpin.ErrMismatch, name)
		require.Nil(t, pin, name)
	}

	// A top the leaf does not chain to cannot be pinned, even approved.
	broken := []*x509.Certificate{leaf, other}
	_, pin, err = trustpin.Approved(broken, host, time.Now(), trustprofile.DERSHA256(other))
	require.ErrorIs(t, err, trustpin.ErrNotPinnable)
	require.Nil(t, pin)
}

func TestValidSHA256AndSubject(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, "x")
	require.True(t, trustpin.ValidSHA256(trustprofile.DERSHA256(ca)))
	require.False(t, trustpin.ValidSHA256(strings.Repeat("g", 64)))
	require.False(t, trustpin.ValidSHA256(strings.Repeat("a", 63)))
	seen := trustpin.Check([]*x509.Certificate{ca}, "x", time.Now())
	require.Equal(t, "CN=trustprofiletest root", seen.Subject())
	long := *ca
	long.Subject = pkix.Name{CommonName: strings.Repeat("é", 600)}
	require.Len(t, []rune(trustpin.Seen{Top: &long}.Subject()), 512)
}

// A chain from an authority in the system's trust store is never pinned,
// whatever is approved: with the name it needs no pin, and without it a
// verify: ca pin would accept anything that authority issues as the host.
// It covers a top that is a store root and a leaf that chains to one (the
// root not sent). Not parallel: it swaps the system's store.
func TestPublicChainsAreNeverPinned(t *testing.T) {
	ca, cert := trustprofiletest.Chain(t, "other.example.com")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	store := x509.NewCertPool()
	store.AddCert(ca)
	defer trustprofile.SetSystemRootsForTest(store)()

	for name, chain := range map[string][]*x509.Certificate{
		"the top is a store root": {leaf, ca},
		"the leaf chains to one":  {leaf},
	} {
		seen := trustpin.Check(chain, "db.example.com", time.Now())
		require.True(t, seen.Public, name)
		require.False(t, seen.System, name)
		require.False(t, seen.Pinnable(), name)
		_, pin, err := trustpin.Approved(chain, "db.example.com", time.Now(), seen.SHA256)
		require.ErrorIs(t, err, trustpin.ErrPublic, name)
		require.Nil(t, pin, name)
	}
	seen := trustpin.Check([]*x509.Certificate{leaf, ca}, "other.example.com", time.Now())
	require.True(t, seen.System)
	require.True(t, seen.Public, "a chain that verifies needs no pin either")
}
