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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/trustpin"
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
