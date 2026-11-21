package supabaseca_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/supabaseca"
	"github.com/basaltdbhq/basaltdb/internal/supabaseca/supabasecatest"
)

// rootSHA256 are the SHA-256 fingerprints of Supabase's two roots' DER, by
// file, as Supabase publishes them.
var rootSHA256 = []struct{ file, sum string }{
	{"prod-ca-2021.crt", "80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA"},
	{"prod-ca-2025.crt", "5F:9B:77:95:1A:7A:A1:30:3F:9B:58:EE:A9:BF:A8:9E:35:8C:FD:C1:5F:97:86:FF:10:D4:93:0A:72:2C:9A:E2"},
}

const supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"

const connectTimeout = 10 * time.Second

func TestEmbeddedRootsAreSupabases(t *testing.T) {
	t.Parallel()
	roots := supabaseca.Roots()
	require.Len(t, roots, len(rootSHA256))
	for i, want := range rootSHA256 {
		sum := sha256.Sum256(roots[i].Raw)
		require.Equal(t, want.sum, strings.ToUpper(colons(hex.EncodeToString(sum[:]))), want.file)
		require.Equal(t, "Supabase Root 2021 CA", roots[i].Subject.CommonName, want.file)
		require.True(t, roots[i].IsCA, want.file)

		b, err := os.ReadFile(want.file)
		require.NoError(t, err)
		block, rest := pem.Decode(b)
		require.NotNil(t, block, want.file)
		require.Equal(t, "CERTIFICATE", block.Type, want.file)
		require.Equal(t, roots[i].Raw, block.Bytes, want.file)
		require.Empty(t, bytes.TrimSpace(rest), "%s holds exactly one certificate", want.file)
	}
	roots[0] = nil
	require.NotNil(t, supabaseca.Roots()[0], "Roots returns a copy")
}

func colons(h string) string {
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func TestCovers(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"db.abcdefghijklmnopqrst.supabase.co":    true,
		"aws-0-eu-central-1.pooler.supabase.com": true,
		"aws-1-us-east-1.pooler.supabase.co":     true,
		"DB.ABCDEFGHIJKLMNOPQRST.SUPABASE.CO":    true,
		"db.abcdefghijklmnopqrst.supabase.co.":   true,
		"supabase.co":                            false,
		"supabase.com":                           false,
		"evilsupabase.co":                        false,
		"db.evilsupabase.com":                    false,
		"db.supabase.co.example.com":             false,
		"db.supabase.cofe":                       false,
		"db.example.com":                         false,
		"203.0.113.7":                            false,
		"/var/run/postgresql":                    false,
		"":                                       false,
	} {
		require.Equal(t, want, supabaseca.Covers(host), host)
	}
}

// connect parses dsn, trusts ca as Supabase's root, and logs in to a
// server presenting cert. It returns the login's error.
func connect(t *testing.T, dsn string, ca *x509.Certificate, cert tls.Certificate) error {
	t.Helper()
	return connectTrusting(t, dsn, cert, ca)
}

// connectTrusting is connect with cas as Supabase's roots.
func connectTrusting(t *testing.T, dsn string, cert tls.Certificate, cas ...*x509.Certificate) error {
	t.Helper()
	cfg, err := pgconn.ParseConfig(dsn)
	require.NoError(t, err)
	supabaseca.Trust(cfg, cas...)
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = supabasecatest.Serve(t, cert)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

func dsnFor(host, params string) string {
	return "postgres://basalt_agent_bot:pw@" + host + ":5432/postgres?" + params
}

// refusedPassword is a login that got through TLS: the server answered.
func refusedPassword(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg), "want the server's refusal, got %v", err)
	require.Equal(t, "28P01", pg.Code)
}

func notVerified(t *testing.T, err error) {
	t.Helper()
	var verify *tls.CertificateVerificationError
	require.True(t, errors.As(err, &verify), "want a certificate verification error, got %v", err)
}

// A Supabase host whose chain ends at the Supabase root verifies, with
// verify-full and its host name check.
func TestSupabaseHostVerifies(t *testing.T) {
	t.Parallel()
	for _, host := range []string{supabaseHost, "aws-0-eu-central-1.pooler.supabase.com", "aws-1-us-east-1.pooler.supabase.co"} {
		ca, cert := supabasecatest.Chain(t, host)
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full"), ca, cert))
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full&channel_binding=require"), ca, cert))
	}
}

// With two roots trusted (Supabase has two), a chain from either verifies
// on a Supabase host, and on no other host.
func TestEitherRootVerifies(t *testing.T) {
	t.Parallel()
	caA, certA := supabasecatest.Chain(t, supabaseHost)
	caB, certB := supabasecatest.Chain(t, supabaseHost)
	dsn := dsnFor(supabaseHost, "sslmode=verify-full")
	for _, cert := range []tls.Certificate{certA, certB} {
		refusedPassword(t, connectTrusting(t, dsn, cert, caA, caB))
	}
	_, other := supabasecatest.Chain(t, supabaseHost)
	notVerified(t, connectTrusting(t, dsn, other, caA, caB))
	host := "db.example.com"
	ca1, c1 := supabasecatest.Chain(t, host)
	ca2, c2 := supabasecatest.Chain(t, host)
	for _, cert := range []tls.Certificate{c1, c2} {
		notVerified(t, connectTrusting(t, dsnFor(host, "sslmode=verify-full"), cert, ca1, ca2))
	}
}

// The same kind of chain on any other host is refused: the root is not
// trusted there.
func TestOtherHostsKeepTheSystemRoots(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"db.example.com", "db.evilsupabase.co", "db.supabase.co.example.com"} {
		ca, cert := supabasecatest.Chain(t, host)
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), ca, cert))
	}
}

// The host name is still checked: a certificate for another Supabase host
// is refused.
func TestHostNameStillChecked(t *testing.T) {
	t.Parallel()
	ca, cert := supabasecatest.Chain(t, "db.otherprojectref000000.supabase.co")
	notVerified(t, connect(t, dsnFor(supabaseHost, "sslmode=verify-full"), ca, cert))
}

// A person's sslrootcert wins: the Supabase root is not added to it.
func TestUserRootCertWins(t *testing.T) {
	t.Parallel()
	ca, cert := supabasecatest.Chain(t, supabaseHost)
	other, _ := supabasecatest.Chain(t, supabaseHost)
	file := filepath.Join(t.TempDir(), "root.crt")
	require.NoError(t, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw}), 0o600))
	notVerified(t, connect(t, dsnFor(supabaseHost, "sslmode=verify-full&sslrootcert="+file), ca, cert))

	cfg, err := pgconn.ParseConfig(dsnFor(supabaseHost, "sslmode=verify-full&sslrootcert=system"))
	require.NoError(t, err)
	before := cfg.TLSConfig.RootCAs
	supabaseca.Trust(cfg, ca)
	require.Same(t, before, cfg.TLSConfig.RootCAs, "sslrootcert=system stays the system's roots only")
}

// Only verify-full configs change; each host of a multi-host string is
// matched on its own.
func TestTrustScope(t *testing.T) {
	t.Parallel()
	ca, _ := supabasecatest.Chain(t, supabaseHost)
	for _, mode := range []string{"require", "verify-ca", "prefer", "allow", "disable"} {
		cfg, err := pgconn.ParseConfig(dsnFor(supabaseHost, "sslmode="+mode))
		require.NoError(t, err)
		supabaseca.Trust(cfg, ca)
		for _, tc := range append([]*tls.Config{cfg.TLSConfig}, fallbackTLS(cfg)...) {
			if tc != nil {
				require.Nil(t, tc.RootCAs, mode)
			}
		}
	}

	cfg, err := pgconn.ParseConfig("postgres://u:pw@" + supabaseHost + ",db.example.com/postgres?sslmode=verify-full")
	require.NoError(t, err)
	supabaseca.Trust(cfg, ca)
	require.NotNil(t, cfg.TLSConfig.RootCAs)
	require.Equal(t, supabaseHost, cfg.TLSConfig.ServerName)
	require.Len(t, cfg.Fallbacks, 1)
	require.Equal(t, "db.example.com", cfg.Fallbacks[0].Host)
	require.Nil(t, cfg.Fallbacks[0].TLSConfig.RootCAs, "the other host keeps the system's roots")
}

func fallbackTLS(cfg *pgconn.Config) []*tls.Config {
	out := make([]*tls.Config, 0, len(cfg.Fallbacks))
	for _, fb := range cfg.Fallbacks {
		out = append(out, fb.TLSConfig)
	}
	return out
}
