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

// rootSHA256 is the SHA-256 of Supabase Root 2021 CA's DER, as Supabase
// publishes it.
const rootSHA256 = "80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA"

const supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"

const connectTimeout = 10 * time.Second

func TestEmbeddedRootIsSupabaseRoot2021(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256(supabaseca.Root().Raw)
	require.Equal(t, rootSHA256, strings.ToUpper(colons(hex.EncodeToString(sum[:]))))
	require.Equal(t, "Supabase Root 2021 CA", supabaseca.Root().Subject.CommonName)
	require.True(t, supabaseca.Root().IsCA)

	b, err := os.ReadFile("prod-ca-2021.crt")
	require.NoError(t, err)
	block, rest := pem.Decode(b)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Empty(t, bytes.TrimSpace(rest), "the file holds exactly one certificate")
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
	cfg, err := pgconn.ParseConfig(dsn)
	require.NoError(t, err)
	supabaseca.Trust(cfg, ca)
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
