package providerca_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/providerca"
	"github.com/basaltdbhq/basaltdb/internal/providerca/providercatest"
)

const (
	supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"
	rdsHost      = "mydb.cluster-c9akciq32xyz.eu-central-1.rds.amazonaws.com"
)

const connectTimeout = 10 * time.Second

func TestFor(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]string{
		"db.abcdefghijklmnopqrst.supabase.co":                      providerca.Supabase,
		"aws-0-eu-central-1.pooler.supabase.com":                   providerca.Supabase,
		"aws-1-us-east-1.pooler.supabase.co":                       providerca.Supabase,
		"DB.ABCDEFGHIJKLMNOPQRST.SUPABASE.CO":                      providerca.Supabase,
		"db.abcdefghijklmnopqrst.supabase.co.":                     providerca.Supabase,
		rdsHost:                                                    providerca.RDS,
		"mydb.c9akciq32xyz.us-east-1.rds.amazonaws.com":            providerca.RDS,
		"mydb.cluster-ro-c9akciq32xyz.us-east-1.rds.amazonaws.com": providerca.RDS,
		"MYDB.C9AKCIQ32XYZ.US-EAST-1.RDS.AMAZONAWS.COM.":           providerca.RDS,
		"mydb.c9akciq32xyz.cn-north-1.rds.amazonaws.com.cn":        providerca.RDS,
		"supabase.co":                 "",
		"supabase.com":                "",
		"rds.amazonaws.com":           "",
		"rds.amazonaws.com.cn":        "",
		"evilsupabase.co":             "",
		"db.evilsupabase.com":         "",
		"db.supabase.co.example.com":  "",
		"db.supabase.cofe":            "",
		"mydb.evilrds.amazonaws.com":  "",
		"mydb.rds.amazonaws.com.evil": "",
		"mydb.rds.amazonaws.co":       "",
		"mydb.s3.amazonaws.com":       "",
		"db.example.com":              "",
		"203.0.113.7":                 "",
		"/var/run/postgresql":         "",
		"":                            "",
	} {
		got, ok := providerca.For(host)
		require.Equal(t, want, got, host)
		require.Equal(t, want != "", ok, host)
	}
}

// connect parses dsn, trusts override's stand-in roots, and logs in to a
// server presenting cert. It returns the login's error.
func connect(t *testing.T, dsn string, cert tls.Certificate, override providerca.Override) error {
	t.Helper()
	cfg, err := pgconn.ParseConfig(dsn)
	require.NoError(t, err)
	providerca.Trust(cfg, override)
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = providercatest.Serve(t, cert)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

// supabaseOnly stands ca in for Supabase's roots.
func supabaseOnly(ca ...*x509.Certificate) providerca.Override {
	return providerca.Override{providerca.Supabase: ca}
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
		ca, cert := providercatest.Chain(t, host)
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert, supabaseOnly(ca)))
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full&channel_binding=require"), cert, supabaseOnly(ca)))
	}
}

// With two roots trusted (Supabase has two), a chain from either verifies
// on a Supabase host, and on no other host.
func TestEitherRootVerifies(t *testing.T) {
	t.Parallel()
	caA, certA := providercatest.Chain(t, supabaseHost)
	caB, certB := providercatest.Chain(t, supabaseHost)
	dsn := dsnFor(supabaseHost, "sslmode=verify-full")
	for _, cert := range []tls.Certificate{certA, certB} {
		refusedPassword(t, connect(t, dsn, cert, supabaseOnly(caA, caB)))
	}
	_, other := providercatest.Chain(t, supabaseHost)
	notVerified(t, connect(t, dsn, other, supabaseOnly(caA, caB)))
	host := "db.example.com"
	ca1, c1 := providercatest.Chain(t, host)
	ca2, c2 := providercatest.Chain(t, host)
	for _, cert := range []tls.Certificate{c1, c2} {
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert, supabaseOnly(ca1, ca2)))
	}
}

// Each provider's roots verify its own hosts only. With a stand-in root for
// each provider trusted at once, a chain from the RDS root verifies on an
// RDS host and is refused on a Supabase host and on any other host; a chain
// from the Supabase root is refused on an RDS host.
func TestProvidersAreSeparate(t *testing.T) {
	t.Parallel()
	hosts := map[string]string{
		providerca.Supabase: supabaseHost,
		providerca.RDS:      rdsHost,
		"":                  "db.example.com",
	}
	for _, signer := range []string{providerca.Supabase, providerca.RDS} {
		for provider, host := range hosts {
			ca, cert := providercatest.Chain(t, host)
			decoy, _ := providercatest.Chain(t, host)
			override := providerca.Override{providerca.Supabase: {decoy}, providerca.RDS: {decoy}}
			override[signer] = []*x509.Certificate{ca}
			err := connect(t, dsnFor(host, "sslmode=verify-full"), cert, override)
			if provider == signer {
				refusedPassword(t, err)
			} else {
				notVerified(t, err)
			}
		}
	}
}

// The same kind of chain on any other host is refused: the root is not
// trusted there.
func TestOtherHostsKeepTheSystemRoots(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"db.example.com", "db.evilsupabase.co", "db.supabase.co.example.com", "mydb.evilrds.amazonaws.com", "mydb.rds.amazonaws.com.evil"} {
		ca, cert := providercatest.Chain(t, host)
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert,
			providerca.Override{providerca.Supabase: {ca}, providerca.RDS: {ca}}))
	}
}

// The host name is still checked: a certificate for another host of the
// same provider is refused.
func TestHostNameStillChecked(t *testing.T) {
	t.Parallel()
	ca, cert := providercatest.Chain(t, "db.otherprojectref000000.supabase.co")
	notVerified(t, connect(t, dsnFor(supabaseHost, "sslmode=verify-full"), cert, supabaseOnly(ca)))
	ca, cert = providercatest.Chain(t, "other.c9akciq32xyz.eu-central-1.rds.amazonaws.com")
	notVerified(t, connect(t, dsnFor(rdsHost, "sslmode=verify-full"), cert, providerca.Override{providerca.RDS: {ca}}))
}

// A person's sslrootcert wins: no provider's root is added to it.
func TestUserRootCertWins(t *testing.T) {
	t.Parallel()
	for _, host := range []string{supabaseHost, rdsHost} {
		ca, cert := providercatest.Chain(t, host)
		other, _ := providercatest.Chain(t, host)
		override := providerca.Override{providerca.Supabase: {ca}, providerca.RDS: {ca}}
		file := filepath.Join(t.TempDir(), "root.crt")
		require.NoError(t, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw}), 0o600))
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full&sslrootcert="+file), cert, override))

		cfg, err := pgconn.ParseConfig(dsnFor(host, "sslmode=verify-full&sslrootcert=system"))
		require.NoError(t, err)
		before := cfg.TLSConfig.RootCAs
		providerca.Trust(cfg, override)
		require.Same(t, before, cfg.TLSConfig.RootCAs, "sslrootcert=system stays the system's roots only")
	}
}

// Only verify-full configs change; each host of a multi-host string is
// matched on its own and gets its own provider's pool.
func TestTrustScope(t *testing.T) {
	t.Parallel()
	ca, _ := providercatest.Chain(t, supabaseHost)
	for _, host := range []string{supabaseHost, rdsHost} {
		for _, mode := range []string{"require", "verify-ca", "prefer", "allow", "disable"} {
			cfg, err := pgconn.ParseConfig(dsnFor(host, "sslmode="+mode))
			require.NoError(t, err)
			providerca.Trust(cfg, nil)
			for _, tc := range append([]*tls.Config{cfg.TLSConfig}, fallbackTLS(cfg)...) {
				if tc != nil {
					require.Nil(t, tc.RootCAs, mode)
				}
			}
		}
	}

	cfg, err := pgconn.ParseConfig("postgres://u:pw@" + supabaseHost + "," + rdsHost + ",db.example.com/postgres?sslmode=verify-full")
	require.NoError(t, err)
	providerca.Trust(cfg, supabaseOnly(ca))
	require.Equal(t, supabaseHost, cfg.TLSConfig.ServerName)
	_, err = ca.Verify(x509.VerifyOptions{Roots: cfg.TLSConfig.RootCAs})
	require.NoError(t, err, "the Supabase host trusts the Supabase root")
	require.Len(t, cfg.Fallbacks, 2)
	require.Equal(t, rdsHost, cfg.Fallbacks[0].Host)
	rds := cfg.Fallbacks[0].TLSConfig.RootCAs
	require.NotNil(t, rds)
	_, err = ca.Verify(x509.VerifyOptions{Roots: rds})
	require.Error(t, err, "the RDS host does not trust the Supabase root")
	for _, root := range providerca.Roots(providerca.RDS) {
		_, err = root.Verify(x509.VerifyOptions{Roots: rds})
		require.NoError(t, err, "the RDS host trusts %s", root.Subject)
	}
	require.Equal(t, "db.example.com", cfg.Fallbacks[1].Host)
	require.Nil(t, cfg.Fallbacks[1].TLSConfig.RootCAs, "the other host keeps the system's roots")
}

func fallbackTLS(cfg *pgconn.Config) []*tls.Config {
	out := make([]*tls.Config, 0, len(cfg.Fallbacks))
	for _, fb := range cfg.Fallbacks {
		out = append(out, fb.TLSConfig)
	}
	return out
}
