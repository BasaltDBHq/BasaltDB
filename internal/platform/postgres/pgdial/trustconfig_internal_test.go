package pgdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// These tests connect, over a fake server's TLS, with the profiles a
// connection string's hosts match (trustConfig) and read what verifies
// them (explainConfig). No database is needed.

const (
	supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"
	rdsHost      = "mydb.cluster-c9akciq32xyz.eu-central-1.rds.amazonaws.com"
)

const connectTimeout = 10 * time.Second

func connect(t *testing.T, dsn string, cert tls.Certificate, set *trustprofile.Set) error {
	t.Helper()
	cfg, err := pgconn.ParseConfig(dsn)
	require.NoError(t, err)
	trustConfig(cfg, set)
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = trustprofiletest.Serve(t, cert)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

func supabaseOnly(t *testing.T, ca ...*x509.Certificate) *trustprofile.Set {
	t.Helper()
	return trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": ca})
}

func dsnFor(host, params string) string {
	return "postgres://basalt_agent_bot" + ":" + "pw@" + host + ":5432/postgres?" + params
}

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

func TestSupabaseHostVerifies(t *testing.T) {
	t.Parallel()
	for _, host := range []string{supabaseHost, "aws-0-eu-central-1.pooler.supabase.com", "aws-1-us-east-1.pooler.supabase.co"} {
		ca, cert := trustprofiletest.Chain(t, host)
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert, supabaseOnly(t, ca)))
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full&channel_binding=require"), cert, supabaseOnly(t, ca)))
	}
}

func TestEitherRootVerifies(t *testing.T) {
	t.Parallel()
	caA, certA := trustprofiletest.Chain(t, supabaseHost)
	caB, certB := trustprofiletest.Chain(t, supabaseHost)
	dsn := dsnFor(supabaseHost, "sslmode=verify-full")
	for _, cert := range []tls.Certificate{certA, certB} {
		refusedPassword(t, connect(t, dsn, cert, supabaseOnly(t, caA, caB)))
	}
	_, other := trustprofiletest.Chain(t, supabaseHost)
	notVerified(t, connect(t, dsn, other, supabaseOnly(t, caA, caB)))
	host := "db.example.com"
	ca1, c1 := trustprofiletest.Chain(t, host)
	ca2, c2 := trustprofiletest.Chain(t, host)
	for _, cert := range []tls.Certificate{c1, c2} {
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert, supabaseOnly(t, ca1, ca2)))
	}
}

// One profile's roots never verify another profile's hosts, built-in or
// operator.
func TestProfilesAreSeparate(t *testing.T) {
	t.Parallel()
	const opHost = "db.internal.example.com"
	hosts := map[string]string{"supabase": supabaseHost, "aws-rds": rdsHost, "mine": opHost, "": "db.example.org"}
	for _, signer := range []string{"supabase", "aws-rds", "mine"} {
		for profile, host := range hosts {
			ca, cert := trustprofiletest.Chain(t, host)
			decoy, _ := trustprofiletest.Chain(t, host)
			pick := func(n string) []*x509.Certificate {
				if n == signer {
					return []*x509.Certificate{ca}
				}
				return []*x509.Certificate{decoy}
			}
			set := trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": pick("supabase"), "aws-rds": pick("aws-rds")},
				trustprofiletest.Profile(t, trustprofile.Operator, "mine", []string{"internal.example.com"}, pick("mine")...))
			err := connect(t, dsnFor(host, "sslmode=verify-full"), cert, set)
			if profile == signer {
				refusedPassword(t, err)
			} else {
				notVerified(t, err)
			}
		}
	}
}

func TestOtherHostsKeepTheSystemRoots(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"db.example.com", "db.evilsupabase.co", "db.supabase.co.example.com", "mydb.evilrds.amazonaws.com", "mydb.rds.amazonaws.com.evil"} {
		ca, cert := trustprofiletest.Chain(t, host)
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert,
			trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}, "aws-rds": {ca}})))
	}
}

func TestHostNameStillChecked(t *testing.T) {
	t.Parallel()
	ca, cert := trustprofiletest.Chain(t, "db.otherprojectref000000.supabase.co")
	notVerified(t, connect(t, dsnFor(supabaseHost, "sslmode=verify-full"), cert, supabaseOnly(t, ca)))
	ca, cert = trustprofiletest.Chain(t, "other.c9akciq32xyz.eu-central-1.rds.amazonaws.com")
	notVerified(t, connect(t, dsnFor(rdsHost, "sslmode=verify-full"), cert, trustprofiletest.Set(t, map[string][]*x509.Certificate{"aws-rds": {ca}})))
}

func TestUserRootCertWins(t *testing.T) {
	t.Parallel()
	for _, host := range []string{supabaseHost, rdsHost} {
		ca, cert := trustprofiletest.Chain(t, host)
		other, _ := trustprofiletest.Chain(t, host)
		set := trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}, "aws-rds": {ca}})
		file := filepath.Join(t.TempDir(), "root.crt")
		require.NoError(t, os.WriteFile(file, trustprofiletest.PEM(other), 0o600))
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full&sslrootcert="+file), cert, set))

		cfg, err := pgconn.ParseConfig(dsnFor(host, "sslmode=verify-full&sslrootcert="+file))
		require.NoError(t, err)
		require.Equal(t, trustprofile.AppliesRootCert, explainConfig(cfg, set).Applies)

		cfg, err = pgconn.ParseConfig(dsnFor(host, "sslmode=verify-full&sslrootcert=system"))
		require.NoError(t, err)
		before := cfg.TLSConfig.RootCAs
		trustConfig(cfg, set)
		require.Same(t, before, cfg.TLSConfig.RootCAs, "sslrootcert=system stays the system's roots only")
	}
}

func TestTrustScope(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, supabaseHost)
	for _, host := range []string{supabaseHost, rdsHost} {
		for _, mode := range []string{"require", "verify-ca", "prefer", "allow", "disable"} {
			cfg, err := pgconn.ParseConfig(dsnFor(host, "sslmode="+mode))
			require.NoError(t, err)
			require.Equal(t, trustprofile.AppliesNotVerified, explainConfig(cfg, trustprofile.BuiltInSet()).Applies, mode)
			trustConfig(cfg, trustprofile.BuiltInSet())
			for _, tc := range append([]*tls.Config{cfg.TLSConfig}, fallbackTLS(cfg)...) {
				if tc != nil {
					require.Nil(t, tc.RootCAs, mode)
				}
			}
		}
	}

	cfg, err := pgconn.ParseConfig("postgres://u" + ":" + "pw@" + supabaseHost + "," + rdsHost + ",db.example.com/postgres?sslmode=verify-full")
	require.NoError(t, err)
	set := supabaseOnly(t, ca)
	a := explainConfig(cfg, set)
	require.Equal(t, trustprofile.AppliesProfile, a.Applies)
	require.Equal(t, "supabase", a.Profile.Name)
	trustConfig(cfg, set)
	require.Equal(t, supabaseHost, cfg.TLSConfig.ServerName)
	_, err = ca.Verify(x509.VerifyOptions{Roots: cfg.TLSConfig.RootCAs})
	require.NoError(t, err, "the Supabase host trusts the Supabase root")
	require.Len(t, cfg.Fallbacks, 2)
	require.Equal(t, rdsHost, cfg.Fallbacks[0].Host)
	rds := cfg.Fallbacks[0].TLSConfig.RootCAs
	require.NotNil(t, rds)
	_, err = ca.Verify(x509.VerifyOptions{Roots: rds})
	require.Error(t, err, "the RDS host does not trust the Supabase root")
	for _, root := range builtInNamed("aws-rds").Certificates() {
		_, err = root.Verify(x509.VerifyOptions{Roots: rds})
		require.NoError(t, err, "the RDS host trusts %s", root.Subject)
	}
	require.Equal(t, "db.example.com", cfg.Fallbacks[1].Host)
	require.Nil(t, cfg.Fallbacks[1].TLSConfig.RootCAs, "the other host keeps the system's roots")

	cfg, err = pgconn.ParseConfig(dsnFor("db.example.com", "sslmode=verify-full"))
	require.NoError(t, err)
	require.Equal(t, trustprofile.AppliesSystem, explainConfig(cfg, set).Applies)
}

func fallbackTLS(cfg *pgconn.Config) []*tls.Config {
	out := make([]*tls.Config, 0, len(cfg.Fallbacks))
	for _, fb := range cfg.Fallbacks {
		out = append(out, fb.TLSConfig)
	}
	return out
}

// builtInNamed is the built-in profile called name, or nil.
func builtInNamed(name string) *trustprofile.Profile {
	for _, p := range trustprofile.BuiltIns() {
		if p.Name == name {
			return p
		}
	}
	return nil
}
