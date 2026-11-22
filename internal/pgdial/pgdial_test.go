package pgdial_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

func TestDefaultModeUnlessTheStringSetsOne(t *testing.T) {
	t.Parallel()
	cases := map[string]pgx.QueryExecMode{
		"postgres://u:p@h:6543/db?sslmode=disable":                                         pgx.QueryExecModeExec,
		"host=h port=6543 user=u dbname=db":                                                pgx.QueryExecModeExec,
		"postgres://u:p@h:5432/db?default_query_exec_mode=cache_statement":                 pgx.QueryExecModeCacheStatement,
		"postgres://u:p@h:5432/db?sslmode=disable&default_query_exec_mode=simple_protocol": pgx.QueryExecModeSimpleProtocol,
	}
	for dsn, want := range cases {
		cfg, err := pgdial.ConnConfig(dsn)
		require.NoError(t, err, dsn)
		require.Equal(t, want, cfg.DefaultQueryExecMode, dsn)

		pool, err := pgdial.PoolConfig(dsn)
		require.NoError(t, err, dsn)
		require.Equal(t, want, pool.ConnConfig.DefaultQueryExecMode, dsn)
	}
	_, err := pgdial.ConnConfig("postgres://u:p@h:5432/db?default_query_exec_mode=bogus")
	require.Error(t, err)
}

// trusts reports whether pool verifies every one of the named built-in
// profile's own roots.
func trusts(pool *x509.CertPool, profile string) bool {
	for _, root := range trustprofile.BuiltInSet().Named(profile).Certificates() {
		if _, err := root.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			return false
		}
	}
	return true
}

// poolTLS is the TLS config a new connection of pool gets.
func poolTLS(t *testing.T, pool *pgxpool.Config) *tls.Config {
	t.Helper()
	cc := pool.ConnConfig.Copy()
	require.NoError(t, pool.BeforeConnect(context.Background(), cc))
	return cc.TLSConfig
}

// Every connection config trusts a built-in profile's roots for that
// profile's host with verify-full, and not the other profile's, a pool's
// new connections too, and whatever query mode the string sets; other
// hosts keep the system's roots.
func TestBuiltInRootsForTheirHosts(t *testing.T) {
	t.Parallel()
	for dsn, profile := range map[string]string{
		"postgres://u:p@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=verify-full":                                            "supabase",
		"postgres://u:p@aws-0-eu-central-1.pooler.supabase.com:6543/postgres?sslmode=verify-full&default_query_exec_mode=simple_protocol": "supabase",
		"postgres://u:p@mydb.c9akciq32xyz.eu-central-1.rds.amazonaws.com:5432/postgres?sslmode=verify-full":                               "aws-rds",
	} {
		other := "aws-rds"
		if profile == "aws-rds" {
			other = "supabase"
		}
		cfg, err := pgdial.ConnConfig(dsn)
		require.NoError(t, err, dsn)
		require.True(t, trusts(cfg.TLSConfig.RootCAs, profile), dsn)
		require.False(t, trusts(cfg.TLSConfig.RootCAs, other), dsn)
		pool, err := pgdial.PoolConfig(dsn)
		require.NoError(t, err, dsn)
		require.Nil(t, pool.ConnConfig.TLSConfig.RootCAs, "the pool's own config stays as parsed")
		tc := poolTLS(t, pool)
		require.True(t, trusts(tc.RootCAs, profile), dsn)
		require.False(t, trusts(tc.RootCAs, other), dsn)
	}
	cfg, err := pgdial.ConnConfig("postgres://u:p@db.example.com:5432/postgres?sslmode=verify-full")
	require.NoError(t, err)
	require.Nil(t, cfg.TLSConfig.RootCAs)
	pool, err := pgdial.PoolConfig("postgres://u:p@db.example.com:5432/postgres?sslmode=verify-full")
	require.NoError(t, err)
	require.Nil(t, poolTLS(t, pool).RootCAs)
}

// A login through pgdial to a Supabase host whose chain ends at the
// (stand-in) Supabase root verifies; the same chain on another host does not.
func TestConnConfigTrustingVerifiesASupabaseChain(t *testing.T) {
	t.Parallel()
	login := func(host string) error {
		ca, cert := trustprofiletest.Chain(t, host)
		cfg, err := pgdial.ConnConfigTrusting("postgres://u:p@"+host+":5432/postgres?sslmode=verify-full",
			trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}}))
		require.NoError(t, err)
		cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
		cfg.DialFunc = trustprofiletest.Serve(t, cert)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			_ = conn.Close(ctx)
		}
		return err
	}
	var pg *pgconn.PgError
	require.ErrorAs(t, login("db.abcdefghijklmnopqrst.supabase.co"), &pg)
	require.Equal(t, "28P01", pg.Code)
	var verify *tls.CertificateVerificationError
	err := login("db.example.com")
	require.ErrorAs(t, err, &verify)
	require.True(t, pgdial.CertificateNotVerified(err))
	hinted := pgdial.WithCertificateHint("postgres://u:p@db.example.com:5432/postgres?sslmode=verify-full", err)
	require.ErrorAs(t, hinted, &verify)
	require.Contains(t, hinted.Error(), "basalt trust add --name NAME --match '=db.example.com'")
	require.Contains(t, hinted.Error(), "sslrootcert")
	for dsn, want := range map[string]string{
		"postgres://u:p@db.example.com:5432/postgres?sslmode=verify-full&sslrootcert=system": "fix that root file",
		"postgres://u:p@db.example.com:5432/postgres?sslmode=verify-ca":                      "only with sslmode=verify-full",
	} {
		h := pgdial.WithCertificateHint(dsn, err)
		require.Contains(t, h.Error(), want, dsn)
		require.NotContains(t, h.Error(), "basalt trust add", dsn)
	}
	plain := errors.New("connection refused")
	require.Same(t, plain, pgdial.WithCertificateHint("postgres://h/db", plain))
	require.False(t, pgdial.CertificateNotVerified(errors.New("connection refused")))
}

// A pool that could not verify a host verifies it on its next connection
// once the source gives a profile for it: no new pool, no restart. Not
// parallel: it sets the process's trust source.
func TestPoolPicksUpANewProfile(t *testing.T) {
	const host = "db.internal.example.com"
	ca, cert := trustprofiletest.Chain(t, host)
	var set atomic.Pointer[trustprofile.Set]
	set.Store(trustprofile.BuiltInSet())
	pgdial.SetTrust(set.Load)
	t.Cleanup(func() { pgdial.SetTrust(nil) })

	cfg, err := pgdial.PoolConfig("postgres://u:p@" + host + ":5432/postgres?sslmode=verify-full")
	require.NoError(t, err)
	cfg.ConnConfig.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.ConnConfig.DialFunc = trustprofiletest.Serve(t, cert)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	var verify *tls.CertificateVerificationError
	_, err = pool.Exec(ctx, "SELECT 1")
	require.ErrorAs(t, err, &verify)

	applied, _, err := pgdial.TrustOf("postgres://u:p@" + host + "/postgres?sslmode=verify-full")
	require.NoError(t, err)
	require.Equal(t, trustprofile.AppliesSystem, applied.Applies)

	set.Store(trustprofile.NewSet(trustprofile.BuiltIns(),
		[]*trustprofile.Profile{trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, ca)}, nil))
	_, err = pool.Exec(ctx, "SELECT 1")
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg, "the next connection verifies and reaches the login")
	require.Equal(t, "28P01", pg.Code)

	applied, _, err = pgdial.TrustOf("postgres://u:p@" + host + "/postgres?sslmode=verify-full")
	require.NoError(t, err)
	require.Equal(t, trustprofile.AppliesProfile, applied.Applies)
	require.Equal(t, "internal", applied.Profile.Name)
}
