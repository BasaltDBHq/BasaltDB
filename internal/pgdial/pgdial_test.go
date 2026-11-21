package pgdial_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/providerca"
	"github.com/basaltdbhq/basaltdb/internal/providerca/providercatest"
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

// trusts reports whether pool verifies every one of the named provider's
// own roots.
func trusts(pool *x509.CertPool, provider string) bool {
	for _, root := range providerca.Roots(provider) {
		if _, err := root.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			return false
		}
	}
	return true
}

// Every connection config trusts a provider's roots for that provider's
// host with verify-full, and not the other provider's, a pool's too, and
// whatever query mode the string sets; other hosts keep the system's roots.
func TestProviderRootsForProviderHosts(t *testing.T) {
	t.Parallel()
	for dsn, provider := range map[string]string{
		"postgres://u:p@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=verify-full":                                            providerca.Supabase,
		"postgres://u:p@aws-0-eu-central-1.pooler.supabase.com:6543/postgres?sslmode=verify-full&default_query_exec_mode=simple_protocol": providerca.Supabase,
		"postgres://u:p@mydb.c9akciq32xyz.eu-central-1.rds.amazonaws.com:5432/postgres?sslmode=verify-full":                               providerca.RDS,
	} {
		other := providerca.RDS
		if provider == providerca.RDS {
			other = providerca.Supabase
		}
		cfg, err := pgdial.ConnConfig(dsn)
		require.NoError(t, err, dsn)
		require.True(t, trusts(cfg.TLSConfig.RootCAs, provider), dsn)
		require.False(t, trusts(cfg.TLSConfig.RootCAs, other), dsn)
		pool, err := pgdial.PoolConfig(dsn)
		require.NoError(t, err, dsn)
		require.True(t, trusts(pool.ConnConfig.TLSConfig.RootCAs, provider), dsn)
		require.False(t, trusts(pool.ConnConfig.TLSConfig.RootCAs, other), dsn)
	}
	cfg, err := pgdial.ConnConfig("postgres://u:p@db.example.com:5432/postgres?sslmode=verify-full")
	require.NoError(t, err)
	require.Nil(t, cfg.TLSConfig.RootCAs)
	pool, err := pgdial.PoolConfig("postgres://u:p@db.example.com:5432/postgres?sslmode=verify-full")
	require.NoError(t, err)
	require.Nil(t, pool.ConnConfig.TLSConfig.RootCAs)
}

// A login through pgdial to a Supabase host whose chain ends at the
// (stand-in) Supabase root verifies; the same chain on another host does not.
func TestConnConfigTrustingVerifiesASupabaseChain(t *testing.T) {
	t.Parallel()
	login := func(host string) error {
		ca, cert := providercatest.Chain(t, host)
		cfg, err := pgdial.ConnConfigTrusting("postgres://u:p@"+host+":5432/postgres?sslmode=verify-full",
			providerca.Override{providerca.Supabase: {ca}})
		require.NoError(t, err)
		cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
		cfg.DialFunc = providercatest.Serve(t, cert)
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
	require.ErrorAs(t, login("db.example.com"), &verify)
}
