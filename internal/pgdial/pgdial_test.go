package pgdial_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
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
