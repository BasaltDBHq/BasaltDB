// Package pgdial opens every Basalt connection to Postgres: the engine's
// agent pools and the CLI's connections (init, uninstall, log, approve,
// revert). They work through a transaction-mode pooler (Supavisor on port
// 6543, PgBouncer) without the person changing the connection string.
//
// pgx's default caches named prepared statements per client connection. A
// transaction pooler hands each transaction a different server connection,
// so a cached name is missing there ("does not exist") or another client
// already prepared it ("already exists", 42P05). QueryExecModeExec sends
// Parse, Bind and Execute of an unnamed statement in one round trip, which
// no pooler can split. Parameters are sent in text form with the types
// their Go values imply. A connection string that sets
// default_query_exec_mode keeps its own mode.
//
// Every connection also trusts a provider's root certificates for that
// provider's hosts (Supabase, Amazon RDS) with sslmode=verify-full (package
// providerca), so the agent's credential, the hand-off probe and init's
// probes verify those providers' certificates without an sslrootcert.
package pgdial

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/internal/providerca"
)

// execModeKey is pgx's connection string setting for the query mode.
const execModeKey = "default_query_exec_mode"

// DefaultMode is the query mode of every Basalt connection unless the
// connection string sets one.
const DefaultMode = pgx.QueryExecModeExec

// ConnConfig parses dsn, applies DefaultMode and trusts each provider's
// roots for its hosts.
func ConnConfig(dsn string) (*pgx.ConnConfig, error) {
	return ConnConfigTrusting(dsn, nil)
}

// ConnConfigTrusting is ConnConfig with override's roots in place of the
// providers' it names: tests give test CAs to stand in for them.
func ConnConfigTrusting(dsn string, override providerca.Override) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	apply(dsn, cfg)
	providerca.Trust(&cfg.Config, override)
	return cfg, nil
}

// Connect opens one connection to dsn with DefaultMode.
func Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	cfg, err := ConnConfig(dsn)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

// PoolConfig parses dsn for a pool, applies DefaultMode and trusts each
// provider's roots for its hosts.
func PoolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	apply(dsn, cfg.ConnConfig)
	providerca.Trust(&cfg.ConnConfig.Config, nil)
	return cfg, nil
}

// apply sets DefaultMode unless dsn names a mode itself (pgx has already
// parsed it into cfg then).
func apply(dsn string, cfg *pgx.ConnConfig) {
	if strings.Contains(dsn, execModeKey) {
		return
	}
	cfg.DefaultQueryExecMode = DefaultMode
}
