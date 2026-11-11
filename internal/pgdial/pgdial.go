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
package pgdial

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// execModeKey is pgx's connection string setting for the query mode.
const execModeKey = "default_query_exec_mode"

// DefaultMode is the query mode of every Basalt connection unless the
// connection string sets one.
const DefaultMode = pgx.QueryExecModeExec

// ConnConfig parses dsn and applies DefaultMode.
func ConnConfig(dsn string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	apply(dsn, cfg)
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

// PoolConfig parses dsn for a pool and applies DefaultMode.
func PoolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	apply(dsn, cfg.ConnConfig)
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
