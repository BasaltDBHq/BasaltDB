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
// Every connection with sslmode=verify-full also trusts the roots of the
// trust profile that matches its host (package trustprofile): the built-in
// profiles (Supabase, Amazon RDS) and the operator's own in trust.d, which
// the process names with SetTrust. So the agent's credential, the hand-off
// probe and init's probes verify those hosts' certificates without an
// sslrootcert. A single connection reads the profiles when its config is
// parsed; a pool reads them again for each new connection, so a profile the
// operator adds applies from the next connection on, with no restart.
package pgdial

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// trustSource gives the trust profiles a new connection uses; nil is the
// built-in profiles alone.
var trustSource atomic.Pointer[func() *trustprofile.Set]

// SetTrust makes every connection opened from now on use the profiles src
// returns, read for each connection (the engine and the CLI pass the
// operator's trust.d with the built-in profiles). nil restores the
// built-in profiles alone.
func SetTrust(src func() *trustprofile.Set) {
	if src == nil {
		trustSource.Store(nil)
		return
	}
	trustSource.Store(&src)
}

// Trust is the trust profiles a connection opened now uses.
func Trust() *trustprofile.Set {
	if src := trustSource.Load(); src != nil {
		return (*src)()
	}
	return trustprofile.BuiltInSet()
}

// execModeKey is pgx's connection string setting for the query mode.
const execModeKey = "default_query_exec_mode"

// DefaultMode is the query mode of every Basalt connection unless the
// connection string sets one.
const DefaultMode = pgx.QueryExecModeExec

// ConnConfig parses dsn, applies DefaultMode and trusts the roots of the
// profile that matches each host (Trust).
func ConnConfig(dsn string) (*pgx.ConnConfig, error) {
	return ConnConfigTrusting(dsn, nil)
}

// ConnConfigTrusting is ConnConfig with set's profiles in place of Trust's;
// nil is Trust's. Tests give test CAs to stand in for a provider's roots.
func ConnConfigTrusting(dsn string, set *trustprofile.Set) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	apply(dsn, cfg)
	if set == nil {
		set = Trust()
	}
	trustprofile.Trust(&cfg.Config, set)
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

// PoolConfig parses dsn for a pool and applies DefaultMode. Its
// BeforeConnect trusts, on each new connection's copy of the config, the
// roots of the profile that matches each host as Trust gives them then. A
// caller that sets its own BeforeConnect calls the one it replaces first.
func PoolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	apply(dsn, cfg.ConnConfig)
	cfg.BeforeConnect = func(_ context.Context, cc *pgx.ConnConfig) error {
		trustprofile.Trust(&cc.Config, Trust())
		return nil
	}
	return cfg, nil
}

// TrustOf is what verifies the certificate of dsn's first host (TrustOfConfig).
func TrustOf(dsn string) (trustprofile.Applied, []trustprofile.Refused, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return trustprofile.Applied{}, nil, err
	}
	a, refused := TrustOfConfig(cfg)
	return a, refused, nil
}

// TrustOfConfig is what verifies the certificate of cfg's first host, a
// config as parsed (a pool's own, before BeforeConnect): the profile Trust
// gives now, the connection's own sslrootcert, the system's authorities,
// or nothing (sslmode below verify-full); and the operator files Trust
// refused.
func TrustOfConfig(cfg *pgconn.Config) (trustprofile.Applied, []trustprofile.Refused) {
	set := Trust()
	return trustprofile.Explain(cfg, set), set.Refused()
}

// CertificateNotVerified reports whether err is a server certificate that
// did not verify (trustprofile.CertificateNotVerified).
func CertificateNotVerified(err error) bool { return trustprofile.CertificateNotVerified(err) }

// WithCertificateHint is err, when it is a certificate of dsn's host that
// did not verify, with what to do: add the host's CA as a trust profile, or
// name it with sslrootcert. Any other err is returned as it is.
func WithCertificateHint(dsn string, err error) error {
	if !CertificateNotVerified(err) {
		return err
	}
	host := "the database's host"
	if cfg, perr := pgconn.ParseConfig(dsn); perr == nil && cfg.Host != "" {
		host = cfg.Host
	}
	return fmt.Errorf("%w; the certificate of %s does not verify: add its CA with basalt trust add --name NAME --match '=%s' --ca <CA file>, "+
		"or name it with sslrootcert=<CA file> in the connection string", err, host, host)
}

// apply sets DefaultMode unless dsn names a mode itself (pgx has already
// parsed it into cfg then).
func apply(dsn string, cfg *pgx.ConnConfig) {
	if strings.Contains(dsn, execModeKey) {
		return
	}
	cfg.DefaultQueryExecMode = DefaultMode
}
