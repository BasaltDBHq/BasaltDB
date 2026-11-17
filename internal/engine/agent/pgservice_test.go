package agent_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// pgWiring is what pgService builds the service from; a pgOption changes it.
type pgWiring struct {
	limits   sqlguard.Limits
	conns    int32
	poolCfg  func(*pgxpool.Config)
	budgeted bool
	returned agentdb.ReturnedFunc
	deps     []func(*agent.Deps, *pgxpool.Pool)
}

type pgOption func(*pgWiring)

// withLimits runs the service with the given limits instead of the defaults.
func withLimits(l sqlguard.Limits) pgOption { return func(w *pgWiring) { w.limits = l } }

// withConns sets the pool's size (2 by default).
func withConns(n int32) pgOption { return func(w *pgWiring) { w.conns = n } }

// withPoolConfig changes the pool's configuration before it is opened.
func withPoolConfig(f func(*pgxpool.Config)) pgOption { return func(w *pgWiring) { w.poolCfg = f } }

// withBudget charges every read of a call to its result budget, as the
// engine runs it.
func withBudget() pgOption { return func(w *pgWiring) { w.budgeted = true } }

// withReturned sets the store's hook for the values a call returned.
func withReturned(f agentdb.ReturnedFunc) pgOption { return func(w *pgWiring) { w.returned = f } }

// withDeps changes the service's dependencies after the Postgres ones are
// filled in, to add optional ones or to wrap a store. It also gets the pool,
// for the dependencies that read the database themselves.
func withDeps(f func(*agent.Deps, *pgxpool.Pool)) pgOption {
	return func(w *pgWiring) { w.deps = append(w.deps, f) }
}

// pgEnv is a service wired to Postgres, with the parts tests reach for.
type pgEnv struct {
	Svc    *agent.Service
	Pool   *pgxpool.Pool
	Store  *agentdb.Store
	Reader *agentdb.Reader
}

// pgService builds an agent service the way the engine does for one agent
// whose connection string is url: a pool, the store, the reader, the default
// limits and the real clock. Every Postgres test builds its service here, so
// a change to the wiring is made in one place.
func pgService(t *testing.T, url string, opts ...pgOption) pgEnv {
	t.Helper()
	w := &pgWiring{limits: sqlguard.DefaultLimits(), conns: 2}
	for _, o := range opts {
		o(w)
	}
	var pool *pgxpool.Pool
	if w.poolCfg == nil {
		var err error
		pool, err = agentdb.NewPool(context.Background(), url, w.conns)
		require.NoError(t, err)
	} else {
		cfg, err := pgdial.PoolConfig(url)
		require.NoError(t, err)
		cfg.MaxConns = w.conns
		w.poolCfg(cfg)
		pool, err = pgxpool.NewWithConfig(context.Background(), cfg)
		require.NoError(t, err)
	}
	t.Cleanup(pool.Close)
	db := resultsize.Pool(pool)
	if w.budgeted {
		db = resultsize.Budgeted(pool)
	}
	store := agentdb.NewStore(db, w.limits, time.Now)
	if w.returned != nil {
		store = store.WithReturned(w.returned)
	}
	reader := agentdb.NewReader(db, w.limits, time.Now)
	d := agent.Deps{
		Name: "bot", Reader: reader, Store: store, Reads: store, Approvals: store, Reverts: store,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
	}
	for _, f := range w.deps {
		f(&d, pool)
	}
	return pgEnv{Svc: agent.NewService(d), Pool: pool, Store: store, Reader: reader}
}
