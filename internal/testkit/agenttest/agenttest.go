// Package agenttest is the Postgres test harness of the agent services: a
// service wired to a real database the way the engine wires it, for the tests of
// the agent and of the packages that take over its use cases.
package agenttest

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// UseStore binds every port of d that reads the agent's store to s.
func UseStore(d *agent.Deps, s agent.SQLStore) {
	d.Core.Store, d.Write.Store, d.Approval.Store, d.Revert.Store, d.Status.Passkeys = s, s, s, s, s
}

// ToolError and ServiceManager are the adapters' values, as the
// app wires them.
func ToolError(err error) *toolresult.ToolError { return app.AgentErrors().ToolError(err) }

func ServiceManager() agent.ServiceManager { return app.AgentServiceManager() }

// PgWiring is what PgService builds the service from; a PgOption changes it.
type PgWiring struct {
	limits   sqlguard.Limits
	conns    int32
	poolCfg  func(*pgxpool.Config)
	budgeted bool
	returned postgres.ReturnedFunc
	deps     []func(*agent.Deps, *pgxpool.Pool)
}

type PgOption func(*PgWiring)

// WithLimits runs the service with the given limits instead of the defaults.
func WithLimits(l sqlguard.Limits) PgOption { return func(w *PgWiring) { w.limits = l } }

// WithConns sets the pool's size (2 by default).
func WithConns(n int32) PgOption { return func(w *PgWiring) { w.conns = n } }

// WithPoolConfig changes the pool's configuration before it is opened.
func WithPoolConfig(f func(*pgxpool.Config)) PgOption { return func(w *PgWiring) { w.poolCfg = f } }

// WithBudget charges every read of a call to its result budget, as the
// engine runs it.
func WithBudget() PgOption { return func(w *PgWiring) { w.budgeted = true } }

// WithReturned sets the store's hook for the values a call returned.
func WithReturned(f postgres.ReturnedFunc) PgOption { return func(w *PgWiring) { w.returned = f } }

// WithDeps changes the service's dependencies after the Postgres ones are
// filled in, to add optional ones or to wrap a store. It also gets the pool,
// for the dependencies that read the database themselves.
func WithDeps(f func(*agent.Deps, *pgxpool.Pool)) PgOption {
	return func(w *PgWiring) { w.deps = append(w.deps, f) }
}

// PgEnv is a service wired to Postgres, with the parts tests reach for.
type PgEnv struct {
	Svc    *agent.Service
	Pool   *pgxpool.Pool
	Store  *postgres.Store
	Reader *postgres.Reader
}

// PgService builds an agent service the way the engine does for one agent
// whose connection string is url: a pool, the store, the reader, the default
// limits and the real clock. Every Postgres test builds its service here, so
// a change to the wiring is made in one place.
func PgService(t *testing.T, url string, opts ...PgOption) PgEnv {
	t.Helper()
	w := &PgWiring{limits: sqlguard.DefaultLimits(), conns: 2}
	for _, o := range opts {
		o(w)
	}
	var pool *pgxpool.Pool
	if w.poolCfg == nil {
		var err error
		pool, err = postgres.NewPool(context.Background(), url, w.conns)
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
	store := postgres.NewStore(db, w.limits, time.Now)
	if w.returned != nil {
		store = store.WithReturned(w.returned)
	}
	reader := postgres.NewReader(db, w.limits, time.Now)
	d := app.AgentHostDeps()
	d.Core.Name, d.Core.Log, d.Core.Now = "bot", slog.New(slog.DiscardHandler), time.Now
	UseStore(&d, store)
	for _, f := range w.deps {
		f(&d, pool)
	}
	return PgEnv{Svc: agent.NewService(d), Pool: pool, Store: store, Reader: reader}
}
