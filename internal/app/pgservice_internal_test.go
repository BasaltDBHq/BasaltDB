package app

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// pgAgent is an agent's Postgres store opened the way the engine opens it,
// for tests that use the store directly before they build the service.
type pgAgent struct {
	store  *postgres.Store
	reader *postgres.Reader
}

// newPGAgent opens a pool on the agent's connection string url and wraps it
// in the store and reader, with the default limits and the real clock. Every
// Postgres test in this package builds its wiring here, so a change to the
// wiring is made in one place.
func newPGAgent(t *testing.T, url string, conns int32) pgAgent {
	t.Helper()
	pool, err := postgres.NewPool(context.Background(), url, conns)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	return pgAgent{
		store:  postgres.NewStore(pool, limits, time.Now),
		reader: postgres.NewReader(pool, limits, time.Now),
	}
}

// testAgentDeps are the dependencies of an agent named name over store: the
// adapters' ones as the engine wires them, a quiet log and the real clock.
func testAgentDeps(name string, store agent.SQLStore) agent.Deps {
	d := AgentHostDeps()
	d.Core.Name, d.Core.Log, d.Core.Now = name, quietLog(), time.Now
	d.Core.Store, d.Write.Store, d.Approval.Store, d.Revert.Store, d.Status.Passkeys = store, store, store, store, store
	return d
}

// service builds the agent service over the store; set fills in the rest of
// its dependencies (logger, links, relay and so on).
func (p pgAgent) service(set func(*agent.Deps)) *agent.Service {
	d := testAgentDeps("bot", p.store)
	if set != nil {
		set(&d)
	}
	return agent.NewService(d)
}
