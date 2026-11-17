package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// pgAgent is an agent's Postgres store opened the way the engine opens it,
// for tests that use the store directly before they build the service.
type pgAgent struct {
	store  *agentdb.Store
	reader *agentdb.Reader
}

// newPGAgent opens a pool on the agent's connection string url and wraps it
// in the store and reader, with the default limits and the real clock. Every
// Postgres test in this package builds its wiring here, so a change to the
// wiring is made in one place.
func newPGAgent(t *testing.T, url string, conns int32) pgAgent {
	t.Helper()
	pool, err := agentdb.NewPool(context.Background(), url, conns)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	return pgAgent{
		store:  agentdb.NewStore(pool, limits, time.Now),
		reader: agentdb.NewReader(pool, limits, time.Now),
	}
}

// service builds the agent service over the store; set fills in the rest of
// its dependencies (logger, links, relay and so on).
func (p pgAgent) service(set func(*agent.Deps)) *agent.Service {
	d := agent.Deps{
		Name: "bot", Reader: p.reader, Store: p.store, Reads: p.store, Approvals: p.store, Reverts: p.store,
		Log: quietLog(), Now: time.Now,
	}
	if set != nil {
		set(&d)
	}
	return agent.NewService(d)
}
