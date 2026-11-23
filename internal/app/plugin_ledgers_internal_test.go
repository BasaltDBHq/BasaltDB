//go:build unix

package app

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost/engine"
)

// The engine's own runtime gives the plugin writer the agent's ledger:
// startAgents maps each agent to its pool and its admission. An admitted
// agent is admitted; an agent served status only (a pending install setup) is
// refused with engine.ErrNotAdmitted.
func TestRuntimeGivesThePluginWriterTheAgentsLedger(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", demoTables, nil)
	r := newRemoteAgent(t, a.URL, guardmodel.SetupAgent)
	cfg, err := config.Load(r.cfgPath)
	require.NoError(t, err)
	env := agentEnv{cfg: cfg, configPath: r.cfgPath, pagesBase: links.DefaultLocal, stateDir: r.dir, pins: &chainpin.Memory{}}
	srv, err := startAgents(context.Background(), cfg, env, map[string]uint32{"bot": 5001}, newAgentRuntime, slog.New(slog.DiscardHandler))
	t.Cleanup(func() {
		for _, c := range srv.closers {
			c()
		}
	})
	require.NoError(t, err)
	l, ok := srv.pluginLedgers["bot"]
	require.True(t, ok, "the runtime's ledger reaches the plugin writer")
	require.NotNil(t, l.db)
	require.NotNil(t, l.admit)
	require.NoError(t, l.admit(context.Background()), "an installed guard admits the agent")

	pending := newRemoteAgent(t, d.NewAgent(t, "other", demoTables, nil).URL, guardmodel.SetupInstall)
	rt := pending.start(t)
	require.ErrorIs(t, pluginAdmit(rt.svc)(context.Background()), engine.ErrNotAdmitted)
}
