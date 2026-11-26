package app

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

func TestAgentCommandsCarryTheUpdateLinkOnlyWhereTheSetupJobsRun(t *testing.T) {
	t.Parallel()
	a := config.Agent{Name: "demo_bot", OSUser: "alice", Store: config.PostgresStore("/c/demo_bot.url")}
	cfg := config.Config{Mode: config.ModeService}

	cmds, err := agentEnv{cfg: cfg}.commands(a)
	require.NoError(t, err)
	require.Empty(t, cmds.UpdateLinkURL(), "no setup jobs, no link: the steps keep basalt init")

	cmds, err = agentEnv{cfg: cfg, setupOrigin: setup.PageOrigin}.commands(a)
	require.NoError(t, err)
	want, err := localsetup.Link(setup.PageOrigin, localsetup.Job{Job: setup.JobUpdate, Agent: "demo_bot", OSUser: "alice"})
	require.NoError(t, err)
	require.Equal(t, want, cmds.UpdateLinkURL())
}

func TestSetupJobsRunOnlyOnAPersonOperatedEngineAtTheSetupOrigin(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/engine.json"
	log := slog.New(slog.DiscardHandler)
	require.Nil(t, setupJobs(config.Config{OperatedBy: "AGENT"}, path, setup.PageOrigin, log, nil))
	require.Nil(t, setupJobs(config.Config{}, path, "http://localhost:9999", log, nil))
	if os.Geteuid() == 0 {
		t.Skip("as root, setupJobs serves nothing")
	}
	require.NotNil(t, setupJobs(config.Config{}, path, setup.PageOrigin, log, nil))
}
