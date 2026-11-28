package app

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"testing"
	"time"

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
	require.Nil(t, setupJobs(config.Config{OperatedBy: "AGENT"}, path, setup.PageOrigin, log, nil, nil, nil))
	require.Nil(t, setupJobs(config.Config{}, path, "http://localhost:9999", log, nil, nil, nil))
	if os.Geteuid() == 0 {
		t.Skip("as root, setupJobs serves nothing")
	}
	require.NotNil(t, setupJobs(config.Config{}, path, setup.PageOrigin, log, nil, nil, nil))
}

// Setting up again on an engine the page removed is a first install on the
// running engine's setup: it records the engine's key in the same state
// directory as the install of an engine with no config (WaitForConfig).
func TestSetupJobsInstallWithTheOptionsOfAFirstInstall(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("as root, setupJobs serves nothing")
	}
	path := t.TempDir() + "/engine.json"
	jobs := setupJobs(config.Config{}, path, setup.PageOrigin, slog.New(slog.DiscardHandler), nil, nil, nil)
	configured, ok := jobs.(*setup.LocalService)
	require.True(t, ok)
	first, err := newLocalSetup(setup.LocalOptions{ConfigPath: path, Origin: setup.PageOrigin, StateDir: WaitOptions{}.StateDir})
	require.NoError(t, err)
	require.Equal(t, first.StateDir(), configured.StateDir())
	require.Equal(t, config.DefaultStateDir(runtime.GOOS), configured.StateDir())
}

// The engine builds the setup page's jobs again each time it serves its
// config again, and the marks of what the page finished (a fix, an Update)
// are the engine's, so the new jobs still answer basalt init's probe.
func TestSetupJobsShareTheEnginesMarksAcrossAReload(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("as root, setupJobs serves nothing")
	}
	path := t.TempDir() + "/engine.json"
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	log := slog.New(slog.DiscardHandler)
	marks := setup.NewMarks()
	before := time.Now().Add(-time.Minute)
	marks.MarkFixed("demo_bot", setup.JobTrust, time.Now())
	marks.MarkUpdated("sales_bot", time.Now())

	first := setupJobs(config.Config{}, path, setup.PageOrigin, log, nil, nil, marks)
	second := setupJobs(config.Config{}, path, setup.PageOrigin, log, nil, nil, marks)
	require.NotSame(t, first, second)
	for _, jobs := range []any{first, second} {
		svc, ok := jobs.(*setup.LocalService)
		require.True(t, ok)
		_, err := svc.Check(context.Background(), setup.Request{Agent: "demo_bot", Since: &before})
		var r *setup.RefusalError
		require.ErrorAs(t, err, &r)
		require.Equal(t, setup.CodeChangedPrefix+setup.JobTrust, r.Code)
		_, err = svc.Check(context.Background(), setup.Request{Agent: "sales_bot", Since: &before})
		require.ErrorAs(t, err, &r)
		require.Equal(t, setup.CodeGuardUpdated, r.Code)
	}
}
