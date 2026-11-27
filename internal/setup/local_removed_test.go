package setup_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// removedService is the setup of an engine that ran with config, whose
// engine.json a REMOVE deleted: the file is not there. Nothing here
// connects to a database.
func removedService(t *testing.T, configured bool, now *time.Time) (*setup.LocalService, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.json")
	svc, err := setup.NewLocal(setup.LocalOptions{
		Backend:    setupbackend.Backend{},
		ConfigPath: path, Origin: origin, Users: fakeUsers{}, Configured: configured,
		Now: func() time.Time { return *now },
		Dial: func(context.Context, string) (setup.Conn, error) {
			return nil, errors.New("no database in this test")
		},
	})
	require.NoError(t, err)
	return svc, path
}

// The page's "Remove it from this computer too" only leaves a mark that
// basalt init's probe reads once, within five minutes; until then, and
// after, the probe and every job but an INSTALL answer ENGINE_REMOVED.
func TestRemoveEngineIsOnlyAMarkForBasaltInit(t *testing.T) {
	t.Parallel()
	now := time.Now()
	svc, _ := removedService(t, true, &now)
	ctx := context.Background()

	_, err := svc.Check(ctx, setup.Request{})
	refusal(t, err, setup.CodeEngineRemoved)
	require.NoError(t, svc.RemoveEngine(ctx))
	_, err = svc.Check(ctx, setup.Request{Job: setup.JobUpdate, Agent: "demo_bot", OSUser: "alice"})
	refusal(t, err, setup.CodeEngineRemoved)
	_, err = svc.Run(ctx, setup.Request{})
	refusal(t, err, setup.CodeEngineRemoved) // only the probe reads the press
	_, err = svc.Check(ctx, setup.Request{})
	refusal(t, err, setup.CodeRemoveAsked)
	_, err = svc.Check(ctx, setup.Request{})
	refusal(t, err, setup.CodeEngineRemoved) // answered once

	require.NoError(t, svc.RemoveEngine(ctx))
	now = now.Add(6 * time.Minute)
	_, err = svc.Check(ctx, setup.Request{})
	refusal(t, err, setup.CodeEngineRemoved) // a press older than five minutes is gone
}

// Only a removed engine takes the press: not one with its config, nor one
// that waits for a first install (a reboot after the removal).
func TestRemoveEngineNeedsARemovedEngine(t *testing.T) {
	t.Parallel()
	now := time.Now()
	waiting, _ := removedService(t, false, &now)
	refusal(t, waiting.RemoveEngine(context.Background()), setup.CodeJobUnavailable)

	set, path := removedService(t, true, &now)
	require.NoError(t, config.WriteFile(path, []byte("{}\n")))
	refusal(t, set.RemoveEngine(context.Background()), setup.CodeJobUnavailable)
}

// An INSTALL on a removed engine runs as a first install: it is checked
// as one (here its agent name is refused before anything connects), not
// answered ENGINE_REMOVED.
func TestAnInstallOnARemovedEngineIsAFirstInstall(t *testing.T) {
	t.Parallel()
	now := time.Now()
	svc, _ := removedService(t, true, &now)
	ctx := context.Background()
	bad := setup.Request{Job: setup.JobInstall, Agent: "Not A Name", OSUser: "alice", Demo: true, DatabaseURL: unusedAdminURL}
	_, err := svc.Check(ctx, bad)
	refusal(t, err, setup.CodeInvalidArgument)
	_, err = svc.Run(ctx, bad)
	refusal(t, err, setup.CodeInvalidArgument)
}
