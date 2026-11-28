package setup_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
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

// A removed engine answers every job but an INSTALL ENGINE_REMOVED,
// the empty probe included: its removal job removes it next.
func TestARemovedEngineAnswersEngineRemoved(t *testing.T) {
	t.Parallel()
	now := time.Now()
	svc, _ := removedService(t, true, &now)
	ctx := context.Background()
	_, err := svc.Check(ctx, setup.Request{})
	refusal(t, err, setup.CodeEngineRemoved)
	_, err = svc.Check(ctx, setup.Request{Job: setup.JobRemove, Agent: "demo_bot", OSUser: "alice"})
	refusal(t, err, setup.CodeEngineRemoved)
	_, err = svc.Run(ctx, setup.Request{Job: setup.JobUpdate, Agent: "demo_bot", OSUser: "alice"})
	refusal(t, err, setup.CodeEngineRemoved)
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
