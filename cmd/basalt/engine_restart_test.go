package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

func TestTheEngineRunsTheNewBinaryAfterItStopsForARestart(t *testing.T) {
	t.Parallel()
	runs, execs := 0, 0
	upgrade := func(context.Context) error { return nil }
	run := func(_ context.Context, o engine.RestartOptions) error {
		runs++
		require.NotNil(t, o.Upgrade, "the engine is told when to restart")
		if runs == 1 {
			return engine.ErrRestart
		}
		return errors.New("stopped")
	}
	exec := func() error {
		execs++
		return errors.New("exec format error")
	}
	err := serveRestarting(context.Background(), run, restart{upgrade: upgrade, exec: exec}, slog.New(slog.DiscardHandler))
	require.EqualError(t, err, "stopped")
	require.Equal(t, 1, execs)
	require.Equal(t, 2, runs, "a new binary that does not start leaves this one serving")
}

func TestTheEngineWithoutARestartRunsOnce(t *testing.T) {
	t.Parallel()
	runs := 0
	run := func(_ context.Context, o engine.RestartOptions) error {
		runs++
		require.Nil(t, o.Upgrade)
		return nil
	}
	require.NoError(t, serveRestarting(context.Background(), run, restart{}, slog.New(slog.DiscardHandler)))
	require.Equal(t, 1, runs)
}
