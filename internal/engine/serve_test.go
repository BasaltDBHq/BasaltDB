package engine_test

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
	run := func(_ context.Context, o engine.Restart) error {
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
	err := engine.ServeRestarting(context.Background(), run, engine.BinaryRestart{Upgrade: upgrade, Exec: exec}, noReload, slog.New(slog.DiscardHandler))
	require.EqualError(t, err, "stopped")
	require.Equal(t, 1, execs)
	require.Equal(t, 2, runs, "a new binary that does not start leaves this one serving")
}

func TestTheEngineWithoutARestartRunsOnce(t *testing.T) {
	t.Parallel()
	runs := 0
	run := func(_ context.Context, o engine.Restart) error {
		runs++
		require.Nil(t, o.Upgrade)
		return nil
	}
	require.NoError(t, engine.ServeRestarting(context.Background(), run, engine.BinaryRestart{}, noReload, slog.New(slog.DiscardHandler)))
	require.Equal(t, 1, runs)
}

func noReload() error { return errors.New("no reload expected") }

// A reload reads the config again and runs the engine anew in this process,
// never running a binary.
func TestTheEngineServesItsConfigAgainAfterAReload(t *testing.T) {
	t.Parallel()
	runs, reloads := 0, 0
	run := func(context.Context, engine.Restart) error {
		runs++
		if runs == 1 {
			return engine.ErrReload
		}
		return errors.New("stopped")
	}
	exec := func() error {
		t.Fatal("a reload runs no binary")
		return nil
	}
	reload := func() error { reloads++; return nil }
	err := engine.ServeRestarting(context.Background(), run, engine.BinaryRestart{Exec: exec}, reload, slog.New(slog.DiscardHandler))
	require.EqualError(t, err, "stopped")
	require.Equal(t, 2, runs)
	require.Equal(t, 1, reloads)

	// A config that cannot be read now stops the engine.
	runs = 0
	err = engine.ServeRestarting(context.Background(), run, engine.BinaryRestart{Exec: exec}, func() error { return errors.New("config refused") }, slog.New(slog.DiscardHandler))
	require.EqualError(t, err, "config refused")
}
