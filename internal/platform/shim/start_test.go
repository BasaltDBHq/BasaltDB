//go:build linux || darwin

package shim_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
)

// An engine that is down is started by the message that finds it so, and
// the message is then answered by the engine.
func TestServeStartsEngineWhenDown(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	var started atomic.Int32
	c, done := startShimWith(t, socket, shim.Options{
		StartWait: 5 * time.Second,
		Start: func(context.Context) error {
			started.Add(1)
			fakeEngine(t, socket) //nolint:contextcheck // the fake engine lives until the test ends
			return nil
		},
	})

	body, isError := c.call(t, "query")

	require.False(t, isError, "%v", body)
	require.Equal(t, "engine", body["from"])
	require.EqualValues(t, 1, started.Load())
	body, isError = c.call(t, "query")
	require.False(t, isError, "%v", body)
	require.EqualValues(t, 1, started.Load(), "an engine that answers is not started again")
	require.NoError(t, c.in.Close())
	require.NoError(t, <-done)
}

func TestServeStartFailsFallsBack(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	c, _ := startShimWith(t, socket, shim.Options{
		StartWait: 50 * time.Millisecond,
		Start:     func(context.Context) error { return errors.New("the basalt binary /x is gone") },
	})

	began := time.Now()
	body, isError := c.call(t, "query")

	require.True(t, isError)
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])
	require.Less(t, time.Since(began), 5*time.Second)
}

// A starter that returns but whose engine never answers costs one wait,
// then the fallback answers.
func TestServeStartedEngineNeverAnswersFallsBackWithinStartWait(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	c, _ := startShimWith(t, socket, shim.Options{StartWait: 200 * time.Millisecond, Start: func(context.Context) error { return nil }})

	began := time.Now()
	body, isError := c.call(t, "query")

	require.True(t, isError)
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])
	require.GreaterOrEqual(t, time.Since(began), 200*time.Millisecond)
	require.Less(t, time.Since(began), 5*time.Second)
}

// A long-lived shim whose engine went away starts one on its next message,
// after the wait for a restart that does not come, and a later message
// starts again without waiting.
func TestServeStartOnLaterMessage(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	var started atomic.Int32
	engineUp := make(chan struct{})
	c, _ := startShimWith(t, socket, shim.Options{
		ReconnectWait: 200 * time.Millisecond,
		StartWait:     50 * time.Millisecond,
		Start: func(context.Context) error {
			if started.Add(1) == 2 {
				close(engineUp)
				fakeEngine(t, socket) //nolint:contextcheck // the fake engine lives until the test ends
			}
			return nil
		},
	})
	// Message 1: the engine is down and not started by anything but Start,
	// which does not bring it up the first time.
	_, isError := c.call(t, "query")
	require.True(t, isError)
	require.EqualValues(t, 1, started.Load())

	// Message 2: Start brings an engine up.
	body, isError := c.call(t, "query")
	require.False(t, isError, "%v", body)
	<-engineUp
	require.EqualValues(t, 2, started.Load())
}

func TestServeNoStartWhenNil(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	c, _ := startShim(t, socket)

	body, isError := c.call(t, "query")

	require.True(t, isError)
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])
}
