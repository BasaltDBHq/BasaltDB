package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTheDrainWaitsForEveryAdmittedRequest(t *testing.T) {
	t.Parallel()
	g := NewCallGate()
	require.True(t, g.Begin()) // a person request, say
	require.False(t, g.closeWhenIdle(cancelled(), time.Minute), "a stop leaves the gate open")
	require.True(t, g.closeWhenIdle(context.Background(), 10*time.Millisecond), "forced shut")
	require.False(t, g.Begin())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.False(t, g.waitIdle(ctx), "still running")
	go func() { time.Sleep(20 * time.Millisecond); g.End() }()
	require.True(t, g.waitIdle(context.Background()))
}

func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
