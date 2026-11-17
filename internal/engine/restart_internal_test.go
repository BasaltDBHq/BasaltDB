package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/vault"
)

type countingDispatcher struct{ calls int }

func (d *countingDispatcher) Dispatch(context.Context, vault.SessionLink, vault.Request) vault.Response {
	d.calls++
	return vault.Response{Status: http.StatusOK}
}

func TestAPageSessionRequestIsCountedAndRefusedOnceTheGateCloses(t *testing.T) {
	t.Parallel()
	g := newCallGate()
	next := &countingDispatcher{}
	d := gatedDispatcher{gate: g, next: next}
	require.Equal(t, http.StatusOK, d.Dispatch(context.Background(), vault.SessionLink{}, vault.Request{}).Status)
	require.True(t, g.tryClose(false), "idle after the request")

	resp := d.Dispatch(context.Background(), vault.SessionLink{}, vault.Request{})
	require.Equal(t, http.StatusServiceUnavailable, resp.Status)
	var body map[string]string
	require.NoError(t, json.Unmarshal(resp.Body, &body))
	require.Equal(t, "UNAVAILABLE", body["code"])
	require.Contains(t, body["message"], "nothing was run")
	require.Equal(t, 1, next.calls, "the refused request never ran")
}

func TestTheDrainWaitsForEveryAdmittedRequest(t *testing.T) {
	t.Parallel()
	g := newCallGate()
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
