package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type countingDispatcher struct{ calls int }

func (d *countingDispatcher) Dispatch(context.Context, SessionLink, Request) Response {
	d.calls++
	return Response{Status: http.StatusOK}
}

// switchGate admits calls until it is closed and counts the running ones.
type switchGate struct {
	closed bool
	busy   int
}

func (g *switchGate) Begin() bool {
	if g.closed {
		return false
	}
	g.busy++
	return true
}

func (g *switchGate) End() { g.busy-- }

func TestAPageSessionRequestIsCountedAndRefusedOnceTheGateCloses(t *testing.T) {
	t.Parallel()
	g := &switchGate{}
	next := &countingDispatcher{}
	d := GatedDispatcher{Gate: g, Next: next}
	require.Equal(t, http.StatusOK, d.Dispatch(context.Background(), SessionLink{}, Request{}).Status)
	require.Zero(t, g.busy, "idle after the request")
	g.closed = true

	resp := d.Dispatch(context.Background(), SessionLink{}, Request{})
	require.Equal(t, http.StatusServiceUnavailable, resp.Status)
	var body map[string]string
	require.NoError(t, json.Unmarshal(resp.Body, &body))
	require.Equal(t, "UNAVAILABLE", body["code"])
	require.Contains(t, body["message"], "nothing was run")
	require.Equal(t, 1, next.calls, "the refused request never ran")
}
