package sdk

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stuckPlugin has handlers that can be made to ignore their context and never
// return, until release is closed.
type stuckPlugin struct {
	fullPlugin
	stuckInit, stuckHealth, stuckShutdown atomic.Bool
	release                               chan struct{}
	once                                  sync.Once
}

func newStuck(t *testing.T) *stuckPlugin {
	p := &stuckPlugin{fullPlugin: *newFull(), release: make(chan struct{})}
	t.Cleanup(p.free)
	return p
}

func (p *stuckPlugin) free() { p.once.Do(func() { close(p.release) }) }

func (p *stuckPlugin) Initialize(ctx context.Context, in Init) error {
	if p.stuckInit.Load() {
		<-p.release
	}
	return p.fullPlugin.Initialize(ctx, in)
}

func (p *stuckPlugin) Health(ctx context.Context) error {
	if p.stuckHealth.Load() {
		<-p.release
	}
	return p.fullPlugin.Health(ctx)
}

func (p *stuckPlugin) Shutdown(ctx context.Context) error {
	if p.stuckShutdown.Load() {
		<-p.release
	}
	return p.fullPlugin.Shutdown(ctx)
}

const shortInit = `{"protocols":["basalt-plugin/1"],"hooks":[],"config":{},"limits":{"timeoutMs":100}}`

// TestStuckHandlersDoNotHoldThePlatformMethods: a handler that never returns
// ends at the call's deadline instead of holding the call.
func TestStuckHandlersDoNotHoldThePlatformMethods(t *testing.T) {
	p := newStuck(t)
	s, c := serveStdio(t, p)
	require.Nil(t, c.call("initialize", shortInit).Error)

	p.stuckInit.Store(true)
	start := time.Now()
	r := c.call("initialize", shortInit)
	require.NotNil(t, r.Error)
	require.Equal(t, codeDeadline, r.Error.Code)
	require.Less(t, time.Since(start), 2*time.Second)

	p.stuckHealth.Store(true)
	start = time.Now()
	r = c.call("health", `{}`)
	require.Nil(t, r.Error)
	require.JSONEq(t, `{"status":"NOT_READY"}`, string(r.Result))
	require.Less(t, time.Since(start), 2*time.Second)

	p.stuckShutdown.Store(true)
	start = time.Now()
	r = c.call("shutdown", `{}`)
	require.Nil(t, r.Error, "shutdown answers even when the plugin's own does not return")
	require.Less(t, time.Since(start), 2*time.Second)
	require.NoError(t, s.await(t), "and Serve ends")
}

// TestCallsInFlightAtEOFAreAnswered: the engine may send a call, close stdin
// and then read the reply; the handler keeps a live context until it returns.
func TestCallsInFlightAtEOFAreAnswered(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var ctxErr atomic.Pointer[error]
	extra := map[string]methodFunc{"slow": func(ctx context.Context, _ json.RawMessage) (any, *rpcError) {
		close(started)
		<-release
		err := ctx.Err()
		ctxErr.Store(&err)
		return struct{}{}, nil
	}}
	s, c := serveStdio(t, newFull(), withExtra(extra))
	c.send(`{"jsonrpc":"2.0","id":1,"method":"slow","params":{}}`)
	<-started
	require.NoError(t, c.w.Close())

	select {
	case err := <-s.done:
		t.Fatalf("Serve returned (%v) with a call in flight", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	r := c.read()
	require.Nil(t, r.Error)
	require.JSONEq(t, `{}`, string(r.Result))
	require.NoError(t, s.await(t))
	require.NoError(t, *ctxErr.Load(), "the handler was not cancelled")
}

// TestCallsInFlightAtEOFEndAtTheirDeadline: a call that never finishes is
// cancelled by its deadline, answered, and does not hold Serve.
func TestCallsInFlightAtEOFEndAtTheirDeadline(t *testing.T) {
	extra := map[string]methodFunc{"slow": func(ctx context.Context, _ json.RawMessage) (any, *rpcError) {
		<-ctx.Done()
		return nil, nil
	}}
	s, c := serveStdio(t, newFull(), withExtra(extra))
	require.Nil(t, c.call("initialize", shortInit).Error)
	c.send(`{"jsonrpc":"2.0","id":9,"method":"slow","params":{}}`)
	require.NoError(t, c.w.Close())
	r := c.read()
	require.NotNil(t, r.Error)
	require.Equal(t, codeDeadline, r.Error.Code)
	require.NoError(t, s.await(t))
}
