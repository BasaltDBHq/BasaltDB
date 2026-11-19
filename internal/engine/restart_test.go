//go:build linux || darwin

package engine_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/shim"
)

// restartTools are an engine build's tools: write counts its runs, slow
// runs until release is closed or its call is cancelled.
type restartTools struct {
	build   string
	writes  atomic.Int32
	started chan struct{}
	release chan struct{}
	// cancelled is set when slow ended by cancellation.
	cancelled atomic.Bool
}

func newRestartTools(build string) *restartTools {
	return &restartTools{build: build, started: make(chan struct{}, 1), release: make(chan struct{})}
}

func (r *restartTools) server() *mcp.Server {
	return mcp.NewServer(mcp.Info{Name: "basalt", Version: r.build},
		mcp.Tool{Name: "write", Call: func(context.Context, json.RawMessage) (any, error) {
			r.writes.Add(1)
			return map[string]string{"build": r.build}, nil
		}},
		mcp.Tool{Name: "slow", Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
			r.started <- struct{}{}
			select {
			case <-r.release:
				return map[string]string{"build": r.build}, nil
			case <-ctx.Done():
				r.cancelled.Store(true)
				return nil, ctx.Err()
			}
		}},
	)
}

// restartingEngine serves tools on socket and stops for a restart when
// upgrade is closed.
type restartingEngine struct {
	done   chan error
	cancel context.CancelFunc
}

func startRestarting(t *testing.T, socket string, tools *restartTools, upgrade <-chan struct{}, idle, drain time.Duration) *restartingEngine {
	t.Helper()
	a := engine.Agent{Name: "bot", UID: myUID(), SocketPath: socket, Server: tools.server()}
	e := engine.New(slog.New(slog.DiscardHandler), []engine.Agent{a}).WithRestart(engine.RestartOptions{
		Upgrade: func(ctx context.Context) error {
			select {
			case <-upgrade:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		IdleWait: idle, DrainWait: drain,
	})
	ctx, cancel := context.WithCancel(context.Background())
	r := &restartingEngine{done: make(chan error, 1), cancel: cancel}
	go func() { r.done <- e.Serve(ctx) }()
	t.Cleanup(cancel)
	waitListening(t, socket)
	return r
}

func (r *restartingEngine) stopped(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not stop")
		return nil
	}
}

// shimClient is an MCP client on basalt mcp's stdio that may send several
// requests before reading the answers, as clients with parallel tool calls
// do.
type shimClient struct {
	in      *io.PipeWriter
	mu      sync.Mutex
	answers map[float64]chan map[string]any
}

func startShimClient(t *testing.T, socket string) *shimClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &shimClient{in: inW, answers: map[float64]chan map[string]any{}}
	go func() {
		_ = shim.ServeWith(context.Background(), socket, fallback, inR, outW, shim.Options{ReconnectWait: 10 * time.Second})
		_ = outW.Close()
	}()
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			id, _ := m["id"].(float64)
			c.mu.Lock()
			ch := c.answers[id]
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}()
	t.Cleanup(func() { _ = inW.Close() })
	return c
}

// send sends a tools/call of tool with id and returns where its answer
// arrives.
func (c *shimClient) send(t *testing.T, id int, tool string) <-chan map[string]any {
	t.Helper()
	ch := make(chan map[string]any, 1)
	c.mu.Lock()
	c.answers[float64(id)] = ch
	c.mu.Unlock()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool}})
	require.NoError(t, err)
	_, err = c.in.Write(append(raw, '\n'))
	require.NoError(t, err)
	return ch
}

// answer waits for an answer and returns the tool's body (or the JSON-RPC
// error's message under "error").
func answer(t *testing.T, ch <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case m := <-ch:
		if e, ok := m["error"].(map[string]any); ok {
			return map[string]any{"error": e["message"]}
		}
		res, _ := m["result"].(map[string]any)
		content, _ := res["content"].([]any)
		require.NotEmpty(t, content, "%v", m)
		first, _ := content[0].(map[string]any)
		text, _ := first["text"].(string)
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &body), text)
		return body
	case <-time.After(15 * time.Second):
		t.Fatal("no answer")
		return nil
	}
}

func TestAnIdleEngineRestartsAndTheNextCallReachesTheNewOne(t *testing.T) {
	t.Parallel()
	socket := shortDir(t) + "/bot.sock"
	oldTools, newTools := newRestartTools("old"), newRestartTools("new")
	upgrade := make(chan struct{})
	old := startRestarting(t, socket, oldTools, upgrade, time.Minute, time.Minute)
	c := startShimClient(t, socket)
	require.Equal(t, "old", answer(t, c.send(t, 1, "write"))["build"])

	close(upgrade)
	require.ErrorIs(t, old.stopped(t), engine.ErrRestart)
	_, err := os.Lstat(socket)
	require.ErrorIs(t, err, os.ErrNotExist, "the socket is gone, so a shim waits for the new engine")

	// The new binary starts, as exec does, while the next call waits.
	next := c.send(t, 2, "write")
	time.Sleep(200 * time.Millisecond)
	startRestarting(t, socket, newTools, make(chan struct{}), time.Minute, time.Minute)
	body := answer(t, next)
	require.Equal(t, "new", body["build"], "%v", body)
	require.EqualValues(t, 1, oldTools.writes.Load())
	require.EqualValues(t, 1, newTools.writes.Load())
}

func TestARestartLetsTheRunningCallFinishAndSendsTheQueuedOneToTheNewEngine(t *testing.T) {
	t.Parallel()
	socket := shortDir(t) + "/bot.sock"
	oldTools, newTools := newRestartTools("old"), newRestartTools("new")
	upgrade := make(chan struct{})
	// No idle moment within 10 ms: the gate closes while slow runs.
	old := startRestarting(t, socket, oldTools, upgrade, 10*time.Millisecond, time.Minute)
	c := startShimClient(t, socket)

	slow := c.send(t, 1, "slow")
	<-oldTools.started
	close(upgrade)
	time.Sleep(100 * time.Millisecond)
	// A write the client sends now waits behind slow on its connection.
	write := c.send(t, 2, "write")
	time.Sleep(100 * time.Millisecond)
	close(oldTools.release)

	require.Equal(t, "old", answer(t, slow)["build"], "the running call finished on the old engine")
	require.ErrorIs(t, old.stopped(t), engine.ErrRestart)
	startRestarting(t, socket, newTools, make(chan struct{}), time.Minute, time.Minute)

	require.Equal(t, "new", answer(t, write)["build"], "the old engine did not run it, so the shim sent it to the new one")
	require.Zero(t, oldTools.writes.Load())
	require.EqualValues(t, 1, newTools.writes.Load(), "run exactly once")
	require.False(t, oldTools.cancelled.Load())
}

func TestARestartWaitsForAMomentWithNoCallRunning(t *testing.T) {
	t.Parallel()
	socket := shortDir(t) + "/bot.sock"
	tools := newRestartTools("old")
	upgrade := make(chan struct{})
	old := startRestarting(t, socket, tools, upgrade, time.Minute, time.Minute)
	c := startShimClient(t, socket)

	slow := c.send(t, 1, "slow")
	<-tools.started
	close(upgrade)
	select {
	case err := <-old.done:
		t.Fatalf("stopped during a call: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(tools.release)
	require.Equal(t, "old", answer(t, slow)["build"])
	require.ErrorIs(t, old.stopped(t), engine.ErrRestart)
}

func TestACallStillRunningAfterTheDrainWaitIsCancelled(t *testing.T) {
	t.Parallel()
	socket := shortDir(t) + "/bot.sock"
	tools := newRestartTools("old")
	upgrade := make(chan struct{})
	old := startRestarting(t, socket, tools, upgrade, 10*time.Millisecond, 100*time.Millisecond)
	c := startShimClient(t, socket)

	slow := c.send(t, 1, "slow")
	<-tools.started
	close(upgrade)
	require.ErrorIs(t, old.stopped(t), engine.ErrRestart)
	require.True(t, tools.cancelled.Load(), "its context was cancelled, so its transaction rolls back")
	body := answer(t, slow)
	require.NotEqual(t, "old", body["build"], "%v", body)
}

func TestStoppingTheEngineDuringTheIdleWaitIsAPlainStop(t *testing.T) {
	t.Parallel()
	socket := shortDir(t) + "/bot.sock"
	tools := newRestartTools("old")
	upgrade := make(chan struct{})
	old := startRestarting(t, socket, tools, upgrade, time.Minute, time.Minute)
	c := startShimClient(t, socket)
	slow := c.send(t, 1, "slow")
	<-tools.started
	close(upgrade)
	time.Sleep(50 * time.Millisecond)
	old.cancel()
	require.NoError(t, old.stopped(t))
	_ = slow
}

func TestStoppingTheEngineDuringTheDrainIsAPlainStop(t *testing.T) {
	t.Parallel()
	socket := shortDir(t) + "/bot.sock"
	tools := newRestartTools("old")
	upgrade := make(chan struct{})
	// The gate closes at once (10 ms) while slow runs; the drain waits.
	old := startRestarting(t, socket, tools, upgrade, 10*time.Millisecond, time.Minute)
	c := startShimClient(t, socket)
	slow := c.send(t, 1, "slow")
	<-tools.started
	close(upgrade)
	time.Sleep(100 * time.Millisecond)
	old.cancel()
	require.NoError(t, old.stopped(t), "a stop, so the new binary is not run")
	_ = slow
}
