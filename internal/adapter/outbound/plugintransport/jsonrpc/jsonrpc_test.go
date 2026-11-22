package jsonrpc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/adaptertest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/jsonrpc"
	protocol "github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	plugin "github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == peerFlag {
		peerMain(os.Args[2:])
	}
	os.Exit(m.Run())
}

const (
	dialWait = 10 * time.Second
	dialStep = 10 * time.Millisecond
)

// peerSpec starts this test binary as the peer, in a directory of its own.
func peerSpec(t *testing.T, args []string, stderr io.Writer) child.Spec {
	t.Helper()
	return child.Spec{Path: os.Args[0], Args: args, Dir: t.TempDir(), Stderr: stderr}
}

func spawn(t *testing.T, mode string, opts ...string) plugin.Transport {
	t.Helper()
	tr, err := jsonrpc.Spawn(context.Background(), peerSpec(t, peerArgs(mode, opts...), nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// startSocketPeer starts a peer process listening on a new socket and returns
// the socket's path. The process is stopped when the test ends.
func startSocketPeer(t *testing.T, mode string, opts ...string) string {
	t.Helper()
	// Unix socket paths are short; t.TempDir is too long on macOS.
	dir, err := os.MkdirTemp("", "jr")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")

	cmd := exec.Command(os.Args[0], append(peerArgs(mode, opts...), "socket="+sock)...)
	cmd.Env = []string{}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return sock
}

func dialPeer(t *testing.T, sock string) plugin.Transport {
	t.Helper()
	deadline := time.Now().Add(dialWait)
	for {
		tr, err := jsonrpc.Dial(context.Background(), sock)
		if err == nil {
			t.Cleanup(func() { _ = tr.Close() })
			return tr
		}
		require.True(t, time.Now().Before(deadline), "peer never listened: %v", err)
		time.Sleep(dialStep)
	}
}

func socket(t *testing.T, mode string, opts ...string) plugin.Transport {
	t.Helper()
	return dialPeer(t, startSocketPeer(t, mode, opts...))
}

func TestAdapter(t *testing.T) {
	t.Run("stdio", func(t *testing.T) {
		adaptertest.Run(t, func(t *testing.T, b adaptertest.Behavior) plugin.Transport {
			return spawn(t, modeOf(b))
		})
	})
	t.Run("unix", func(t *testing.T) {
		adaptertest.Run(t, func(t *testing.T, b adaptertest.Behavior) plugin.Transport {
			return socket(t, modeOf(b))
		})
	})
}

type kinds struct {
	name string
	make func(t *testing.T, mode string, opts ...string) plugin.Transport
}

var both = []kinds{
	{"stdio", spawn},
	{"unix", socket},
}

func classOf(err error) plugin.FailureClass {
	var c plugin.Classed
	if errors.As(err, &c) {
		return c.FailureClass()
	}
	return ""
}

type obj struct {
	N int    `json:"n"`
	S string `json:"s"`
}

func TestMessageCap(t *testing.T) {
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			var out obj
			// A line of exactly the cap is accepted.
			tr := k.make(t, "size", "n="+itoa(protocol.MaxMessageBytes))
			require.NoError(t, tr.Call(context.Background(), "x", obj{}, &out))
			require.NotEmpty(t, out.S)

			// One byte more is refused.
			tr = k.make(t, "size", "n="+itoa(protocol.MaxMessageBytes+1))
			err := tr.Call(context.Background(), "x", obj{}, &out)
			require.Equal(t, plugin.ClassBadResponse, classOf(err), "%v", err)
		})
	}
}

func TestEndlessLineIsCapped(t *testing.T) {
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			tr := k.make(t, "flood")
			ctx, cancel := context.WithTimeout(context.Background(), dialWait)
			defer cancel()
			err := tr.Call(ctx, "x", obj{}, nil)
			require.Equal(t, plugin.ClassBadResponse, classOf(err), "%v", err)
		})
	}
}

func TestRequestOverTheCapIsNotSent(t *testing.T) {
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			tr := k.make(t, "echo")
			big := obj{S: strings.Repeat("a", protocol.MaxMessageBytes)}
			err := tr.Call(context.Background(), "x", big, nil)
			require.Equal(t, plugin.ClassOverLimit, classOf(err), "%v", err)
			// The connection is unharmed.
			var out obj
			require.NoError(t, tr.Call(context.Background(), "x", obj{N: 1}, &out))
		})
	}
}

func TestPluginErrorsCarryNoText(t *testing.T) {
	for _, k := range both {
		for _, mode := range []string{"rpcerror", "noresult"} {
			t.Run(k.name+"/"+mode, func(t *testing.T) {
				tr := k.make(t, mode)
				err := tr.Call(context.Background(), "x", obj{}, nil)
				require.Equal(t, plugin.ClassBadResponse, classOf(err))
				require.NotContains(t, err.Error(), adaptertest.GarbageMarker)
			})
		}
	}
}

// TestParamsAreNotHTMLEscaped: the plugin reads event bytes as the engine
// built them, compacted, with no <, > or & escaped, as over ConnectRPC.
func TestParamsAreNotHTMLEscaped(t *testing.T) {
	tr := spawn(t, "rawparams")
	params := protocol.FeedObserveRequest{Agent: "a", Events: json.RawMessage(`[ {"data": {"seq": 1, "table": "a<b&c>d"}} ]`)}
	var got struct {
		Raw string `json:"raw"`
	}
	if err := tr.Call(context.Background(), protocol.MethodFeedObserve, params, &got); err != nil {
		t.Fatal(err)
	}
	if want := `{"agent":"a","events":[{"data":{"seq":1,"table":"a<b&c>d"}}]}`; got.Raw != want {
		t.Fatalf("the plugin read %s, want %s", got.Raw, want)
	}
}

func TestResultOfTheWrongShape(t *testing.T) {
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			tr := k.make(t, "wrongtype")
			var out obj
			err := tr.Call(context.Background(), "x", obj{}, &out)
			require.Equal(t, plugin.ClassBadResponse, classOf(err))
		})
	}
}

func TestResponseForAnIdNeverIssued(t *testing.T) {
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			tr := k.make(t, "strangeid")
			err := tr.Call(context.Background(), "x", obj{}, nil)
			require.Equal(t, plugin.ClassBadResponse, classOf(err))
			// Once dead, a transport stays failed.
			err = tr.Call(context.Background(), "x", obj{}, nil)
			require.Error(t, err)
			require.Equal(t, plugin.ClassUnavailable, classOf(err))
		})
	}
}

func TestChildExitStaysExited(t *testing.T) {
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			tr := k.make(t, "exit")
			require.Equal(t, plugin.ClassExited, classOf(tr.Call(context.Background(), "x", obj{}, nil)))
			require.Equal(t, plugin.ClassExited, classOf(tr.Call(context.Background(), "x", obj{}, nil)))
		})
	}
}

func TestLateAnswerAfterCancelIsDropped(t *testing.T) {
	const slowMs = "150"
	for _, k := range both {
		t.Run(k.name, func(t *testing.T) {
			tr := k.make(t, "slow", "ms="+slowMs)
			short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			require.ErrorIs(t, tr.Call(short, "x", obj{N: 1}, nil), context.DeadlineExceeded)

			// The first call's answer arrives while the second waits; the
			// second must still get its own.
			var out obj
			require.NoError(t, tr.Call(context.Background(), "x", obj{N: 2}, &out))
			require.Equal(t, 2, out.N)
		})
	}
}

func TestStdioChildHasAnEmptyEnvironment(t *testing.T) {
	t.Setenv("BASALT_TEST_SECRET", "hunter2")
	tr := spawn(t, "env")
	var out struct {
		Env []string `json:"env"`
	}
	require.NoError(t, tr.Call(context.Background(), "x", obj{}, &out))
	require.Empty(t, out.Env)
}

// lockedBuffer is a writer the exec package may fill from its own goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestStderrIsDiscardedUnlessAWriterIsGiven(t *testing.T) {
	var out obj
	// nil: nothing to observe, and the call works.
	tr := spawn(t, "stderr")
	require.NoError(t, tr.Call(context.Background(), "x", obj{N: 1}, &out))

	var buf lockedBuffer
	tr, err := jsonrpc.Spawn(context.Background(), peerSpec(t, peerArgs("stderr"), &buf))
	require.NoError(t, err)
	require.NoError(t, tr.Call(context.Background(), "x", obj{N: 1}, &out))
	require.NoError(t, tr.Close())
	require.Contains(t, buf.String(), adaptertest.GarbageMarker)
}

func TestSpawnFailureIsAnError(t *testing.T) {
	_, err := jsonrpc.Spawn(context.Background(), child.Spec{Path: filepath.Join(t.TempDir(), "missing"), Dir: t.TempDir()})
	require.Error(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = jsonrpc.Spawn(ctx, peerSpec(t, peerArgs("echo"), nil))
	require.ErrorIs(t, err, context.Canceled)
}

func TestInstancesShareNothing(t *testing.T) {
	type pid struct {
		Pid int `json:"pid"`
	}
	get := func(tr plugin.Transport) int {
		var p pid
		require.NoError(t, tr.Call(context.Background(), "x", obj{}, &p))
		return p.Pid
	}

	t.Run("stdio", func(t *testing.T) {
		a, b := spawn(t, "pid"), spawn(t, "pid")
		require.NotEqual(t, get(a), get(b))
		require.NoError(t, a.Close())
		require.NotZero(t, get(b), "closing one instance left the other running")
	})
	t.Run("unix", func(t *testing.T) {
		a, b := socket(t, "pid"), socket(t, "pid")
		require.NotEqual(t, get(a), get(b))
		require.NoError(t, a.Close())
		require.NotZero(t, get(b))
	})
	t.Run("two connections to one socket", func(t *testing.T) {
		sock := startSocketPeer(t, "pid")
		a, b := dialPeer(t, sock), dialPeer(t, sock)
		require.NotZero(t, get(a))
		require.NoError(t, a.Close())
		require.NotZero(t, get(b), "closing one connection ended the other")
	})
}

func TestCloseStopsTheChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals")
	}
	tr := spawn(t, "pid")
	var p struct {
		Pid int `json:"pid"`
	}
	require.NoError(t, tr.Call(context.Background(), "x", obj{}, &p))
	require.NoError(t, tr.Close())
	// Close has reaped the child: signal 0 finds no such process.
	proc, err := os.FindProcess(p.Pid)
	require.NoError(t, err)
	require.Error(t, proc.Signal(syscallZero()))
}
