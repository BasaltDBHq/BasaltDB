//go:build unix

package plugin

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
)

// readWatch is a same-user engine's plugin watch with no database: one
// entry that does not require approval, served to product_a, never started.
// euid is the engine's effective uid as the watch reads engine.json with it:
// 0 is the hardened read the engine's start makes as root.
type readWatch struct {
	t      *testing.T
	f      *pluginFixture
	ep     *Plugins
	w      *pluginWatch
	logged *lockedBuffer
}

// lockedBuffer is the watch's log, written from its goroutine.
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

func newReadWatch(t *testing.T, euid int) *readWatch {
	return newReadWatchKept(t, euid, nil)
}

// newReadWatchKept is newReadWatch for an engine that keeps entries of its
// own in kept (an agent-operated engine on the bot's computer); nil keeps
// none.
func newReadWatchKept(t *testing.T, euid int, kept *Store) *readWatch {
	t.Helper()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a")
	f.writeConfig()
	cfg, err := cli.LoadEngineConfigAs(trustedOpener{}, euid, f.configPath)
	require.NoError(t, err, "the engine's own read of the start config")
	logged := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logged, nil))
	ep := NewFor(cfg, f.configPath, Options{Ports: testPorts, Dialer: dial.Dialer{}, SocketBase: f.sockBase, euid: euid, kept: kept}, log)
	rw := &readWatch{t: t, f: f, ep: ep, w: newPluginWatch(ep, cfg, f.configPath, map[string]AgentLedger{}), logged: logged}
	rw.w.step(context.Background()) // the first read of engine.json changes nothing
	require.False(t, rw.w.bad)
	require.True(t, rw.enabled(), "the entry is configured at start")
	return rw
}

// enabled reports whether the watch serves the entry from engine.json as it
// last read it.
func (rw *readWatch) enabled() bool {
	rw.ep.mu.Lock()
	defer rw.ep.mu.Unlock()
	return len(rw.ep.configured) == 1 && rw.ep.configured[0].Enabled
}

// configInvalid reports whether status shows agentName PLUGIN_CONFIG_INVALID.
func (rw *readWatch) configInvalid(agentName string) bool {
	return slices.ContainsFunc(rw.ep.pluginProblems(agentName), func(p pluginProblem) bool {
		return p.Code == problemPluginConfigInvalid
	})
}

// disabledConfig writes, at path, the fixture's config with the entry
// turned off.
func (rw *readWatch) disabledConfig(path string) {
	rw.t.Helper()
	at := rw.f.configPath
	rw.f.configPath = path
	defer func() { rw.f.configPath = at }()
	rw.f.cfg.Plugins[0].Enabled = false
	rw.f.writeConfig()
	rw.f.cfg.Plugins[0].Enabled = true
}

// requireRefused: the watch refused engine.json with the error the engine's
// own read gives for it, applied nothing, and status says so.
func (rw *readWatch) requireRefused(why string) {
	rw.t.Helper()
	t := rw.t
	_, engineErr := cli.LoadEngineConfigAs(trustedOpener{}, 0, rw.f.configPath)
	require.ErrorContains(t, engineErr, why, "the engine's read as root refuses it")
	rw.w.step(context.Background())
	require.True(t, rw.w.bad)
	require.True(t, rw.enabled(), "nothing from the refused file is applied")
	for _, a := range []string{"product_a", "client_x"} {
		require.True(t, rw.configInvalid(a), a)
	}
	require.Contains(t, rw.logged.String(), engineErr.Error(), "the watch refused it the same way")
	rw.w.step(context.Background())
	rw.w.step(context.Background())
	require.Equal(t, 1, strings.Count(rw.logged.String(), whyLogged), "logged once while the file stays refused")
}

const whyLogged = "engine.json changed and its plugins cannot be read"

// An agent-operated engine running as root, whose engine.json is replaced
// by a symlink to a FIFO, or by a FIFO: the watch refuses it without
// blocking, also on the engine-kept entries' path (a change of the entries
// file applies over the last good read's entries), and keeps answering:
// a kick still returns, as request_plugin's applyNow needs.
func TestWatchAsRootRefusesFIFOConfig(t *testing.T) {
	t.Parallel()
	for _, link := range []bool{true, false} {
		state, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		store, err := NewPluginhost(state, time.Now)
		require.NoError(t, err)
		rw := newReadWatchKept(t, 0, store)
		fifo := filepath.Join(filepath.Dir(rw.f.configPath), "fifo")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))
		require.NoError(t, os.Remove(rw.f.configPath))
		why := "not a regular file"
		if link {
			require.NoError(t, os.Symlink(fifo, rw.f.configPath))
			why = "symlink"
		} else {
			require.NoError(t, os.Rename(fifo, rw.f.configPath))
		}
		_, engineErr := cli.LoadEngineConfigAs(trustedOpener{}, 0, rw.f.configPath)
		require.ErrorContains(t, engineErr, why, "the engine's read as root refuses it")

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { rw.w.run(ctx, RealClock()); close(done) }()
		kick := func() {
			t.Helper()
			reply := make(chan struct{})
			select {
			case rw.ep.kick <- reply:
			case <-time.After(10 * time.Second):
				t.Fatal("the watch takes no kick: it is blocked")
			}
			select {
			case <-reply:
			case <-time.After(10 * time.Second):
				t.Fatal("the watch's pass never returned: it is blocked")
			}
		}
		kick()
		// A change of the engine-kept entries file, while engine.json is
		// refused: applied over the entries of the last good read.
		require.NoError(t, os.WriteFile(store.EntriesPath(), []byte("[]"), 0o600))
		kick()
		kick()
		require.True(t, rw.enabled(), "nothing from the refused file is applied")
		require.True(t, rw.configInvalid("product_a"))
		require.Contains(t, rw.logged.String(), engineErr.Error())
		require.Equal(t, 1, strings.Count(rw.logged.String(), whyLogged), "logged once")
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the watch does not stop")
		}
	}
}

// An engine running as root re-reads engine.json with the hardened read of
// its start: a symlink in its place is refused, not followed, and nothing
// from the file it names is applied, though as the engine's user the same
// link is followed.
func TestWatchAsRootRefusesSymlinkedConfig(t *testing.T) {
	t.Parallel()
	for _, euid := range []int{0, os.Geteuid()} {
		rw := newReadWatch(t, euid)
		planted := filepath.Join(filepath.Dir(rw.f.configPath), "planted.json")
		rw.disabledConfig(planted)
		require.NoError(t, os.Remove(rw.f.configPath))
		require.NoError(t, os.Symlink(planted, rw.f.configPath))
		if euid == 0 {
			rw.requireRefused("symlink")
			continue
		}
		rw.w.step(context.Background())
		require.False(t, rw.w.bad, "as the engine's user, unchanged: the link is followed")
		require.False(t, rw.enabled())
	}
}

// As root, an engine.json that group or others can write is refused, as the
// engine's start refuses it; once its mode is fixed, its change applies.
func TestWatchAsRootRefusesWritableConfig(t *testing.T) {
	t.Parallel()
	rw := newReadWatch(t, 0)
	rw.disabledConfig(rw.f.configPath)
	require.NoError(t, os.Chmod(rw.f.configPath, 0o620))
	rw.requireRefused("writable by group or others")

	require.NoError(t, os.Chmod(rw.f.configPath, 0o600))
	rw.w.step(context.Background())
	require.False(t, rw.w.bad)
	require.False(t, rw.enabled(), "the change applies once the engine's read accepts the file")
	require.False(t, rw.configInvalid("product_a"))
}

// A normal engine.json still reloads on a change, as root (the hardened
// read accepts a regular file its directory's owner owns) and as the
// engine's user, and an unchanged one changes nothing.
func TestWatchReloadsChangedConfig(t *testing.T) {
	t.Parallel()
	for _, euid := range []int{0, os.Geteuid()} {
		rw := newReadWatch(t, euid)
		rw.w.step(context.Background())
		require.True(t, rw.enabled(), "unchanged")

		rw.disabledConfig(rw.f.configPath)
		rw.w.step(context.Background())
		require.False(t, rw.w.bad, "euid %d", euid)
		require.False(t, rw.enabled(), "euid %d: the change applies", euid)

		rw.f.writeConfig()
		rw.w.step(context.Background())
		require.True(t, rw.enabled(), "euid %d: and back", euid)
		require.False(t, rw.configInvalid("product_a"))
	}
}
