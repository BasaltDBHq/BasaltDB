//go:build unix

package plugin

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

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
	logged *bytes.Buffer
}

func newReadWatch(t *testing.T, euid int) *readWatch {
	t.Helper()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a")
	f.writeConfig()
	cfg, err := cli.LoadEngineConfigAs(trustedOpener{}, euid, f.configPath)
	require.NoError(t, err, "the engine's own read of the start config")
	logged := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logged, nil))
	ep := NewFor(cfg, f.configPath, Options{Ports: testPorts, Dialer: dial.Dialer{}, SocketBase: f.sockBase, euid: euid}, log)
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
