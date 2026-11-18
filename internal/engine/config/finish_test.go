//go:build unix

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

const finishSetupID = "0193a4c2-7d1e-7c3a-9f00-0000000000e5"

func pendingAgent(name string) config.Agent {
	return config.Agent{
		Name: name, OSUser: "bot", Store: config.PostgresStore("/c/" + name + ".url"), InitArgs: []string{"--agent=" + name},
		Setup: &config.Setup{
			SetupID: finishSetupID, Kind: "INSTALL", GuardVersion: 16, ExpiresAt: "2026-11-13T10:00:00Z",
			Code: "basalt-setup.1.abc.def", Fingerprint: "a1b2 c3d4 e5f6 0718 293a",
		},
	}
}

func TestClearSetupClearsOnlyThatSetup(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot, other := pendingAgent("bot"), pendingAgent("other")
	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/run/basalt", OperatedBy: "AGENT", PagesURL: links.Portal}, bot))
	require.NoError(t, config.UpsertAgent(path, config.Settings{}, other))

	// Another setup id (init --remote made a new code meanwhile): unchanged.
	cleared, err := config.ClearSetup(path, "bot", "0193a4c2-7d1e-7c3a-9f00-0000000000ff")
	require.NoError(t, err)
	require.False(t, cleared)

	cleared, err = config.ClearSetup(path, "bot", finishSetupID)
	require.NoError(t, err)
	require.True(t, cleared)
	c, err := config.Load(path)
	require.NoError(t, err)
	bot.Setup = nil
	require.Equal(t, []config.Agent{bot, other}, c.Agents, "only bot's setup goes; everything else stays")
	require.Equal(t, "AGENT", c.OperatedBy)
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), fi.Mode().Perm())

	cleared, err = config.ClearSetup(path, "bot", finishSetupID)
	require.NoError(t, err)
	require.False(t, cleared, "nothing pending any more")
	cleared, err = config.ClearSetup(path, "nobody", finishSetupID)
	require.NoError(t, err)
	require.False(t, cleared)
}

func TestClearSetupRefusesALinkedConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	require.NoError(t, config.UpsertAgent(target, config.Settings{SocketDir: "/run/basalt"}, pendingAgent("bot")))
	link := filepath.Join(dir, "engine.json")
	require.NoError(t, os.Symlink(target, link))
	_, err := config.ClearSetup(link, "bot", finishSetupID)
	require.Error(t, err)
	c, err := config.Load(target)
	require.NoError(t, err)
	require.NotNil(t, c.Agents[0].Setup)
}

// The engine clearing agent a's setup while basalt init writes agent b: both
// hold the config's lock from read to write, so neither change is lost.
func TestClearSetupAndAnUpsertOfAnotherAgentBothLand(t *testing.T) {
	t.Parallel()
	const rounds = 30
	for i := range rounds {
		path := filepath.Join(t.TempDir(), "engine.json")
		a, b := pendingAgent("a"), pendingAgent("b")
		require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/run/basalt"}, a))
		require.NoError(t, config.UpsertAgent(path, config.Settings{}, b))

		b.InitArgs = []string{"--agent=b", "--write=public.notes"}
		var wg sync.WaitGroup
		var clearErr, upsertErr error
		wg.Go(func() { _, clearErr = config.ClearSetup(path, "a", finishSetupID) })
		wg.Go(func() { upsertErr = config.UpsertAgent(path, config.Settings{}, b) })
		wg.Wait()
		require.NoError(t, clearErr, "round %d", i)
		require.NoError(t, upsertErr, "round %d", i)

		c, err := config.Load(path)
		require.NoError(t, err)
		require.Nil(t, c.Agents[0].Setup, "round %d: a's clear landed", i)
		require.Equal(t, b.InitArgs, c.Agents[1].InitArgs, "round %d: b's upsert landed", i)
	}
}

func TestLockFileIsExclusive(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "agents", "bot.url.lock")
	unlock, err := config.LockFile(path)
	require.NoError(t, err)
	_, err = config.LockFile(path)
	require.True(t, errors.Is(err, config.ErrLocked), "%v", err)
	unlock()
	unlock, err = config.LockFile(path)
	require.NoError(t, err)
	unlock()
}

func TestReadOwnCredential(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bot.url.pending")
	require.NoError(t, config.WriteFile(path, []byte("postgres://bot:pw@db/app\n")))
	dsn, fi, err := config.ReadOwnCredential(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://bot:pw@db/app", dsn)
	require.NoError(t, config.SameCredentialFile(path, fi))

	// Replaced after it was read: no longer the same file.
	require.NoError(t, config.WriteFile(path, []byte("postgres://bot:other@db/app\n")))
	require.Error(t, config.SameCredentialFile(path, fi))

	require.NoError(t, os.Chmod(path, 0o644))
	_, _, err = config.ReadOwnCredential(path)
	require.ErrorContains(t, err, "0600")

	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(path, link))
	_, _, err = config.ReadOwnCredential(link)
	require.Error(t, err, "never through a symlink")
}
