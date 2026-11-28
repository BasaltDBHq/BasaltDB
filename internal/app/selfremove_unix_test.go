//go:build unix

package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

func writeFiles(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	}
}

func requireGone(t *testing.T, p string) {
	t.Helper()
	_, err := os.Lstat(p)
	require.ErrorIs(t, err, os.ErrNotExist, p)
}

func requireThere(t *testing.T, p string) {
	t.Helper()
	_, err := os.Lstat(p)
	require.NoError(t, err, p)
}

// The default tree goes whole. A state folder outside it loses only the
// engine's own files and stays when anything else is in it; a credential
// file basalt did not write stays, and both are reported. The binary
// stays.
func TestRemoveEngineFiles(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, config.UserDirName)
	configPath := filepath.Join(dir, "engine.json")
	writeFiles(t, configPath, filepath.Join(dir, "agents", "bot.url"), filepath.Join(dir, "run", "bot.sock"), filepath.Join(dir, "state", "engine.log"))
	cfg := config.Config{
		SocketDir: filepath.Join(dir, "run"), StateDir: filepath.Join(dir, "state"),
		Agents: []config.Agent{{Name: "bot", Store: config.PostgresStore(filepath.Join(dir, "agents", "bot.url"))}},
	}
	keep := filepath.Join(base, "bin", "basalt")
	writeFiles(t, keep)
	require.NoError(t, removeEngineFilesIn(cfg, configPath, "bot", configPath))
	requireGone(t, dir)
	requireThere(t, keep)

	t.Run("state outside: only the engine's files, and a folder with others stays", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, config.UserDirName)
		configPath := filepath.Join(dir, "engine.json")
		state := filepath.Join(base, "state")
		mine := filepath.Join(state, "notes.txt")
		writeFiles(t, configPath, filepath.Join(state, "engine.log"), filepath.Join(state, "channel.json"), filepath.Join(state, "bot.head.json"),
			filepath.Join(state, "crash", "01a1f78c-52b8-7c3a-9f00-0000000000e1.json"), mine)
		cfg := config.Config{StateDir: state}
		err := removeEngineFilesIn(cfg, configPath, "bot", configPath)
		require.Error(t, err)
		require.Equal(t, handoff.KeptDeleteFailed, keptReason(err))
		requireGone(t, filepath.Join(state, "engine.log"))
		requireGone(t, filepath.Join(state, "channel.json"))
		requireGone(t, filepath.Join(state, "bot.head.json"))
		requireGone(t, filepath.Join(state, "crash"))
		requireThere(t, mine)
	})

	t.Run("a shared folder keeps another agent's socket and head, and files the engine did not name", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, config.UserDirName)
		configPath := filepath.Join(dir, "engine.json")
		shared := filepath.Join(base, "shared")
		foreign := []string{filepath.Join(shared, "x.sock"), filepath.Join(shared, "x.head.json"), filepath.Join(shared, "crash", "notes.txt")}
		own := []string{filepath.Join(shared, "bot.sock"), filepath.Join(shared, "bot.head.json"), filepath.Join(shared, "crash", "01a1f78c-52b8-7c3a-9f00-0000000000e1.json")}
		writeFiles(t, configPath)
		writeFiles(t, foreign...)
		writeFiles(t, own...)
		cfg := config.Config{StateDir: shared, SocketDir: shared}
		err := removeEngineFilesIn(cfg, configPath, "bot", configPath)
		require.Error(t, err, "the shared folder is not empty, so it stays")
		for _, p := range foreign {
			requireThere(t, p)
		}
		for _, p := range own {
			requireGone(t, p)
		}
	})

	t.Run("a credential file basalt did not write stays", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, config.UserDirName)
		configPath := filepath.Join(dir, "engine.json")
		cred := filepath.Join(base, "elsewhere", "bot.url")
		writeFiles(t, configPath, cred)
		cfg := config.Config{Agents: []config.Agent{{Name: "bot", Store: config.PostgresStore(cred)}}}
		err := removeEngineFilesIn(cfg, configPath, "bot", configPath)
		require.ErrorIs(t, err, errCredentialKept)
		require.Equal(t, handoff.KeptCredentialFile, keptReason(err))
		requireThere(t, cred)
	})

	t.Run("a basalt folder that is not the default: only the engine's files go", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), config.UserDirName)
		configPath := filepath.Join(dir, "engine.json")
		other := filepath.Join(dir, "notes.txt")
		cred := filepath.Join(dir, "agents", "bot.url")
		writeFiles(t, configPath, other, cred)
		cfg := config.Config{Agents: []config.Agent{{Name: "bot", Store: config.PostgresStore(cred)}}}
		require.NoError(t, removeEngineFilesIn(cfg, configPath, "bot", filepath.Join(t.TempDir(), "basalt", "engine.json")))
		requireGone(t, configPath)
		requireGone(t, filepath.Join(dir, "agents"))
		requireThere(t, other)
	})
}

// A removal is decided on engine.json as it is when it is taken, not as
// the engine started: a second agent written since keeps the engine
// (OTHER_AGENTS) and deletes nothing, and a removal replaced since is not
// taken at all.
func TestTakeRemovalReadsTheConfigAgain(t *testing.T) {
	cfg, _ := removalConfig(t)
	r := remote(t, cfg, "--agent", "bot", "--remove")
	var reports []string
	removed := handoff.Removed{Agent: "bot", SetupID: r.res.SetupID, Report: func(_ context.Context, result, reason string) error {
		reports = append(reports, result+" "+reason)
		return nil
	}}
	log := slog.New(slog.DiscardHandler)

	// A second agent is written after the engine started.
	editConfig(t, cfg, func(c *config.Config) {
		other := c.Agents[0]
		other.Name, other.Removal, other.Setup = "other", nil, nil
		other.Store = config.PostgresStore(filepath.Join(filepath.Dir(cfg), "agents", "other.url"))
		c.Agents = append(c.Agents, other)
	})
	s := &selfRemoval{}
	require.True(t, takeRemoval(context.Background(), cfg, removed, s, log))
	require.Nil(t, s.taken(), "the engine stays for the other agent")
	require.Equal(t, []string{"KEPT OTHER_AGENTS"}, reports)

	// The same at the end of runWith: nothing is deleted, and the caller
	// serves the config again (engine.ErrReload) for the agents it has now.
	reports = nil
	require.False(t, finishSelfRemoval(context.Background(), cfg, &removed, log), "nothing deleted: the engine serves its config again")
	require.Equal(t, []string{"KEPT OTHER_AGENTS"}, reports)
	requireThere(t, cfg)

	// A removal replaced by a newer link is not taken.
	editConfig(t, cfg, func(c *config.Config) {
		c.Agents = c.Agents[:1]
		newer := *c.Agents[0].Removal
		newer.SetupID = "01a1f78c-52b8-7c3a-9f00-0000000000e2"
		c.Agents[0].Removal = &newer
	})
	reports = nil
	require.False(t, takeRemoval(context.Background(), cfg, removed, s, log))
	require.Nil(t, s.taken())
	require.Empty(t, reports)

	// The removal engine.json records, one agent: taken.
	editConfig(t, cfg, func(c *config.Config) { c.Agents[0].Removal.SetupID = r.res.SetupID })
	require.True(t, takeRemoval(context.Background(), cfg, removed, s, log))
	require.NotNil(t, s.taken())
}
