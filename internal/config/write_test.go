package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

func TestUpsertAgent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "etc", "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", Store: config.PostgresStore("/c/bot.url")}

	_, err := config.UpsertAgentVault(path, config.Settings{SocketDir: "/run/basalt"}, bot)
	require.NoError(t, err)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/run/basalt", c.SocketDir)
	require.Equal(t, []config.Agent{bot}, c.Agents)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), info.Mode().Perm())

	// Existing settings stay; same name replaces, a new name appends.
	require.NoError(t, os.WriteFile(path, []byte(`{"socketDir":"/s","agents":[{"name":"bot","osUser":"alice","store": {"kind": "POSTGRES", "credentialFile":"/c/bot.url"}}],"limits":{"readRowLimit":7}}`), config.FileMode))
	bot.OSUser = "bob"
	other := config.Agent{Name: "other", OSUser: "carol", Store: config.PostgresStore("/c/other.url")}
	_, err = config.UpsertAgentVault(path, config.Settings{SocketDir: "/ignored", StateDir: "/ignored"}, bot)
	require.NoError(t, err)
	_, err = config.UpsertAgentVault(path, config.Settings{SocketDir: "/ignored"}, other)
	require.NoError(t, err)
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/s", c.SocketDir)
	require.Empty(t, c.StateDir)
	require.Equal(t, 7, c.Limits.ReadRowLimit)
	require.Equal(t, []config.Agent{bot, other}, c.Agents)

	_, err = config.UpsertAgentVault(path, config.Settings{SocketDir: "/s"}, config.Agent{Name: "Bad/Name", OSUser: "x", Store: config.PostgresStore("/x")})
	require.Error(t, err)
}

func TestUpsertAgentStateDirAndPagesURL(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", Store: config.PostgresStore("/c/bot.url")}

	// A new file takes the state directory; the pages base URL is set.
	_, err := config.UpsertAgentVault(path, config.Settings{
		SocketDir: "/home/alice/basalt/run", StateDir: "/home/alice/basalt/state",
		PagesURL: "http://localhost:8787",
	}, bot)
	require.NoError(t, err)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/home/alice/basalt/state", c.StateDir)
	require.Equal(t, "http://localhost:8787", c.PagesURL)

	// Without one the existing one stays; a new one replaces it, and the
	// older approvalPage key with it.
	_, err = config.UpsertAgentVault(path, config.Settings{}, bot)
	require.NoError(t, err)
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8787", c.PagesURL)
	_, err = config.UpsertAgentVault(path, config.Settings{PagesURL: "http://localhost:9000"}, bot)
	require.NoError(t, err)
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:9000", c.PagesURL)
	require.Equal(t, "/home/alice/basalt/state", c.StateDir)
}

func TestUpsertAgentRecordsTheModeAndKeepsThePersons(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore("/c/bot.url")}
	service := config.Settings{SocketDir: "/run/basalt", Mode: config.ModeService, PersonUIDs: []uint32{501}}
	_, err := config.UpsertAgentVault(path, service, bot)
	require.NoError(t, err)

	// Re-running init keeps the recorded person and adds a new one once.
	service.PersonUIDs = []uint32{502, 501}
	_, err = config.UpsertAgentVault(path, service, bot)
	require.NoError(t, err)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.True(t, c.Service())
	require.Equal(t, []uint32{501, 502}, c.PersonUIDs)

	// No mode written means same-user mode.
	plain := filepath.Join(t.TempDir(), "engine.json")
	_, err = config.UpsertAgentVault(plain, config.Settings{SocketDir: "/tmp/run"}, bot)
	require.NoError(t, err)
	c, err = config.Load(plain)
	require.NoError(t, err)
	require.False(t, c.Service())
	require.Empty(t, c.PersonUIDs)
}

func TestNoAgentTakesThePersonSocket(t *testing.T) {
	t.Parallel()
	require.False(t, config.ValidAgentName(config.PersonSocketName))
}
