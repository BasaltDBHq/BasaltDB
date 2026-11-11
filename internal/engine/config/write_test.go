package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestUpsertAgent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "etc", "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", CredentialFile: "/c/bot.url"}

	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/run/basalt"}, bot))
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/run/basalt", c.SocketDir)
	require.Equal(t, []config.Agent{bot}, c.Agents)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), info.Mode().Perm())

	// Existing settings stay; same name replaces, a new name appends.
	require.NoError(t, os.WriteFile(path, []byte(`{"socketDir":"/s","agents":[{"name":"bot","osUser":"alice","credentialFile":"/c/bot.url"}],"limits":{"readRowLimit":7}}`), config.FileMode))
	bot.OSUser = "bob"
	other := config.Agent{Name: "other", OSUser: "carol", CredentialFile: "/c/other.url"}
	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/ignored", StateDir: "/ignored"}, bot))
	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/ignored"}, other))
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/s", c.SocketDir)
	require.Empty(t, c.StateDir)
	require.Equal(t, 7, c.Limits.ReadRowLimit)
	require.Equal(t, []config.Agent{bot, other}, c.Agents)

	require.Error(t, config.UpsertAgent(path, config.Settings{SocketDir: "/s"}, config.Agent{Name: "Bad/Name", OSUser: "x", CredentialFile: "/x"}))
}

func TestUpsertAgentStateDirAndApprovalPage(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", CredentialFile: "/c/bot.url"}

	// A new file takes the state directory; the approval page is set.
	require.NoError(t, config.UpsertAgent(path, config.Settings{
		SocketDir: "/home/alice/basalt/run", StateDir: "/home/alice/basalt/state",
		ApprovalPage: "http://localhost:8787/approve/",
	}, bot))
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/home/alice/basalt/state", c.StateDir)
	require.Equal(t, "http://localhost:8787/approve/", c.ApprovalPage)

	// Without a page the existing one stays; a new page replaces it.
	require.NoError(t, config.UpsertAgent(path, config.Settings{}, bot))
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8787/approve/", c.ApprovalPage)
	require.NoError(t, config.UpsertAgent(path, config.Settings{ApprovalPage: "http://localhost:9000/approve/"}, bot))
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:9000/approve/", c.ApprovalPage)
	require.Equal(t, "/home/alice/basalt/state", c.StateDir)
}
