package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// An engine.json's breaking epoch: its "breaking" field when it has one;
// else 0.0.1's shape (an agent with its own credentialFile and no store,
// or a directAddr) is 0 and today's shape is 1. The install and restart
// scripts read the same keys (osservice's TestConfigEpochMatchesTheConfigPackage).
func TestEpochOf(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		raw  string
		want int
	}{
		"0.0.1, an agent's own credentialFile": {`{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c/a.url"}]}`, 0},
		"0.0.1, directAddr":                    {`{"socketDir": "/s", "agents": [], "directAddr": "0.0.0.0:7443"}`, 0},
		"today's shape, without the field":     {`{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c/a.url"}}]}`, 1},
		"the field":                            {`{"breaking": 1, "socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}]}`, 1},
		"the field, below":                     {`{"breaking": 0, "socketDir": "/s", "agents": []}`, 0},
		"the field, above":                     {`{"breaking": 2, "socketDir": "/s", "agents": []}`, 2},
		"not an object":                        {`[]`, config.BreakingEpoch},
		"a field that is not a number":         {`{"breaking": "1"}`, config.BreakingEpoch},
	} {
		require.Equal(t, c.want, config.EpochOf([]byte(c.raw)), name)
	}
}

// Every write records this build's epoch, and a config of a later epoch is
// refused with the update that fixes it.
func TestConfigWritesAndChecksTheBreakingEpoch(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	_, err := config.UpsertAgentVault(path, config.Settings{SocketDir: "/run/basalt"},
		config.Agent{Name: "bot", OSUser: "alice", Store: config.PostgresStore("/c/bot.url")})
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"breaking": 1,`)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, config.BreakingEpoch, c.Breaking)

	later := write(t, "engine.json", `{"breaking": 2, "socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}]}`, 0o600)
	_, err = config.Load(later)
	require.True(t, config.IsBreaking(err))
	require.ErrorContains(t, err, "written by a newer BasaltDB (breaking 2, this basalt reads 1): update basalt")
}
