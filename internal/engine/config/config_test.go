package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func write(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func TestLoad(t *testing.T) {
	t.Parallel()
	path := write(t, "engine.json", `{
		"socketDir": "/run/basalt",
		"agents": [{"name": "tracker_bot", "osUser": "iman", "credentialFile": "/etc/basalt/agents/tracker_bot.url"}],
		"limits": {"statementTimeoutMs": 2500, "readRowLimit": 200}
	}`, 0o600)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "/run/basalt/tracker_bot.sock", c.SocketPath("tracker_bot"))
	require.Equal(t, 2500*time.Millisecond, c.Limits.StatementTimeout())
	require.Equal(t, 200, c.Limits.ReadRowLimit)
}

func TestLoadRefuses(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown key":     `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}], "extra": 1}`,
		"no agents":       `{"socketDir": "/s", "agents": []}`,
		"no socket dir":   `{"agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}]}`,
		"bad name":        `{"socketDir": "/s", "agents": [{"name": "Bot!", "osUser": "u", "credentialFile": "/c"}]}`,
		"duplicate name":  `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}, {"name": "a", "osUser": "v", "credentialFile": "/d"}]}`,
		"no os user":      `{"socketDir": "/s", "agents": [{"name": "a", "credentialFile": "/c"}]}`,
		"negative limit":  `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}], "limits": {"readRowLimit": -1}}`,
		"not json":        `socketDir=/s`,
		"socket too long": `{"socketDir": "/` + strings.Repeat("d", 100) + `", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}]}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(write(t, "engine.json", content, 0o600))
			require.Error(t, err)
		})
	}
}

func TestCheckSocketPath(t *testing.T) {
	t.Parallel()
	require.NoError(t, config.CheckSocketPath("/Users/someone/basalt-m4/run/demo_bot.sock"))
	require.NoError(t, config.CheckSocketPath("/"+strings.Repeat("d", 102)))
	err := config.CheckSocketPath("/" + strings.Repeat("d", 103))
	require.ErrorContains(t, err, "is 104 bytes; Unix sockets allow 103")
}

func TestValidAgentName(t *testing.T) {
	t.Parallel()
	require.True(t, config.ValidAgentName("bot"))
	require.True(t, config.ValidAgentName("tracker_bot2"))
	require.False(t, config.ValidAgentName("tracker-bot"), "the guard's role names have no hyphen")
	require.False(t, config.ValidAgentName(""))
	require.False(t, config.ValidAgentName("2bot"))
	require.False(t, config.ValidAgentName("Bot"))
	require.False(t, config.ValidAgentName("bot.x"))
	require.False(t, config.ValidAgentName("bot/../x"))
	require.True(t, config.ValidAgentName("a"+strings.Repeat("b", 49)))
	require.False(t, config.ValidAgentName("a"+strings.Repeat("b", 50)), "basalt_agent_<name> must fit 63 bytes")
}

func TestReadCredential(t *testing.T) {
	t.Parallel()
	url := "postgres://basalt_agent_bot@db.example/app"
	got, err := config.ReadCredential(write(t, "bot.url", url+"\n", 0o600))
	require.NoError(t, err)
	require.Equal(t, url, got)

	_, err = config.ReadCredential(write(t, "bot.url", url, 0o640))
	require.ErrorContains(t, err, "readable by the engine's user only")
	_, err = config.ReadCredential(write(t, "bot.url", url, 0o604))
	require.ErrorContains(t, err, "readable by the engine's user only")
	_, err = config.ReadCredential(write(t, "bot.url", "  \n", 0o600))
	require.ErrorContains(t, err, "empty")
	_, err = config.ReadCredential(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	require.Equal(t, "/etc/basalt/engine.json", config.DefaultPath("linux"))
	require.Equal(t, "/run/basalt", config.DefaultSocketDir("linux"))
	require.Equal(t, "/Library/Application Support/Basalt/engine.json", config.DefaultPath("darwin"))
	require.Equal(t, "/Library/Application Support/Basalt/run", config.DefaultSocketDir("darwin"))
	require.Equal(t, "/var/lib/basalt", config.DefaultStateDir("linux"))
	require.Equal(t, "/Library/Application Support/Basalt/state", config.DefaultStateDir("darwin"))
	require.Equal(t, "/srv/state", config.Config{StateDir: "/srv/state"}.StateDirFor("linux"))
	require.Equal(t, "/var/lib/basalt", config.Config{}.StateDirFor("linux"))
}
