package setupcli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// basaltDir is a config folder named as the person's own (…/basalt) with
// an engine.json and an agent's credential.
func basaltDir(t *testing.T, engineJSON string) (dir, path string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "basalt")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "agents"), 0o700))
	path = filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(engineJSON), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agents", "bot.url"), []byte("postgres://x\n"), 0o600))
	return dir, path
}

const config001 = `{"socketDir": "/home/a/.config/basalt/run", "agents": [{"name": "bot", "osUser": "a", "credentialFile": "/home/a/.config/basalt/agents/bot.url"}], "limits": {}}`

// basalt init moves a config folder from before the last breaking release
// aside, whole, to the first free .old name: it never deletes, overwrites
// or nests one.
func TestMoveBreakingConfigAside(t *testing.T) {
	t.Parallel()
	dir, path := basaltDir(t, config001)
	old, err := moveBreakingConfigAside(path)
	require.NoError(t, err)
	require.Equal(t, dir+".old", old)
	require.NoDirExists(t, dir)
	require.FileExists(t, filepath.Join(old, "engine.json"))
	require.FileExists(t, filepath.Join(old, "agents", "bot.url"), "never deleted")

	// Again, with .old taken: .old.2, and .old is untouched.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "agents"), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(config001), 0o600))
	again, err := moveBreakingConfigAside(path)
	require.NoError(t, err)
	require.Equal(t, dir+".old.2", again)
	require.FileExists(t, filepath.Join(old, "agents", "bot.url"))
	require.NoDirExists(t, filepath.Join(old, "basalt"), "never nested")
}

// A config of this epoch, or none, stays where it is.
func TestMoveBreakingConfigAsideLeavesTodaysConfig(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"before the field": `{"socketDir": "/s", "agents": [{"name": "bot", "osUser": "a", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}]}`,
		"with the field":   `{"breaking": 1, "socketDir": "/s", "agents": []}`,
	} {
		dir, path := basaltDir(t, raw)
		old, err := moveBreakingConfigAside(path)
		require.NoError(t, err, name)
		require.Empty(t, old, name)
		require.DirExists(t, dir, name)
	}
	old, err := moveBreakingConfigAside(filepath.Join(t.TempDir(), "basalt", "engine.json"))
	require.NoError(t, err)
	require.Empty(t, old, "no config")
}
