package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// userHost is a person (not root) whose config directory is dir.
type userHost struct {
	Machine
	dir string
}

func (h userHost) Euid() int                      { return 501 }
func (h userHost) UserConfigDir() (string, error) { return h.dir, nil }

func writeConfig(t *testing.T, path string, agents ...string) {
	t.Helper()
	body := ""
	for i, a := range agents {
		if i > 0 {
			body += ","
		}
		body += `{"name": "` + a + `", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/x/` + a + `.url"}}`
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(`{"socketDir": "/s", "agents": [`+body+`]}`), 0o600))
}

// twoConfigs is a machine with a system and a user engine config.
func twoConfigs(t *testing.T, system, user []string) (*IO, string, string) {
	t.Helper()
	dir := t.TempDir()
	sysPath := filepath.Join(dir, "etc", "engine.json")
	userPath := filepath.Join(dir, "home", "basalt", "engine.json")
	writeConfig(t, sysPath, system...)
	writeConfig(t, userPath, user...)
	c := &IO{Host: userHost{dir: filepath.Join(dir, "home")}, SystemConfigPath: sysPath}
	return c, sysPath, userPath
}

// With two configs and the agent in exactly one, that one is used.
func TestFindConfigPicksTheConfigThatHoldsTheAgent(t *testing.T) {
	t.Parallel()
	c, sys, user := twoConfigs(t, []string{"demo_bot"}, []string{"other"})
	got, err := c.FindConfig("demo_bot")
	require.NoError(t, err)
	require.Equal(t, sys, got)
	got, err = c.FindConfig("other")
	require.NoError(t, err)
	require.Equal(t, user, got)
}

// The agent in both or in neither: a refusal that names it and both paths.
func TestFindConfigRefusesWhenTheAgentIsInBothOrNeither(t *testing.T) {
	t.Parallel()
	c, sys, user := twoConfigs(t, []string{"a", "shared"}, []string{"b", "shared"})
	for _, agent := range []string{"shared", "missing"} {
		got, err := c.FindConfig(agent)
		require.Empty(t, got)
		var e *AgentConfigsError
		require.ErrorAs(t, err, &e)
		require.Contains(t, err.Error(), agent)
		require.Contains(t, err.Error(), sys)
		require.Contains(t, err.Error(), user)
		require.Equal(t, agent == "shared", e.InBoth)
	}
}

// Without an agent the current rule stays: two configs refuse, naming both.
func TestFindConfigWithoutAnAgentRefusesTwoConfigs(t *testing.T) {
	t.Parallel()
	c, sys, user := twoConfigs(t, []string{"a"}, []string{"b"})
	_, err := c.FindConfig("")
	require.ErrorContains(t, err, "two engine configs")
	require.ErrorContains(t, err, sys)
	require.ErrorContains(t, err, user)
}

// One config only: it is used whatever the agent.
func TestFindConfigWithOneConfigIgnoresTheAgent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sys := filepath.Join(dir, "etc", "engine.json")
	writeConfig(t, sys, "a")
	c := &IO{Host: userHost{dir: filepath.Join(dir, "home")}, SystemConfigPath: sys}
	got, err := c.FindConfig("nobody")
	require.NoError(t, err)
	require.Equal(t, sys, got)
}
