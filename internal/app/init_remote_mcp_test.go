package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

func skipIfSystemConfig(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(config.DefaultPath(runtime.GOOS)); err == nil {
		t.Skip("a system engine config is installed on this machine")
	}
}

// userRemote is a run not as root on host h, every agent login refused.
func userRemote(h *fakeHost) remoteEnv {
	return remoteEnv{host: h, login: refusedLogin, probe: noNetworkProbe, noNetwork: true}
}

// Non-root init --remote without --config prints `basalt mcp --agent NAME`
// and no --config: basalt mcp finds the per-user config, and the socket
// directory in it.
func TestInitRemoteMCPCommandDefaultConfig(t *testing.T) {
	t.Parallel()
	skipIfSystemConfig(t)
	h := newFakeHost(t)
	r := remoteWith(t, userRemote(h), "", "--agent", "bot")
	want := []string{fakeBin, "mcp", "--agent", "bot"}
	require.Equal(t, want, r.res.MCPCommand)
	require.Contains(t, r.stdout, "  "+cli.ShellJoin(want)+"\n")
	require.NotContains(t, r.stdout, "--config")
	require.FileExists(t, filepath.Join(h.configDir, config.UserDirName, "engine.json"))
}

// A config in another place gives the same command: basalt mcp finds it.
func TestInitRemoteMCPCommandWithConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "bot", "engine.json")
	r := remoteWith(t, userRemote(h), cfg, "--agent", "lead_bot")
	want := []string{fakeBin, "mcp", "--agent", "lead_bot"}
	require.Equal(t, want, r.res.MCPCommand)
	require.Contains(t, r.stdout, "  "+cli.ShellJoin(want)+"\n")
}

// Root/service init --remote with a service config returns the command the
// agent's OS user runs for the service socket: only the agent.
func TestInitRemoteMCPCommandAsRootService(t *testing.T) {
	t.Parallel()
	r := remoteWith(t, sudo(t, "1234"), withState(t, tempConfig(t)), "--agent", "bot")
	require.True(t, r.cfg.Service())
	require.Equal(t, config.DefaultSocketDir(runtime.GOOS), r.cfg.SocketDir)
	require.Equal(t, []string{fakeBin, "mcp", "--agent", "bot"}, r.res.MCPCommand)
}

// Not root, with a system engine config in place, init --remote stops and
// names it: a second config in the user's folder would make every later
// command stop on two.
func TestInitRemoteRefusesASecondConfigBesideTheSystemOne(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	system := filepath.Join(h.configDir, "etc", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(system), 0o700))
	require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), cli.Stdio{In: strings.NewReader(""), Out: &stdout, Err: &stderr},
		func(string) string { return "" })
	c.Host, c.AgentLogin, c.Probe, c.SystemConfigPath = h, refusedLogin, noNetworkProbe, system
	code := runInit(c, setupHost{}, []string{"--remote", "--agent", "bot"})
	require.Equal(t, cli.ExitError, code, stderr.String())
	require.Contains(t, stderr.String(), system)
	_, err := os.Stat(filepath.Join(h.configDir, config.UserDirName, "engine.json"))
	require.ErrorIs(t, err, os.ErrNotExist, "no second config")
}

// Not root, with a system config and the user's own config both in place and
// the agent only in the user's: init --remote --agent goes on in the user's
// config, where the agent lives, and writes no second one.
func TestInitRemoteGoesOnInTheUserConfigWhenTheAgentIsOnlyThere(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	system := filepath.Join(h.configDir, "etc", "engine.json")
	user := filepath.Join(h.configDir, config.UserDirName, "engine.json")
	for p, agent := range map[string]string{system: "other", user: "bot"} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(`{"socketDir": "/s", "stateDir": "`+filepath.Join(h.configDir, config.UserDirName, setup.StateDirName)+`", "operatedBy": "AGENT", "pagesUrl": "https://portal.basaltvault.app", "agents": [{"name": "`+agent+`", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "`+filepath.Join(h.configDir, "cred", agent+".url")+`"}}]}`), 0o600))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(filepath.Dir(user), setup.StateDirName), 0o700))
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), cli.Stdio{In: strings.NewReader(""), Out: &stdout, Err: &stderr},
		func(string) string { return "" })
	c.Host, c.AgentLogin, c.Probe, c.SystemConfigPath = h, refusedLogin, noNetworkProbe, system
	_, err := setupcli.InitRemote(c, setupHost{}, []string{"--remote", "--agent", "bot"})
	require.NoError(t, err, stderr.String())
}
