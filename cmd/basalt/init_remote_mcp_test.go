package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
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
	require.Contains(t, r.stdout, "  "+shellJoin(want)+"\n")
	require.NotContains(t, r.stdout, "--config")
	require.FileExists(t, filepath.Join(h.configDir, perUserDirName, "engine.json"))
}

// A config in another place gives the same command: basalt mcp finds it.
func TestInitRemoteMCPCommandWithConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "bot", "engine.json")
	r := remoteWith(t, userRemote(h), cfg, "--agent", "lead_bot")
	want := []string{fakeBin, "mcp", "--agent", "lead_bot"}
	require.Equal(t, want, r.res.MCPCommand)
	require.Contains(t, r.stdout, "  "+shellJoin(want)+"\n")
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
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(string) string { return "" })
	c.host, c.agentLogin, c.probe, c.systemConfigPath = h, refusedLogin, noNetworkProbe, system
	code := runInitAdmin(c, []string{"--remote", "--agent", "bot"})
	require.Equal(t, exitError, code, stderr.String())
	require.Contains(t, stderr.String(), system)
	_, err := os.Stat(filepath.Join(h.configDir, perUserDirName, "engine.json"))
	require.ErrorIs(t, err, os.ErrNotExist, "no second config")
}

// init and init --demo, not root, with a system engine config in place and
// --no-service: refused before any SQL, no second config.
func TestInitRefusesAForegroundSetupBesideTheSystemConfig(t *testing.T) {
	t.Parallel()
	for _, extra := range [][]string{
		{"--agent", "bot", "--write", "public.leads"},
		{"--demo"},
	} {
		h := newFakeHost(t)
		system := filepath.Join(h.configDir, "etc", "engine.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(system), 0o700))
		require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
		var stdout, stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
			func(k string) string {
				if k == envAdminURL {
					return "postgres://admin@127.0.0.1:1/postgres"
				}
				return ""
			})
		c.host, c.systemConfigPath = h, system
		code := runInitAdmin(c, append([]string{"--no-service", "--yes", "--skip-passkey"}, extra...))
		require.Equal(t, exitError, code, "%v: %s", extra, stderr.String())
		require.Contains(t, stderr.String(), system)
		_, err := os.Stat(filepath.Join(h.configDir, perUserDirName, "engine.json"))
		require.ErrorIs(t, err, os.ErrNotExist, "no second config")
	}
}

// The backstop for a service declined at the prompt: perUserPaths, which
// moves a foreground setup to the person's folder, refuses beside a system
// config.
func TestPerUserPathsRefusesBesideTheSystemConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	system := filepath.Join(h.configDir, "etc", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(system), 0o700))
	require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}},
		func(string) string { return "" })
	c.host, c.systemConfigPath = h, system
	_, err := perUserPaths(c, initFlags{agent: "bot"})
	require.ErrorContains(t, err, system)

	// With no system config it moves to the person's folder.
	require.NoError(t, os.Remove(system))
	f, err := perUserPaths(c, initFlags{agent: "bot"})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(h.configDir, perUserDirName, "engine.json"), f.configPath)
}
