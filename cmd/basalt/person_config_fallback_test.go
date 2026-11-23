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

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// The engine finds the same per-user config when it is started without
// --config by a user who is not root.
func TestEngineFindsThePerUserConfigWithoutTheConfigFlag(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(config.DefaultPath(runtime.GOOS)); err == nil {
		t.Skip("a system engine config is installed on this machine")
	}
	h := newFakeHost(t)
	user := filepath.Join(h.configDir, perUserDirName, "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(user), 0o700))
	require.NoError(t, os.WriteFile(user, []byte(`not json`), 0o600))
	run := func(args ...string) string {
		var errOut bytes.Buffer
		code := runEngineOn(context.Background(), args, stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &errOut}, h)
		require.NotEqual(t, cli.ExitOK, code)
		return errOut.String()
	}
	require.Contains(t, run(), "engine.json", "the per-user config was loaded")
	require.NotContains(t, run(), config.DefaultPath(runtime.GOOS))
	require.Contains(t, run("--config", filepath.Join(h.configDir, "x.json")), "x.json")
}

// basalt mcp without --config reads the per-user config a rootless bot's init
// left, so status names the foreground engine command of that config.
func TestMCPFindsThePerUserConfigWithoutTheConfigFlag(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(config.DefaultPath(runtime.GOOS)); err == nil {
		t.Skip("a system engine config is installed on this machine")
	}
	h := newFakeHost(t)
	dir := filepath.Join(h.configDir, perUserDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "engine.json")
	cfg := `{"socketDir": "` + filepath.Join(dir, "run") + `", "operatedBy": "AGENT", "pagesUrl": "https://portal.basaltvault.app", "mode": "SAME_USER",
		"agents": [{"name": "bot", "osUser": "bot", "store": {"kind": "POSTGRES", "credentialFile": "` + filepath.Join(dir, "agents", "bot.url") + `"}, "initArgs": ["--agent=bot"]}]}`
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	run := func(args ...string) string {
		var out, errOut bytes.Buffer
		in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}}` + "\n"
		code := runMCPOn(context.Background(), args, stdio{in: strings.NewReader(in), out: &out, err: &errOut}, h)
		require.Equal(t, cli.ExitOK, code, errOut.String())
		return out.String()
	}
	require.Contains(t, run("--agent", "bot"), "basalt engine --config ")
	require.Contains(t, run("--agent", "bot"), path)
	// The one agent the config serves needs no --agent.
	require.Contains(t, run(), path)
}
