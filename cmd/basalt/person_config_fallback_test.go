package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// A bot that is not root has no --config to give: init --remote left its
// config in the user's own config directory, and log, approve and revert find
// it there, as status does.
func TestPersonCommandsFindThePerUserConfigWithoutTheConfigFlag(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(config.DefaultPath(runtime.GOOS)); err == nil {
		t.Skip("a system engine config is installed on this machine")
	}
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, perUserDirName, "engine.json")
	r := cliOn(t, h, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", cfg, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)

	id := uuid.NewString()
	// Each of these answers from the agent's own ledger, which only the
	// per-user config leads to: the held write or the revert is not there.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"approve", "--agent", "bot", "--show", id}, "is not a held write of this agent"},
	} {
		got := cliOn(t, h, nil, "", tc.args...)
		require.Equal(t, exitError, got.code, "%v: %s", tc.args, got.stderr)
		require.Contains(t, got.stderr, tc.want, "%v did not reach the per-user engine", tc.args)
		require.NotContains(t, got.stderr, config.DefaultPath(runtime.GOOS), "%v read the system path", tc.args)
	}
	pk := cliOn(t, h, nil, "", "passkey", "list", "--agent", "bot")
	require.Equal(t, exitOK, pk.code, pk.stderr)
	require.Contains(t, pk.stderr, "no active passkey")
	require.NotContains(t, pk.stderr, config.DefaultPath(runtime.GOOS))
	// passkey check also reaches the per-user ledger: init skipped the
	// passkey, so it answers that none is registered.
	chk := cliOn(t, h, nil, "", "passkey", "check", "--agent", "bot")
	require.Equal(t, exitError, chk.code, chk.stderr)
	require.Contains(t, chk.stderr, "no active passkey; register one")
	require.NotContains(t, chk.stderr, config.DefaultPath(runtime.GOOS))

	// The same commands do not fall back when root runs them.
	root := cliOn(t, systemSocketHost(t), nil, "", "passkey", "list", "--agent", "bot")
	require.NotEqual(t, exitOK, root.code)
}

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
		require.NotEqual(t, exitOK, code)
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
		require.Equal(t, exitOK, code, errOut.String())
		return out.String()
	}
	require.Contains(t, run("--agent", "bot"), "basalt engine --config ")
	require.Contains(t, run("--agent", "bot"), path)
	// The one agent the config serves needs no --agent.
	require.Contains(t, run(), path)
}
