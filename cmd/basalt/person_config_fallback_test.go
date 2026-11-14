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

	logged := cliOn(t, h, nil, "", "log", "--agent", "bot")
	require.Equal(t, exitOK, logged.code, logged.stderr)

	id := uuid.NewString()
	// Each of these answers from the agent's own ledger, which only the
	// per-user config leads to: the held write or the revert is not there.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"approve", "--agent", "bot", "--show", id}, "is not a held write of this agent"},
		{[]string{"revert", "--agent", "bot", "--status", id}, "prepared with this agent's credential"},
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
	list := cliOn(t, h, nil, "", "access", "--agent", "bot")
	require.Equal(t, exitOK, list.code, list.stderr)
	require.Contains(t, list.stdout, "Can write\n  public.leads")
	// The commands access prints name the per-user config.
	require.Contains(t, list.stdout, "--config "+cfg)

	up := cliOn(t, h, map[string]string{envAdminURL: d.URL}, "", "upgrade", "--agent", "bot", "--dry-run")
	require.Equal(t, exitOK, up.code, up.stderr)
	require.Contains(t, up.stderr, "the guard is up to date", "upgrade did not reach the agent's database")

	// The same commands do not fall back when root runs them.
	root := cliOn(t, systemSocketHost(t), nil, "", "log", "--agent", "bot")
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

// The engine run with --user looks for the per-user config in the home of the
// user it dropped to, not in the HOME it inherited from root.
func TestUserConfigDirIn(t *testing.T) {
	t.Parallel()
	got, err := userConfigDirIn("linux", "/home/bot")
	require.NoError(t, err)
	require.Equal(t, "/home/bot/.config", got)
	got, err = userConfigDirIn("darwin", "/Users/bot")
	require.NoError(t, err)
	require.Equal(t, "/Users/bot/Library/Application Support", got)
	_, err = userConfigDirIn("linux", "")
	require.Error(t, err)
}
