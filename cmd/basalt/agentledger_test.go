package main

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// A person (not root) on a service engine cannot read its config or the
// agent's credential, and no socket answers for them any more: approve,
// revert and passkey say to use sudo and never read the files.
func TestServiceModeAsAPersonSaysToUseSudo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  func(*cliIO, []string) int
		args []string
	}{
		{"approve", runApprove, []string{"--agent", "bot", "--show", "0190b4a0-0000-7000-8000-000000000000"}},
		{"revert", runRevert, []string{"--agent", "bot", "--status", "0190b4a0-0000-7000-8000-000000000000"}},
		{"passkey list", runPasskey, []string{"list", "--agent", "bot"}},
	} {
		var stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
		h := newFakeHost(t)
		h.euid = 1000
		c.host = h
		c.engine = engineAccess{unitInstalled: func() bool { return true }}
		require.Equal(t, exitError, tc.run(c, tc.args), tc.name)
		require.Contains(t, stderr.String(), "this engine runs as a service", tc.name)
		require.Contains(t, stderr.String(), "sudo", tc.name)
		require.NotContains(t, stderr.String(), config.DefaultPath(runtime.GOOS), "%s read the engine's files", tc.name)
	}
}

// With no unit, or a config, a credential file or the env given, the
// command reads the files itself; root always does.
func TestServiceModeOnlyForAPersonOnTheSystemConfig(t *testing.T) {
	t.Parallel()
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
	h := newFakeHost(t)
	h.euid = 1000
	c.host = h
	def := config.DefaultPath(runtime.GOOS)
	c.engine = engineAccess{unitInstalled: func() bool { return false }}
	require.False(t, c.serviceMode("bot", "", def))
	c.engine.unitInstalled = func() bool { return true }
	require.True(t, c.serviceMode("bot", "", def))
	require.False(t, c.serviceMode("bot", "", "/elsewhere/engine.json"))
	require.False(t, c.serviceMode("bot", "/tmp/bot.url", def))
	require.False(t, c.serviceMode("", "", def))
	h.euid = 0
	require.False(t, c.serviceMode("bot", "", def), "root reads the files")
}
