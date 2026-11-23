package app

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// TestInitIsTheOneSetupCommand checks the one basalt command a step names
// for a setup job (CONTRACT.md, Next steps): basalt init with --agent, and
// --remote on an agent-operated engine, and nothing else: no --config, no
// saved flags, no change flag.
func TestInitIsTheOneSetupCommand(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", "/srv/basalt/engine.json", "/srv/my basalt/engine.json", config.DefaultPath("linux")} {
		c := mustCommands(t, path, "linux")
		require.Equal(t, "basalt init --agent bot", c.Init(), path)
		require.Equal(t, "basalt init --agent bot --remote", c.OperatedBy("AGENT").Init(), path)
		require.Equal(t, "basalt init --agent bot", c.OperatedBy("PERSON").Init(), path)
	}
}

func TestCommandsRefuseARelativeConfigPath(t *testing.T) {
	t.Parallel()
	_, err := NewCommands("bot", "engine.json", "linux", testManager())
	require.Error(t, err)
}

func TestCommandsRefuseABadAgentName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "Bot", "bot; rm -rf /", "a b", "$(x)"} {
		_, err := NewCommands(name, "", "linux", testManager())
		require.Error(t, err, name)
	}
}

func TestForegroundEngineCommands(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "/home/me/engine.json", "linux").Foreground()
	require.Equal(t, "basalt engine --config /home/me/engine.json", c.EngineStart())
	require.Equal(t, "basalt engine --config /home/me/engine.json", c.EngineRestart())
	def := mustCommands(t, "", "darwin").Foreground()
	require.Equal(t, "basalt engine --config "+guidance.ShellQuote(config.DefaultPath("darwin")), def.EngineStart())
	spaced := mustCommands(t, "/home/my me/engine.json", "linux").Foreground()
	require.Equal(t, "basalt engine --config '/home/my me/engine.json'", spaced.EngineStart())
}

func TestServiceEngineCommands(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "", "linux")
	require.Equal(t, "sudo systemctl start basalt-engine.service", c.EngineStart())
	require.Contains(t, c.EngineRestart(), "sudo systemctl ")
}

func TestShellQuoteALeadingEquals(t *testing.T) {
	t.Parallel()
	require.Equal(t, "'=ls'", guidance.ShellQuote("=ls"), "zsh expands =cmd")
	require.Equal(t, "plain/path", guidance.ShellQuote("plain/path"))
}

func mustCommands(t *testing.T, path, goos string) guidance.Commands {
	t.Helper()
	c, err := NewCommands("bot", path, goos, testManager())
	require.NoError(t, err)
	return c
}
