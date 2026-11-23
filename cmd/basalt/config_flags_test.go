package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// The engine config, the credential file and the sockets are found by
// themselves: only basalt engine takes --config (CLI contract, Config
// discovery).
func TestOnlyEngineTakesTheConfigFlags(t *testing.T) {
	t.Setenv("BASALT_DATABASE_URL", "")
	t.Setenv("BASALT_ADMIN_DATABASE_URL", "")
	for _, k := range cli.AgentMarkers {
		t.Setenv(k, "")
	}
	cmds := [][]string{
		{"init"},
		{"init", "--remote"},
		{"mcp"},
		{"service", "install"},
	}
	for _, base := range cmds {
		for _, flag := range []string{"--config", "--credential-file", "--socket-dir", "--socket"} {
			name := strings.Join(append(append([]string{}, base...), flag), " ")
			t.Run(name, func(t *testing.T) {
				var out, errw bytes.Buffer
				args := append(append([]string{}, base...), flag, "/nowhere")
				code := run(context.Background(), args, stdio{in: strings.NewReader(""), out: &out, err: &errw})
				require.Equal(t, cli.ExitUsage, code, "stderr: %s", errw.String())
				require.Contains(t, errw.String(), "flag provided but not defined: -"+strings.TrimPrefix(flag, "--"))
			})
		}
	}
}

func TestEngineStillTakesConfig(t *testing.T) {
	t.Parallel()
	var out, errw bytes.Buffer
	code := run(context.Background(), []string{"engine", "--config"}, stdio{in: strings.NewReader(""), out: &out, err: &errw})
	require.Equal(t, cli.ExitUsage, code)
	require.Contains(t, errw.String(), "flag needs an argument: -config")
}

// basalt service install always installs the engine on the system config
// path, the one the removal script checks for engine.json before it
// removes anything: it takes no --config.
func TestServiceInstallIsPinnedToTheConfigTheRemovalChecks(t *testing.T) {
	t.Parallel()
	var out, errw bytes.Buffer
	code := run(context.Background(), []string{"service", "install", "--config", "/elsewhere/engine.json", "--dry-run"}, stdio{in: strings.NewReader(""), out: &out, err: &errw})
	require.Equal(t, cli.ExitUsage, code)
	require.Contains(t, errw.String(), "flag provided but not defined: -config")
	for _, goos := range []string{"linux", "darwin"} {
		script, err := osservice.RemoveScript(goos)
		require.NoError(t, err)
		path := config.DefaultPath(goos)
		if strings.Contains(path, " ") {
			path = "'" + path + "'"
		}
		require.Contains(t, script, "[ ! -e "+path+" ]", goos)
	}
}
