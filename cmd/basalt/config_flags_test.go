package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The engine config, the credential file and the sockets are found by
// themselves: only basalt engine takes --config (CLI contract, Config
// discovery).
func TestOnlyEngineTakesTheConfigFlags(t *testing.T) {
	t.Setenv("BASALT_DATABASE_URL", "")
	t.Setenv("BASALT_ADMIN_DATABASE_URL", "")
	for _, k := range agentMarkers {
		t.Setenv(k, "")
	}
	cmds := [][]string{
		{"init"},
		{"init", "--remote"},
		{"mcp"},
		{"service", "install"},
		{"service", "uninstall"},
		{"approve"},
		{"passkey", "list"},
		{"passkey", "check"},
		{"upgrade"},
		{"uninstall"},
		{"classify"},
		{"trust", "list"},
		{"trust", "add"},
		{"trust", "pin"},
		{"trust", "remove"},
		{"trust", "disable"},
	}
	for _, base := range cmds {
		for _, flag := range []string{"--config", "--credential-file", "--socket-dir", "--socket"} {
			name := strings.Join(append(append([]string{}, base...), flag), " ")
			t.Run(name, func(t *testing.T) {
				var out, errw bytes.Buffer
				args := append(append([]string{}, base...), flag, "/nowhere")
				code := run(context.Background(), args, stdio{in: strings.NewReader(""), out: &out, err: &errw})
				require.Equal(t, exitUsage, code, "stderr: %s", errw.String())
				require.Contains(t, errw.String(), "flag provided but not defined: -"+strings.TrimPrefix(flag, "--"))
			})
		}
	}
}

func TestEngineStillTakesConfig(t *testing.T) {
	t.Parallel()
	var out, errw bytes.Buffer
	code := run(context.Background(), []string{"engine", "--config"}, stdio{in: strings.NewReader(""), out: &out, err: &errw})
	require.Equal(t, exitUsage, code)
	require.Contains(t, errw.String(), "flag needs an argument: -config")
}
