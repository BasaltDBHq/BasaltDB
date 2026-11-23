package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

type result struct {
	code           int
	stdout, stderr string
}

// cliOn runs basalt on host h with stdin and an environment holding only
// env: pass newFakeHost(t) for a person who is not root,
// whose config dir is short enough for the sockets next to the config.
func cliOn(t *testing.T, h *fakeHost, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cache := t.TempDir()
	c := newIO(context.Background(), cli.Stdio{In: strings.NewReader(stdin), Out: &stdout, Err: &stderr},
		func(k string) string {
			if v, ok := env[k]; ok || k != envCacheDir {
				return v
			}
			return cache
		})
	c.Host = h
	code := runGuard(c, args)
	return result{code, stdout.String(), stderr.String()}
}

var guardCommands = map[string]func(*cli.IO, []string) int{
	"init": runInitCommand,
}

func tempConfig(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "basalt", "engine.json")
}

func TestHelpSaysOneEngineServesManyAgents(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--help"}, {"init", "-h"}} {
		code, stdout, stderr := runArgs(args...)
		require.Equal(t, cli.ExitOK, code, stderr)
		out := stdout + stderr
		for _, want := range []string{"One engine serves many agents", "one database", "basalt init --remote --agent NAME"} {
			require.Contains(t, out, want, args)
		}
	}
}

// runGuard runs args[0] on c with the path flags moved into c.Paths.
func runGuard(c *cli.IO, args []string) int {
	cmd := guardCommands[args[0]]
	return cmd(c, takePathFlags(c, cmd, args[1:]))
}
