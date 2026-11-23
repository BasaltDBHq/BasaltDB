package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

func runArgs(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, cli.Stdio{In: strings.NewReader(""), Out: &stdout, Err: &stderr})
	return code, stdout.String(), stderr.String()
}

func TestRun(t *testing.T) {
	t.Parallel()
	cases := []struct {
		args       []string
		code       int
		stdout     string
		stderrPart string
	}{
		{args: []string{"version"}, code: cli.ExitOK, stdout: "basalt " + buildinfo.Version + "\n"},
		{args: []string{"--version"}, code: cli.ExitOK, stdout: "basalt " + buildinfo.Version + "\n"},
		{args: nil, code: cli.ExitUsage, stderrPart: "Usage: basalt"},
		{args: []string{"serve"}, code: cli.ExitUsage, stderrPart: `unknown command "serve"`},
		// Removed: the setup page's Update check does their jobs.
		{args: []string{"passkey", "list"}, code: cli.ExitUsage, stderrPart: `unknown command "passkey"`},
		{args: []string{"trust", "pin", "--host", "h"}, code: cli.ExitUsage, stderrPart: `unknown command "trust"`},
		{args: []string{"classify"}, code: cli.ExitUsage, stderrPart: `unknown command "classify"`},
		{args: []string{"mcp"}, code: cli.ExitUsage, stderrPart: "-agent"},
		{args: []string{"mcp", "--agent", "Bad/Name"}, code: cli.ExitUsage},
		// No engine: the shim answers itself; an empty session ends cleanly.
		{args: []string{"mcp", "--agent", "nobody_runs_this"}, code: cli.ExitOK},
		{args: []string{"engine", "--config", filepath.Join(t.TempDir(), "none.json")}, code: cli.ExitError, stderrPart: "basalt engine:"},
		{args: []string{"engine", "extra"}, code: cli.ExitUsage},
		{args: []string{"service"}, code: cli.ExitUsage, stderrPart: "want install"},
		{args: []string{"service", "restart"}, code: cli.ExitUsage},
	}
	for _, tc := range cases {
		code, stdout, stderr := runArgs(tc.args...)
		require.Equal(t, tc.code, code, "%v: %s", tc.args, stderr)
		if tc.stdout != "" {
			require.Equal(t, tc.stdout, stdout)
		}
		require.Contains(t, stderr, tc.stderrPart, tc.args)
	}

	code, stdout, _ := runArgs("help")
	require.Equal(t, cli.ExitOK, code)
	for _, name := range []string{"engine", "mcp", "service", "version"} {
		require.Contains(t, stdout, name)
	}
}
