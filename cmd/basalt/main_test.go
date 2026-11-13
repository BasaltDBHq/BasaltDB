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

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

func runArgs(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, stdio{in: strings.NewReader(""), out: &stdout, err: &stderr})
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
		{args: []string{"version"}, code: exitOK, stdout: "basalt " + buildinfo.Version + "\n"},
		{args: []string{"--version"}, code: exitOK, stdout: "basalt " + buildinfo.Version + "\n"},
		{args: nil, code: exitUsage, stderrPart: "Usage: basalt"},
		{args: []string{"serve"}, code: exitUsage, stderrPart: `unknown command "serve"`},
		{args: []string{"mcp"}, code: exitUsage, stderrPart: "-agent"},
		{args: []string{"mcp", "--agent", "Bad/Name"}, code: exitUsage},
		// No engine: the shim answers itself; an empty session ends cleanly.
		{args: []string{"mcp", "--socket", filepath.Join(t.TempDir(), "none.sock")}, code: exitOK},
		{args: []string{"engine", "--config", filepath.Join(t.TempDir(), "none.json")}, code: exitError, stderrPart: "basalt engine:"},
		{args: []string{"engine", "extra"}, code: exitUsage},
		{args: []string{"service"}, code: exitUsage, stderrPart: "want install or uninstall"},
		{args: []string{"service", "restart"}, code: exitUsage},
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
	require.Equal(t, exitOK, code)
	for _, name := range []string{"engine", "mcp", "service", "version"} {
		require.Contains(t, stdout, name)
	}
}

func TestServiceUninstallDryRun(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runArgs("service", "uninstall", "--dry-run", "--binary", "/usr/local/bin/basalt")
	// The plan stops the service only when its unit file is on this host.
	installed := func(path string) bool { _, err := os.Stat(path); return err == nil }
	switch runtime.GOOS {
	case "linux":
		require.Equal(t, exitOK, code, stderr)
		require.Contains(t, stdout, "rm -f "+service.SystemdUnitPath)
		if installed(service.SystemdUnitPath) {
			require.Contains(t, stdout, "systemctl disable --now basalt-engine.service")
		}
	case "darwin":
		require.Equal(t, exitOK, code, stderr)
		require.Contains(t, stdout, "rm -f "+service.LaunchdPlist)
		if installed(service.LaunchdPlist) {
			require.Contains(t, stdout, "launchctl bootout system/dev.basaltdb.engine")
		}
	default:
		require.Equal(t, exitError, code)
	}
}
