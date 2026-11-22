package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/updatecheck"
)

func TestPrintUpdateLine(t *testing.T) {
	n := &updatecheck.Notice{Current: "0.0.1", Latest: "0.0.2", URL: "u"}
	var b bytes.Buffer
	printUpdateLine(&b, func(string) string { return "" }, n, "/x/basalt")
	if got := b.String(); strings.Contains(got, "\x1b") || !strings.Contains(got, "basalt 0.0.1 is out of date; 0.0.2 is available.") || !strings.HasSuffix(got, "\n") {
		t.Errorf("non-terminal output = %q", got)
	}
	b.Reset()
	printUpdateLine(&b, func(string) string { return "" }, nil, "/x/basalt")
	if b.Len() != 0 {
		t.Errorf("printed without a notice: %q", b.String())
	}
}

func TestStartUpdateNoticeSkips(t *testing.T) {
	// BASALT_CACHE_DIR points at an empty dir, so no notice could print
	// even if a command did not skip; the point is that no refresh starts
	// and nothing blocks. The off switch and skip list return at once.
	getenv := func(k string) string {
		if k == updatecheck.EnvDisable {
			return "off"
		}
		return ""
	}
	var e bytes.Buffer
	for _, args := range [][]string{nil, {"engine"}, {"mcp"}, {"status", "--json"}, {"version"}} {
		startUpdateNotice(context.Background(), args, stdio{err: &e}, getenv)()
	}
	if e.Len() != 0 {
		t.Errorf("printed %q", e.String())
	}
}

// writeUserConfig saves an engine.json where a person without the system
// config reads it, with the given mode.
func writeUserConfig(t *testing.T, h *fakeHost, body string, mode os.FileMode) {
	t.Helper()
	if _, err := os.Stat(config.DefaultPath("linux")); err == nil {
		t.Skip("a system engine.json exists on this machine")
	}
	dir := filepath.Join(h.configDir, perUserDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	require.NoError(t, os.Chmod(path, mode))
}

// configWith is a valid engine.json with updateCheck set to state.
func configWith(state string) string {
	return `{"socketDir":"/run/basalt","updateCheck":"` + state + `",` +
		`"agents":[{"name":"bot","osUser":"u","store":{"kind":"POSTGRES","credentialFile":"/etc/basalt/agents/bot.url"}}]}`
}

// releaseBuild makes this test binary a build with a release number.
func releaseBuild(t *testing.T) {
	t.Helper()
	old := buildinfo.Version
	buildinfo.Version = "0.0.1"
	t.Cleanup(func() { buildinfo.Version = old })
}

func TestUpdateOffFollowsAReadableConfig(t *testing.T) {
	releaseBuild(t)
	getenv := func(string) string { return "" }
	h := newFakeHost(t)
	writeUserConfig(t, h, configWith("OFF"), 0o600)
	require.True(t, updateOff(getenv, "linux", h))
	h = newFakeHost(t)
	writeUserConfig(t, h, configWith("ON"), 0o600)
	require.False(t, updateOff(getenv, "linux", h))
}

func TestUpdateOffWithNoConfigIsOn(t *testing.T) {
	releaseBuild(t)
	h := newFakeHost(t)
	if _, err := os.Stat(config.DefaultPath("linux")); err == nil {
		t.Skip("a system engine.json exists on this machine")
	}
	require.False(t, updateOff(func(string) string { return "" }, "linux", h))
}
