package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/links"
)

// cliHost is cli with host h, which records the links basalt opens instead
// of starting a browser.
func cliHost(t *testing.T, h host, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(string) string { return "" })
	c.host = h
	code := guardCommands[args[0]](c, args[1:])
	return result{code, stdout.String(), stderr.String()}
}

func TestOpenLink(t *testing.T) {
	t.Parallel()
	link := "http://localhost:8787/approvals/0190a3f2-7c1e-7000-8000-000000000001#1.abc"
	h := newFakeHost(t)
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
	c.host = h

	require.NoError(t, openLink(c, link, &stdout, linkRef{}))
	require.Equal(t, []string{link}, h.opened)
	require.Empty(t, stdout.String(), "an opened link is not printed")
	require.Contains(t, stderr.String(), "opened the link in your browser")

	h.openErr = errors.New("no display")
	require.NoError(t, openLink(c, link, &stdout, linkRef{}))
	require.Equal(t, link+"\n", stdout.String(), "the link is printed when no browser opens")
	require.Contains(t, stderr.String(), "could not open a browser (no display)")

	stdout.Reset()
	require.Error(t, openLink(c, "-a Calculator", &stdout, linkRef{}))
	require.Len(t, h.opened, 2, "a page that is not a web URL never reaches the opener")
	require.Empty(t, stdout.String(), "a bad URL is not printed either")
}

func TestBrowserOpener(t *testing.T) {
	t.Parallel()
	for goos, want := range map[string]string{"darwin": "open", "linux": "xdg-open"} {
		got, ok := browserOpener(goos)
		require.True(t, ok, goos)
		require.Equal(t, want, got)
	}
	_, ok := browserOpener("windows")
	require.False(t, ok)
}

func TestConfiguredBase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hosted := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(hosted, []byte(`{"socketDir": "/s", "pagesUrl": "https://console.basaltvault.app",
		"agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c"}]}`), 0o600))
	plain := filepath.Join(dir, "plain.json")
	require.NoError(t, os.WriteFile(plain, []byte(`{"socketDir": "/s", "agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c"}]}`), 0o600))

	require.Equal(t, links.HostedConsole, configuredBase(nonRoot(t), "", "bot", hosted), "the config's pagesUrl")
	require.Equal(t, "http://localhost:9000", configuredBase(nonRoot(t), "http://localhost:9000", "bot", hosted), "--pages-url wins")
	require.Equal(t, links.DefaultLocal, configuredBase(nonRoot(t), "", "", hosted), "no --agent, no config: the local pages")
	require.Equal(t, links.DefaultLocal, configuredBase(nonRoot(t), "", "bot", plain), "the default until hosting")
	require.Equal(t, links.DefaultLocal, configuredBase(nonRoot(t), "", "bot", filepath.Join(dir, "missing.json")))
}

func TestEnginePathIsAbsolute(t *testing.T) {
	t.Parallel()
	require.Equal(t, "/home/me/basalt-m4/engine.json", enginePath("/home/me/basalt-m4/engine.json"))
	abs, err := filepath.Abs("engine.json")
	require.NoError(t, err)
	require.Equal(t, abs, enginePath("engine.json"), "a relative path works from any directory")
}

// nonRoot is a CLI that does not run as root.
func nonRoot(t *testing.T) *cliIO {
	t.Helper()
	return &cliIO{host: newFakeHost(t), getenv: func(string) string { return "" }}
}
