package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/revert"
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
	link := "http://localhost:8787/approve/#1.abc"
	h := newFakeHost(t)
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
	c.host = h

	openLink(c, link, &stdout)
	require.Equal(t, []string{link}, h.opened)
	require.Empty(t, stdout.String(), "an opened link is not printed")
	require.Contains(t, stderr.String(), "opened the link in your browser")

	h.openErr = errors.New("no display")
	openLink(c, link, &stdout)
	require.Equal(t, link+"\n", stdout.String(), "the link is printed when no browser opens")
	require.Contains(t, stderr.String(), "could not open a browser (no display)")

	stdout.Reset()
	openLink(c, "-a Calculator", &stdout)
	require.Len(t, h.opened, 2, "a page that is not a web URL never reaches the opener")
	require.Equal(t, "-a Calculator\n", stdout.String())
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

func TestConfiguredPage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	withPage := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(withPage, []byte(`{"socketDir": "/s", "approvalPage": "http://localhost:8787/approve/",
		"agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c"}]}`), 0o600))
	without := filepath.Join(dir, "plain.json")
	require.NoError(t, os.WriteFile(without, []byte(`{"socketDir": "/s", "agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c"}]}`), 0o600))

	require.Equal(t, "http://localhost:8787/approve/", configuredPage("", approval.PageURL, "bot", withPage, ""))
	require.Equal(t, "http://localhost:8787/revert/", configuredPage("", revert.PageURL, "bot", withPage, revertSibling))
	require.Equal(t, "https://x.test/a/", configuredPage("https://x.test/a/", approval.PageURL, "bot", withPage, ""), "--page wins")
	require.Equal(t, approval.PageURL, configuredPage("", approval.PageURL, "", withPage, ""), "no --agent, no config")
	require.Equal(t, revert.PageURL, configuredPage("", revert.PageURL, "bot", without, revertSibling))
	require.Equal(t, revert.PageURL, configuredPage("", revert.PageURL, "bot", filepath.Join(dir, "missing.json"), revertSibling))
}

func TestConfigArg(t *testing.T) {
	t.Parallel()
	require.Empty(t, configArg(config.DefaultPath(runtime.GOOS)))
	require.Equal(t, "--config /home/me/basalt-m4/engine.json", configArg("/home/me/basalt-m4/engine.json"))
	require.Equal(t, "--config '/Users/me/My Basalt/engine.json'", configArg("/Users/me/My Basalt/engine.json"))
	abs, err := filepath.Abs("engine.json")
	require.NoError(t, err)
	require.Equal(t, "--config "+shellQuote(abs), configArg("engine.json"), "a relative path works from any directory")
}
