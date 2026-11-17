package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
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
		`"agents":[{"name":"bot","osUser":"u","credentialFile":"/etc/basalt/agents/bot.url"}]}`
}

func engineSays(state string, err error) func(context.Context) (person.PagesDTO, error) {
	return func(context.Context) (person.PagesDTO, error) {
		return person.PagesDTO{UpdateCheck: state}, err
	}
}

func noEngine(t *testing.T) func(context.Context) (person.PagesDTO, error) {
	return func(context.Context) (person.PagesDTO, error) {
		t.Error("the engine was asked although the config was read")
		return person.PagesDTO{}, errors.New("unexpected")
	}
}

func TestUpdateOffFollowsAReadableConfig(t *testing.T) {
	getenv := func(string) string { return "" }
	h := newFakeHost(t)
	writeUserConfig(t, h, configWith("OFF"), 0o600)
	require.True(t, updateOff(context.Background(), getenv, "linux", h, noEngine(t)))
	h = newFakeHost(t)
	writeUserConfig(t, h, configWith("ON"), 0o600)
	require.False(t, updateOff(context.Background(), getenv, "linux", h, noEngine(t)))
}

func TestUpdateOffWithNoConfigIsOn(t *testing.T) {
	h := newFakeHost(t)
	if _, err := os.Stat(config.DefaultPath("linux")); err == nil {
		t.Skip("a system engine.json exists on this machine")
	}
	require.False(t, updateOff(context.Background(), func(string) string { return "" }, "linux", h, noEngine(t)))
}

// In service mode engine.json is the engine's own (0600): an admin's OFF
// reaches the person's CLI through the engine, never through the file.
func TestUpdateOffFollowsTheEngineWhenTheConfigCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	getenv := func(string) string { return "" }
	h := newFakeHost(t)
	writeUserConfig(t, h, configWith("OFF"), 0)
	ctx := context.Background()
	require.True(t, updateOff(ctx, getenv, "linux", h, engineSays("OFF", nil)), "the engine says OFF")
	require.False(t, updateOff(ctx, getenv, "linux", h, engineSays("ON", nil)), "the engine says ON")
	require.True(t, updateOff(ctx, getenv, "linux", h, engineSays("", errors.New("down"))), "no engine answer, no request")
	require.True(t, updateOff(ctx, getenv, "linux", h, engineSays("", nil)), "an engine that does not say stays off")
}

func TestStatusUpdateIsTheStatusToolShape(t *testing.T) {
	if _, err := os.Stat(config.DefaultPath("linux")); err == nil {
		t.Skip("a system engine.json exists on this machine")
	}
	old := buildinfo.Version
	buildinfo.Version = "0.0.1"
	t.Cleanup(func() { buildinfo.Version = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v0.0.2","body":"Security: fixes a leak"}]`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ck := &updatecheck.Checker{Dir: dir, Current: "0.0.1", URL: srv.URL}
	require.NoError(t, ck.Refresh(context.Background()))

	newCLI := func(cacheDir string) *cliIO {
		return &cliIO{
			ctx: context.Background(), goos: "linux", host: newFakeHost(t),
			getenv: func(k string) string {
				if k == envCacheDir {
					return cacheDir
				}
				return ""
			},
			engine: engineAccess{personSocket: filepath.Join(t.TempDir(), "none.sock")},
		}
	}
	fromEngine := &agent.UpdateInfo{Current: "0.0.1", Latest: "0.0.3", URL: "u", Message: "WARNING: from the engine"}

	got := statusUpdate(newCLI(dir), fromEngine)
	require.NotNil(t, got)
	require.Equal(t, "0.0.2", got.Latest)
	require.True(t, got.Security)
	require.True(t, strings.HasPrefix(got.Message, "SECURITY UPDATE: "), got.Message)
	raw, err := json.Marshal(statusOut{StatusReport: agent.StatusReport{Update: got}})
	require.NoError(t, err)
	require.Contains(t, string(raw), `"update":{"current":"0.0.1","latest":"0.0.2","security":true,"url":`)
	require.Contains(t, string(raw), `"message":"SECURITY UPDATE:`)

	// An empty cache falls back to the engine's own notice.
	require.Equal(t, fromEngine, statusUpdate(newCLI(t.TempDir()), fromEngine))
	require.Nil(t, statusUpdate(newCLI(t.TempDir()), nil))
}
