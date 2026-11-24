package app_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
)

// adminURL is an admin connection string with a password in it; no
// answer may carry any part of it.
// leakMarker is the admin string's password: a word no page contains, so
// finding it in an answer means the request was echoed.
const leakMarker = "zq7leakmarker"

const adminURL = "postgres://admin" + ":" + leakMarker + "@db/x"

// pageOrigin is the setup page's origin for a test listener at addr.
func pageOrigin(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return "http://localhost:" + port
}

func waitOptions(addr, configPath string) app.WaitOptions {
	return app.WaitOptions{Addr: addr, Origin: pageOrigin(addr), ConfigPath: configPath, Log: slog.New(slog.DiscardHandler)}
}

// freeAddr is a loopback address nothing listens on, right now.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func waitUp(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		// The engine says its build, so basalt init can tell an older one.
		return resp.StatusCode == http.StatusOK && resp.Header.Get(pageserver.BuildHeader) == buildinfo.Version
	}, 5*time.Second, 20*time.Millisecond)
}

func do(t *testing.T, method, url, host, origin string) (int, map[string]string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(`{"databaseUrl":"`+adminURL+`"}`))
	require.NoError(t, err)
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body map[string]string
	_ = json.Unmarshal(raw, &body)
	require.NotContains(t, string(raw), leakMarker, "nothing of a request is answered back")
	return resp.StatusCode, body
}

func TestWaitForConfigServesOnlyTheSetupPageThenReturns(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	configPath := filepath.Join(t.TempDir(), "engine.json")
	type waited struct {
		ln  net.Listener
		err error
	}
	done := make(chan waited, 1)
	go func() {
		ln, err := app.WaitForConfig(context.Background(), waitOptions(addr, configPath))
		done <- waited{ln, err}
	}()
	waitUp(t, addr)

	base := "http://" + addr
	page := pageOrigin(addr)
	code, _ := do(t, http.MethodGet, base+"/setup/", "", "")
	require.Equal(t, http.StatusOK, code, "the setup page")
	code, _ = do(t, http.MethodGet, base+"/lib/setup.js", "", "")
	require.Equal(t, http.StatusOK, code, "and the files it loads")
	code, body := do(t, http.MethodPost, base+"/api/v1/setup/check", "", page)
	require.Equal(t, http.StatusBadRequest, code, "the setup routes run the job: this body names none")
	require.Equal(t, "INVALID_ARGUMENT", body["code"])
	code, _ = do(t, http.MethodPost, base+"/api/v1/setup/run", "", page)
	require.Equal(t, http.StatusBadRequest, code)
	code, body = do(t, http.MethodGet, base+"/api/v1/approvals/x", "", "")
	require.Equal(t, http.StatusNotFound, code, "no other route")
	require.Equal(t, "NOT_FOUND", body["code"])

	code, _ = do(t, http.MethodGet, base+"/healthz", "evil.example", "")
	require.Equal(t, http.StatusBadRequest, code, "a foreign Host is refused")
	code, _ = do(t, http.MethodPost, base+"/api/v1/setup/check", "evil.example", page)
	require.Equal(t, http.StatusBadRequest, code, "a foreign Host is refused on the setup routes too, before the body")
	for _, foreign := range []string{"https://evil.example", base, ""} {
		code, _ = do(t, http.MethodPost, base+"/api/v1/setup/check", "", foreign)
		require.Equal(t, http.StatusForbidden, code, "only the page origin, exactly: %q", foreign)
	}

	select {
	case w := <-done:
		t.Fatalf("returned before the config exists: %v", w.err)
	default:
	}
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))
	var w waited
	select {
	case w = <-done:
		require.NoError(t, w.err)
	case <-time.After(5 * time.Second):
		t.Fatal("the engine did not see its config")
	}
	// The listener is handed on still bound: no other process can take the
	// port between the setup page and the engine's own pages.
	require.Equal(t, addr, w.ln.Addr().String())
	_, err := net.Listen("tcp", addr)
	require.Error(t, err, "the port is still held")
	// And it still accepts: the engine serves its pages on it.
	hs := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte("pages")) }), ReadHeaderTimeout: time.Second}
	go func() { _ = hs.Serve(w.ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	resp, err := http.Get("http://" + addr + "/")
	require.NoError(t, err)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "pages", string(raw))
}

func TestWaitForConfigNamesATakenPort(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	_, err = app.WaitForConfig(context.Background(), waitOptions(ln.Addr().String(), filepath.Join(t.TempDir(), "engine.json")))
	require.ErrorContains(t, err, "serves its setup page on "+ln.Addr().String()+", but another process holds it")
	require.ErrorContains(t, err, "lsof -nP -iTCP:"+port+" -sTCP:LISTEN")
}

func TestWaitForConfigStopsWithItsContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() {
		_, err := app.WaitForConfig(ctx, waitOptions(addr, filepath.Join(t.TempDir(), "engine.json")))
		done <- err
	}()
	waitUp(t, addr)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop")
	}
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err, "a stopped wait frees its port")
	require.NoError(t, ln.Close())
}
