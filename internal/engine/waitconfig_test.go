package engine_test

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

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// adminURL is an admin connection string with a password in it; no
// answer may carry any part of it.
const adminURL = "postgres://admin" + ":" + "secret@db/x"

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
		return resp.StatusCode == http.StatusOK
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
	require.NotContains(t, string(raw), "secret", "nothing of a request is answered back")
	return resp.StatusCode, body
}

func TestWaitForConfigServesOnlyTheSetupPageThenReturns(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	configPath := filepath.Join(t.TempDir(), "engine.json")
	done := make(chan error, 1)
	go func() {
		done <- engine.WaitForConfig(context.Background(), addr, configPath, slog.New(slog.DiscardHandler))
	}()
	waitUp(t, addr)

	origin := "http://" + addr
	code, body := do(t, http.MethodGet, origin+"/setup/", "", "")
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, "UNAVAILABLE", body["code"], "the setup routes are placeholders until the page ships")
	code, body = do(t, http.MethodPost, origin+"/api/v1/setup/check", "", origin)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, "UNAVAILABLE", body["code"])
	code, _ = do(t, http.MethodPost, origin+"/api/v1/setup/run", "", origin)
	require.Equal(t, http.StatusServiceUnavailable, code)
	code, body = do(t, http.MethodGet, origin+"/api/v1/approvals/x", "", "")
	require.Equal(t, http.StatusNotFound, code, "no other route")
	require.Equal(t, "NOT_FOUND", body["code"])

	code, _ = do(t, http.MethodGet, origin+"/healthz", "evil.example", "")
	require.NotEqual(t, http.StatusOK, code, "a foreign Host is refused")
	code, _ = do(t, http.MethodPost, origin+"/api/v1/setup/check", "", "https://evil.example")
	require.Equal(t, http.StatusForbidden, code, "a foreign Origin is refused")

	select {
	case err := <-done:
		t.Fatalf("returned before the config exists: %v", err)
	default:
	}
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the engine did not see its config")
	}
	// The port is free again for the engine's own pages.
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, ln.Close())
}

func TestWaitForConfigNamesATakenPort(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	err = engine.WaitForConfig(context.Background(), ln.Addr().String(), filepath.Join(t.TempDir(), "engine.json"), slog.New(slog.DiscardHandler))
	require.ErrorContains(t, err, "serves its setup page on "+ln.Addr().String()+", but another process holds it")
	require.ErrorContains(t, err, "lsof -nP -iTCP:"+port+" -sTCP:LISTEN")
}

func TestWaitForConfigStopsWithItsContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() {
		done <- engine.WaitForConfig(ctx, addr, filepath.Join(t.TempDir(), "engine.json"), slog.New(slog.DiscardHandler))
	}()
	waitUp(t, addr)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop")
	}
}
