package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// statusThroughShim asks the engine-down server for status.
func statusThroughShim(t *testing.T, configPath string) map[string]any {
	t.Helper()
	srv, err := engineDownServer("bot", configPath, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, srv.ServeLine(context.Background(), &out,
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}}`)))
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(out.String()), &resp), out.String())
	require.False(t, resp.Result.IsError, out.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &body))
	return body
}

func TestMCPStatusReadsASameUserConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// The config refuses a socket path too long to bind (103 bytes), and the
	// test temp dir can be long (a deep checkout, a long TMPDIR), so the
	// sockets live in a short directory of their own.
	sockDir, err := os.MkdirTemp("/tmp", "bm")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	cred := filepath.Join(dir, "agents", "bot.url")
	path := filepath.Join(dir, "engine.json")
	cfg := `{"socketDir": "` + sockDir + `", "operatedBy": "AGENT", "pagesUrl": "https://portal.basaltvault.app", "mode": "SAME_USER",
		"agents": [{"name": "bot", "osUser": "bot", "store": {"kind": "POSTGRES", "credentialFile": "` + cred + `"}, "initArgs": ["--agent=bot"]}]}`
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))

	_, err = config.Load(path)
	require.NoError(t, err)
	body := statusThroughShim(t, path)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(raw), cred, "status never names the credential file")
	require.Equal(t, "AGENT", body["operatedBy"])
	require.Equal(t, "GUARD_ONLY", body["enforcement"])
	step := body["problems"].([]any)[0].(map[string]any)["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, "basalt engine --config "+path, step["command"], "a same-user engine starts in the foreground")
}

func TestMCPStatusWithoutAConfig(t *testing.T) {
	t.Parallel()
	body := statusThroughShim(t, filepath.Join(t.TempDir(), "none.json"))
	require.Equal(t, "PERSON", body["operatedBy"])
	require.Equal(t, "GUARD_ONLY", body["enforcement"], "the shim cannot tell the agent cannot read the credential")
	require.Equal(t, false, body["ready"])
}

func TestShimAgentNamesTheSocket(t *testing.T) {
	t.Parallel()
	require.Equal(t, "bot", engine.ShimAgent("bot", "/x/other.sock"))
	require.Equal(t, "other", engine.ShimAgent("", "/x/other.sock"))
}
