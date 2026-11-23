package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/shim"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// uploadSource writes a plugin folder basalt mcp can read.
func uploadSource(t *testing.T) string {
	t.Helper()
	files, exec := source("1.0.0")
	dir := t.TempDir()
	for _, f := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, f.Path)), 0o755))
		mode := os.FileMode(0o644)
		for _, e := range exec {
			if e == f.Path {
				mode = 0o755
			}
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, f.Path), f.Data, mode))
	}
	return dir
}

// uploadRequests is a Requests over a real upload store, bot running
// as keptPerson (admitted) and other as keptOtherUID (not).
func uploadRequests(t *testing.T) (*Requests, *pluginhost.Store, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "bu")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	store, err := pluginhost.New(filepath.Join(dir, "state"), time.Now)
	require.NoError(t, err)
	p := &Requests{uids: map[string]uint32{"bot": keptPerson, "other": keptOtherUID}, admitted: []uint32{keptPerson}}
	p.kept.Store(&KeptPlugins{ports: testPorts, store: store})
	return p, store, dir
}

// The upload goes over a second connection to the agent's own socket, and
// belongs to the agent's OS user.
func TestUploadGoesOverTheAgentSocket(t *testing.T) {
	t.Parallel()
	p, store, dir := uploadRequests(t)
	sock := serveAgentSocket(t, dir, p, "bot", func() error { return nil })
	up, err := shim.NewPluginUploader(sock)(context.Background(), uploadSource(t))
	require.NoError(t, err)
	require.Equal(t, "acme-ner", up.Name)
	require.Equal(t, 1, store.Open())
}

// An agent the tool refuses is refused the upload before anything is
// written: it cannot hold one of the engine's open uploads.
func TestUploadRefusedBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()
	p, store, dir := uploadRequests(t)
	for _, tc := range []struct {
		name, caller, reason string
		served               func() error
	}{
		{"not the person's OS user", "other", agent.ReasonPluginAgentNotAllowed, func() error { return nil }},
		{"refused by the tool", "bot", agent.ReasonPluginAgentOperated, func() error {
			return &toolresult.ToolError{Code: "PLUGIN_REFUSED", Reason: agent.ReasonPluginAgentOperated, Message: "operated by an agent"}
		}},
	} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, tc.reason), 0o700))
		sock := serveAgentSocket(t, filepath.Join(dir, tc.reason), p, tc.caller, tc.served)
		_, err := shim.NewPluginUploader(sock)(context.Background(), uploadSource(t))
		var te *toolresult.ToolError
		require.True(t, errors.As(err, &te), "%s: %v", tc.name, err)
		require.Equal(t, "PLUGIN_REFUSED", te.Code, tc.name)
		require.Equal(t, tc.reason, te.Reason, tc.name)
		require.Zero(t, store.Open(), "%s: nothing was written", tc.name)
	}
}

// An engine that does not serve the methods answers method not found: the
// call goes on without an upload, and the engine says why.
func TestUploadToAnEngineWithoutTheMethods(t *testing.T) {
	t.Parallel()
	var p *Requests
	dir, err := os.MkdirTemp("", "bn") // short: a socket path is at most 104 bytes
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := serveAgentSocket(t, dir, p, "bot", func() error { return nil })
	_, err = shim.NewPluginUploader(sock)(context.Background(), uploadSource(t))
	require.ErrorIs(t, err, shim.ErrNoUploads)
	_, err = shim.NewPluginUploader(filepath.Join(dir, "gone.sock"))(context.Background(), uploadSource(t))
	require.ErrorIs(t, err, shim.ErrNoUploads, "no engine on the socket")
}

// bigSource is a plugin folder whose model file takes several parts.
