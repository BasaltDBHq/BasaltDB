package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/shim"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/service/keptplugins"
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

// uploadRequests is a pluginRequests over a real upload store, bot running
// as keptPerson (admitted) and other as keptOtherUID (not).
func uploadRequests(t *testing.T) (*pluginRequests, *keptplugins.Store, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "bu")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	store, err := keptplugins.New(filepath.Join(dir, "state"), time.Now)
	require.NoError(t, err)
	p := &pluginRequests{uids: map[string]uint32{"bot": keptPerson, "other": keptOtherUID}, admitted: []uint32{keptPerson}}
	p.kept.Store(&keptPlugins{store: store})
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
			return &mcp.ToolError{Code: "PLUGIN_REFUSED", Reason: agent.ReasonPluginAgentOperated, Message: "operated by an agent"}
		}},
	} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, tc.reason), 0o700))
		sock := serveAgentSocket(t, filepath.Join(dir, tc.reason), p, tc.caller, tc.served)
		_, err := shim.NewPluginUploader(sock)(context.Background(), uploadSource(t))
		var te *mcp.ToolError
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
	var p *pluginRequests
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
func bigSource(t *testing.T, size int) (string, []byte) {
	t.Helper()
	exe := []byte("#!/bin/sh\nexit 0\n")
	model := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": "1.0.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner" } },
  "files": { "bin/acme-ner": "sha256:%x", "share/model.txt": "sha256:%x" },
  "network": { "egress": [] }
}
`, sha256.Sum256(exe), sha256.Sum256(model))
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "share"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, pluginhost.ManifestFile), []byte(manifest), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "acme-ner"), exe, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "share", "model.txt"), model, 0o644))
	return dir, model
}

// Through the engine's own agent listener: the upload's second connection
// is served while the relay's stays open, a file of several parts arrives
// whole, and a peer of another OS user is refused before anything is
// written.
func TestUploadThroughTheEnginesAgentSocket(t *testing.T) {
	t.Parallel()
	p, store, dir := uploadRequests(t)
	served := func() error { return nil }
	mine := uint32(os.Getuid())
	bot := Agent{
		Name: "bot", UID: mine, SocketPath: filepath.Join(dir, "bot.sock"),
		Server: mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}).WithMethods(p.uploadMethods("bot", served)),
	}
	stranger := Agent{
		Name: "other", UID: mine + 1, SocketPath: filepath.Join(dir, "other.sock"),
		Server: mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}).WithMethods(p.uploadMethods("bot", served)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(slog.New(slog.DiscardHandler), []Agent{bot, stranger}).Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", bot.SocketPath)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	// The relay's connection, open for the whole upload.
	relay, err := net.Dial("unix", bot.SocketPath)
	require.NoError(t, err)
	defer relay.Close()
	_, err = relay.Write(append(mcp.HelloLine("test"), '\n'))
	require.NoError(t, err)
	hello, err := bufio.NewReader(relay).ReadBytes('\n')
	require.NoError(t, err)
	require.Contains(t, string(hello), `"result"`)

	src, model := bigSource(t, 200<<10)
	up, err := shim.NewPluginUploader(bot.SocketPath)(context.Background(), src)
	require.NoError(t, err)
	require.Equal(t, 1, store.Open())
	id, err := uuid.Parse(up.UploadID)
	require.NoError(t, err)
	staged, err := store.Take(keptPerson, id) // the configured agent's OS user owns it
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(staged.Dir, "share", "model.txt"))
	require.NoError(t, err)
	require.Equal(t, model, got, "every part arrived, in order")
	staged.Release()

	_, err = shim.NewPluginUploader(stranger.SocketPath)(context.Background(), src)
	require.Error(t, err, "another OS user's connection is refused")
	require.Zero(t, store.Open(), "nothing was written for it")
}
