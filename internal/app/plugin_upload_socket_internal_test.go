//go:build unix

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost/engine"
)

// uploadPerson and uploadOther are two OS user ids other than the test's own:
// the person's, whose agent may upload, and a stranger's.
var uploadPerson, uploadOther = func() (uint32, uint32) {
	self := uint32(os.Getuid())
	var out []uint32
	for uid := uint32(2001); len(out) < 2; uid++ {
		if uid != self {
			out = append(out, uid)
		}
	}
	return out[0], out[1]
}()

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

func TestUploadThroughTheEnginesAgentSocket(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bu")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	store, err := pluginhost.New(filepath.Join(dir, "state"), time.Now)
	require.NoError(t, err)
	p := newPluginRequests(map[string]uint32{"bot": uploadPerson, "other": uploadOther}, []uint32{uploadPerson})
	p.SetKept(engine.OpenKeptPlugins(config.Config{}, "", store, nil, nil, slog.New(slog.DiscardHandler)))
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
	staged, err := store.Take(uploadPerson, id) // the configured agent's OS user owns it
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(staged.Dir, "share", "model.txt"))
	require.NoError(t, err)
	require.Equal(t, model, got, "every part arrived, in order")
	staged.Release()

	_, err = shim.NewPluginUploader(stranger.SocketPath)(context.Background(), src)
	require.Error(t, err, "another OS user's connection is refused")
	require.Zero(t, store.Open(), "nothing was written for it")
}
