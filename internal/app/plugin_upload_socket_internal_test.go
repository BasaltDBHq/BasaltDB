//go:build unix

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
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
	require.NoError(t, os.WriteFile(filepath.Join(dir, plugin.ManifestFile), []byte(manifest), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "acme-ner"), exe, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "share", "model.txt"), model, 0o644))
	return dir, model
}

func TestUploadThroughTheEnginesAgentSocket(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bu")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	store, err := plugin.NewPluginhost(filepath.Join(dir, "state"), time.Now)
	require.NoError(t, err)
	p := newPluginRequests(map[string]uint32{"bot": uploadPerson, "other": uploadOther}, []uint32{uploadPerson})
	p.SetKept(plugin.OpenKeptPlugins(config.Config{}, "", store, nil, nil, slog.New(slog.DiscardHandler), pluginPorts))
	served := func() error { return nil }
	mine := uint32(os.Getuid())
	bot := engine.Agent{
		Name: "bot", UID: mine, SocketPath: filepath.Join(dir, "bot.sock"),
		Server: mcpServer{mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "test"}).WithMethods(p.uploadMethods("bot", served))},
	}
	stranger := engine.Agent{
		Name: "other", UID: mine + 1, SocketPath: filepath.Join(dir, "other.sock"),
		Server: mcpServer{mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "test"}).WithMethods(p.uploadMethods("bot", served))},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- engine.New(slog.New(slog.DiscardHandler), mcpLines{}, []engine.Agent{bot, stranger}).Serve(ctx)
	}()
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
	_, err = relay.Write(append(mcpserver.HelloLine("test"), '\n'))
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

// The upload methods answer with a code and a reason the agent can act on:
// PLUGIN_REFUSED for a refusal of the tool or the engine, INVALID_ARGUMENT
// for a part that is not one, NOT_FOUND for an upload the engine does not
// hold.
func TestUploadMethodsAnswerWithTheirCodes(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bu")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	store, err := plugin.NewPluginhost(filepath.Join(dir, "state"), time.Now)
	require.NoError(t, err)
	p := newPluginRequests(map[string]uint32{"bot": uploadPerson, "other": uploadOther}, []uint32{uploadPerson})
	p.SetKept(plugin.OpenKeptPlugins(config.Config{}, "", store, nil, nil, slog.New(slog.DiscardHandler), pluginPorts))
	ok := func() error { return nil }
	part := func(raw string) json.RawMessage { return json.RawMessage(raw) }
	ctx := context.Background()

	call := func(caller, method string, served func() error, raw json.RawMessage) *toolresult.ToolError {
		t.Helper()
		_, err := p.uploadMethods(caller, served)[method](ctx, raw)
		var te *toolresult.ToolError
		require.ErrorAs(t, err, &te)
		return te
	}

	te := call("bot", mcpserver.MethodPluginUploadBegin, func() error {
		return &toolresult.ToolError{Code: "PLUGIN_REFUSED", Reason: agent.ReasonPluginAgentOperated, Message: "operated by an agent"}
	}, nil)
	require.Equal(t, "PLUGIN_REFUSED", te.Code)
	require.Equal(t, agent.ReasonPluginAgentOperated, te.Reason, "the tool's own refusal is passed on")

	te = call("other", mcpserver.MethodPluginUploadBegin, ok, nil)
	require.Equal(t, "PLUGIN_REFUSED", te.Code)
	require.Equal(t, agent.ReasonPluginAgentNotAllowed, te.Reason, "an OS user the engine does not let change plugins")

	te = call("bot", mcpserver.MethodPluginUploadPart, ok, part(`{"uploadId":"x"}`))
	require.Equal(t, "INVALID_ARGUMENT", te.Code)
	require.Equal(t, guidance.CodeInvalidArgument, te.Code)
	te = call("bot", mcpserver.MethodPluginUploadPart, ok, part(`{"uploadId":"`+uuid.NewString()+`","path":"a","offset":0,"data":"","extra":1}`))
	require.Equal(t, "INVALID_ARGUMENT", te.Code, "an unknown field is refused")

	te = call("bot", mcpserver.MethodPluginUploadPart, ok, part(`{"uploadId":"`+uuid.NewString()+`","path":"a","offset":0,"data":""}`))
	require.Equal(t, "NOT_FOUND", te.Code)
	require.Equal(t, guidance.CodeNotFound, te.Code)
}
