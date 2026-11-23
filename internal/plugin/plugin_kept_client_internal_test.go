package plugin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// keptClient calls the engine-kept plugin methods in process, as the OS
// user uid with scope (nil: a person, who may name every agent).
type keptClient struct {
	s     *KeptPlugins
	uid   func() uint32
	scope Scope
}

func (c keptClient) PluginUploadBegin(ctx context.Context) (PluginUploadBeginResult, error) {
	return c.s.UploadBegin(ctx, c.uid())
}

func (c keptClient) PluginUploadPart(ctx context.Context, p PluginUploadPartParams) (PluginUploadPartResult, error) {
	return c.s.UploadPart(ctx, c.uid(), p)
}

func (c keptClient) PluginOpen(ctx context.Context, p PluginOpenParams) (PluginOpenResult, error) {
	return c.s.Open(ctx, c.uid(), c.scope, p)
}

func (c keptClient) PluginList(ctx context.Context) (PluginListResult, error) {
	return c.s.List(ctx, c.scope)
}

func (c keptClient) PluginApprove(ctx context.Context, p PluginApproveParams) (PluginApproveResult, error) {
	return c.s.Approve(ctx, p)
}

func (c keptClient) PluginDisable(ctx context.Context, p PluginEntryParams) (PluginEntryResult, error) {
	return c.s.Disable(ctx, c.scope, p)
}

func (c keptClient) PluginRemove(ctx context.Context, p PluginEntryParams) (PluginEntryResult, error) {
	return c.s.Remove(ctx, c.scope, p)
}

// PluginUpload begins an upload and sends files in parts of at most the
// engine's maxPartBytes, as basalt mcp does.
func (c keptClient) PluginUpload(ctx context.Context, files []UploadFile) (uuid.UUID, error) {
	begun, err := c.PluginUploadBegin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	part := begun.MaxPartBytes
	if part <= 0 {
		return uuid.Nil, errors.New("no part size")
	}
	for _, f := range files {
		if len(f.Data) == 0 {
			if _, err := c.PluginUploadPart(ctx, PluginUploadPartParams{UploadID: begun.UploadID, Path: f.Path}); err != nil {
				return uuid.Nil, err
			}
			continue
		}
		for off := 0; off < len(f.Data); off += part {
			chunk := f.Data[off:min(off+part, len(f.Data))]
			if _, err := c.PluginUploadPart(ctx, PluginUploadPartParams{
				UploadID: begun.UploadID, Path: f.Path, Offset: int64(off), Data: base64.RawURLEncoding.EncodeToString(chunk),
			}); err != nil {
				return uuid.Nil, err
			}
		}
	}
	return begun.UploadID, nil
}

// serveAgentSocket serves caller's upload methods of p on a Unix socket
// under dir, as the engine serves them on the agent's own socket, and
// returns its path.
func serveAgentSocket(t *testing.T, dir string, p *Requests, caller string, served func() error) string {
	t.Helper()
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "test"}).WithMethods(uploadMethods(p, caller, served))
	sock := filepath.Join(dir, caller+".sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(context.Background(), bufio.NewReader(conn), conn)
			}()
		}
	}()
	return sock
}

// uploadMethods is the plumbing of the engine's upload methods on an agent's
// socket, for the tests that send files through the shim. It maps only the
// refusals they look at; the app's own methods, and every code they answer
// with, are tested in the app (TestUploadMethodsAnswerWithTheirCodes).
func uploadMethods(p *Requests, caller string, served func() error) map[string]mcpserver.MethodFunc {
	if p == nil {
		return nil
	}
	fail := func(err error) *toolresult.ToolError {
		var te *toolresult.ToolError
		var r *PluginRefusedError
		switch {
		case errors.As(err, &te):
			return te
		case errors.As(err, &r):
			return &toolresult.ToolError{Code: "PLUGIN_REFUSED", Reason: r.Reason, Message: r.Message}
		}
		return &toolresult.ToolError{Code: guidance.CodeInternal, Message: err.Error()}
	}
	return map[string]mcpserver.MethodFunc{
		mcpserver.MethodPluginUploadBegin: func(ctx context.Context, _ json.RawMessage) (any, error) {
			out, err := p.UploadBegin(ctx, caller, served)
			if err != nil {
				return nil, fail(err)
			}
			return out, nil
		},
		mcpserver.MethodPluginUploadPart: func(ctx context.Context, raw json.RawMessage) (any, error) {
			out, err := p.UploadPart(ctx, caller, served, raw)
			if err != nil {
				return nil, fail(err)
			}
			return out, nil
		},
	}
}
