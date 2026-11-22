package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/shim"
	"github.com/basaltdbhq/basaltdb/internal/service/person"
)

// keptClient calls the engine-kept plugin methods in process, as the OS
// user uid with scope (nil: a person, who may name every agent).
type keptClient struct {
	s     *keptPlugins
	uid   func() uint32
	scope person.Scope
}

func (c keptClient) PluginUploadBegin(ctx context.Context) (person.PluginUploadBeginResult, error) {
	return c.s.UploadBegin(ctx, c.uid())
}

func (c keptClient) PluginUploadPart(ctx context.Context, p person.PluginUploadPartParams) (person.PluginUploadPartResult, error) {
	return c.s.UploadPart(ctx, c.uid(), p)
}

func (c keptClient) PluginOpen(ctx context.Context, p person.PluginOpenParams) (person.PluginOpenResult, error) {
	return c.s.Open(ctx, c.uid(), c.scope, p)
}

func (c keptClient) PluginList(ctx context.Context) (person.PluginListResult, error) {
	return c.s.List(ctx, c.scope)
}

func (c keptClient) PluginApprove(ctx context.Context, p person.PluginApproveParams) (person.PluginApproveResult, error) {
	return c.s.Approve(ctx, p)
}

func (c keptClient) PluginDisable(ctx context.Context, p person.PluginEntryParams) (person.PluginEntryResult, error) {
	return c.s.Disable(ctx, c.scope, p)
}

func (c keptClient) PluginRemove(ctx context.Context, p person.PluginEntryParams) (person.PluginEntryResult, error) {
	return c.s.Remove(ctx, c.scope, p)
}

// PluginUpload begins an upload and sends files in parts of at most the
// engine's maxPartBytes, as basalt mcp does.
func (c keptClient) PluginUpload(ctx context.Context, files []shim.PluginFile) (uuid.UUID, error) {
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
			if _, err := c.PluginUploadPart(ctx, person.PluginUploadPartParams{UploadID: begun.UploadID, Path: f.Path}); err != nil {
				return uuid.Nil, err
			}
			continue
		}
		for off := 0; off < len(f.Data); off += part {
			chunk := f.Data[off:min(off+part, len(f.Data))]
			if _, err := c.PluginUploadPart(ctx, person.PluginUploadPartParams{
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
func serveAgentSocket(t *testing.T, dir string, p *pluginRequests, caller string, served func() error) string {
	t.Helper()
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}).WithMethods(p.uploadMethods(caller, served))
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
