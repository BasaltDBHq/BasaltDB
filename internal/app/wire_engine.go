package app

import (
	"context"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// mcpServer is an agent's MCP server as the engine serves it.
type mcpServer struct{ *mcpserver.Server }

func (s mcpServer) ServeGated(ctx context.Context, in io.Reader, out io.Writer, gate engine.Gate) error {
	return s.Server.ServeGated(ctx, in, out, gate)
}

// mcpLines writes the engine's own lines in the MCP wire format.
type mcpLines struct{}

func (mcpLines) WritePeerRefused(w io.Writer, message string) error {
	return mcpserver.WritePeerRefused(w, message)
}
