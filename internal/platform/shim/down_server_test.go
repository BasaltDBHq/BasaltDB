package shim

import (
	"context"
	"encoding/json"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// downServer is the fallback of basalt mcp while the engine is down, as
// internal/app builds it: the engine-down tools and the answer to a request
// the engine took and never answered. The package's own tests cannot import
// internal/app (it imports this package), so they build it here.
type downServer struct {
	*mcpserver.Server
	down agent.EngineDown
}

func newDownServer(down agent.EngineDown) downServer {
	info := mcpserver.Info{Name: "basalt", Version: "test"}
	return downServer{Server: mcpserver.NewServer(info, mcpserver.ToolsFrom(down.Tools(), nil)...), down: down}
}

func (s downServer) Abandoned(_ context.Context, out io.Writer, line []byte) error {
	req, ok := mcpserver.RequestOf(line)
	if !ok {
		return nil
	}
	if req.Method != "tools/call" {
		return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, agent.AbandonedMessage)
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.Params, &p)
	te := s.down.Abandoned(p.Name)
	if te == nil {
		return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, agent.AbandonedMessage)
	}
	return mcpserver.WriteToolError(out, req.ID, te)
}
