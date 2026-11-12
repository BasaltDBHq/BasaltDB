package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/pkg/uniqueid"
)

// EngineDown is what basalt mcp serves itself while the engine socket does
// not answer (CONTRACT.md, Next steps, Startup failures): the tool list from
// the embedded contracts, status, and UNAVAILABLE reason ENGINE_UNREACHABLE
// for every other call. It holds no credential and reaches no database.
type EngineDown struct {
	// Name is the agent's name.
	Name string
	// Commands are the agent's commands: the engine start among them.
	Commands Commands
	// Config is the engine config the shim could read; nil when it could
	// not (then operatedBy is PERSON).
	Config *config.Config
	Log    *slog.Logger
	Now    func() time.Time
}

// Tools are the tools of every IMPLEMENTED contract, and status, each
// answering as above.
func (d EngineDown) Tools() []mcp.Tool {
	if d.Log == nil || d.Now == nil {
		panic("agent: engine-down tools need a logger and a clock")
	}
	contracts := mcpcontract.MustLoad()
	out := make([]mcp.Tool, 0, len(contracts))
	for _, c := range contracts {
		if c.Status != mcpcontract.StatusImplemented && c.Name != toolStatus {
			continue
		}
		call := d.unreachable(c.Name)
		if c.Name == toolStatus {
			call = d.status
		}
		out = append(out, mcp.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: call})
	}
	return out
}

func (d EngineDown) status(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, d.invalidArgument(err)
	}
	return EngineDownStatus(d.Name, d.Commands, d.Config, buildinfo.Version, d.Now())
}

func (d EngineDown) unreachable(tool string) func(context.Context, json.RawMessage) (any, error) {
	return func(context.Context, json.RawMessage) (any, error) {
		te := &mcp.ToolError{
			Code: CodeUnavailable, Reason: reasonEngineUnreachable, ErrorID: uniqueid.New(),
			Message: "the basalt engine does not answer on this agent's socket, so " + tool + " cannot run; status still works",
		}
		d.Log.Error("engine unreachable", "tool", tool, "error_id", te.ErrorID)
		b := NewSteps()
		te.PersonMessage = engineUnreachableSteps(b, d.Commands)
		steps, err := b.Build()
		if err != nil {
			return nil, err
		}
		te.NextSteps = steps
		return nil, te
	}
}

func (d EngineDown) invalidArgument(err error) *mcp.ToolError {
	te := &mcp.ToolError{Code: CodeInvalidArgument, Message: err.Error()}
	b := NewSteps()
	invalidArgumentSteps(b, te, failure{tool: toolStatus})
	te.NextSteps, _ = b.Build() // one fixed step: it cannot fail
	return te
}
