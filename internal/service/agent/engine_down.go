package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"runtime"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/app/laststop"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
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
	// ConfigErr is why Config is nil when the config was read and refused.
	ConfigErr error
	Log       *slog.Logger
	Now       func() time.Time
	// StartFailure, when set, is why basalt mcp could not start the engine
	// on its last try ("" when it did not try or it worked): shown in status
	// as ENGINE_START_FAILED and in the answer to every other call.
	StartFailure func() string
	// ConfigPath is the engine.json path, used to end the start hold-off
	// when that file has changed since the supervisor gave up.
	ConfigPath string
}

func (d EngineDown) startFailure() string {
	if d.StartFailure == nil {
		return ""
	}
	return d.StartFailure()
}

// gaveUpMessage is the ENGINE_GAVE_UP sentence during a start hold-off, or
// "" when the hold-off does not apply.
func (d EngineDown) gaveUpMessage() string {
	if d.Config == nil {
		return ""
	}
	stop, ok := ReadLastStop(d.Config.StateDirFor(runtime.GOOS))
	if !ok {
		return ""
	}
	if _, holding := laststop.StartHoldOffUntil(lastStopRecord(stop), d.ConfigPath, d.Now()); !holding {
		return ""
	}
	return engineGaveUpMessage(stop, d.ConfigPath, d.Now())
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
		out = append(out, mcp.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: refuseAdminCredential(c.Name, call)})
	}
	return out
}

func (d EngineDown) status(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, d.invalidArgument(err)
	}
	return EngineDownStatusAfterStart(d.Name, d.Commands, d.Config, d.ConfigErr, buildinfo.Version, d.Now(), d.startFailure(), d.ConfigPath)
}

func (d EngineDown) unreachable(tool string) func(context.Context, json.RawMessage) (any, error) {
	return func(context.Context, json.RawMessage) (any, error) {
		message := "the basalt engine does not answer on this agent's socket, so " + tool + " cannot run; status still works"
		if f := d.startFailure(); f != "" {
			message += ". " + f
		} else if m := d.gaveUpMessage(); m != "" {
			message += ". " + m
		}
		te, err := d.unreachableError(tool, tool, message)
		if err != nil {
			return nil, err
		}
		return nil, te
	}
}

// unreachableError is UNAVAILABLE ENGINE_UNREACHABLE for a call of tool,
// logged under its error id.
// retry is the tool an agent-operated engine's agent calls again once it
// started the engine; "" calls status.
func (d EngineDown) unreachableError(tool, retry, message string) (*mcp.ToolError, error) {
	te := &mcp.ToolError{Code: CodeUnavailable, Reason: reasonEngineUnreachable, ErrorID: uniqueid.New(), Message: message}
	d.Log.Error("engine unreachable", "tool", tool, "error_id", te.ErrorID)
	b := NewSteps()
	te.PersonMessage = engineUnreachableSteps(b, d.commands(), retry)
	steps, err := b.Build()
	if err != nil {
		return nil, err
	}
	te.NextSteps = steps
	return te, nil
}

// EngineDownServer is what basalt mcp answers with itself: the engine-down
// tools, and the answer to a request the engine took but closed the
// connection without answering.
type EngineDownServer struct {
	*mcp.Server
	down EngineDown
}

// Server is the engine-down tools served under info.
func (d EngineDown) Server(info mcp.Info) EngineDownServer {
	return EngineDownServer{Server: mcp.NewServer(info, d.Tools()...), down: d}
}

// Abandoned answers a request the engine took and never answered (it
// closed the connection: it stopped, or it refused the peer), always with
// an error and never by running the call again: a tools/call gets UNAVAILABLE
// ENGINE_UNREACHABLE with its steps, any other request a JSON-RPC error. A
// notification gets nothing.
func (s EngineDownServer) Abandoned(_ context.Context, out io.Writer, line []byte) error {
	req, ok := mcp.RequestOf(line)
	if !ok {
		return nil
	}
	const message = "the basalt engine closed the connection before answering, so the call may or may not have run; call status, and read before you write again"
	if req.Method != "tools/call" {
		return mcp.WriteError(out, req.ID, mcp.ErrCodeServer, message)
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.Params, &p) // a call without a name is still answered
	// The call may have run: the agent checks status, never repeats it.
	te, err := s.down.unreachableError(p.Name, "", message)
	if err != nil {
		return mcp.WriteError(out, req.ID, mcp.ErrCodeServer, message)
	}
	return mcp.WriteToolError(out, req.ID, te)
}

// commands are d's commands for the operatedBy of the config the shim
// read; PERSON when it read none.
func (d EngineDown) commands() Commands {
	if d.Config == nil {
		return d.Commands.OperatedBy(mcpcontract.OperatedByPerson)
	}
	return d.Commands.OperatedBy(d.Config.OperatedBy)
}

func (d EngineDown) invalidArgument(err error) *mcp.ToolError {
	te := &mcp.ToolError{Code: CodeInvalidArgument, Message: err.Error()}
	b := NewSteps()
	invalidArgumentSteps(b, te, failure{tool: toolStatus})
	te.NextSteps, _ = b.Build() // one fixed step: it cannot fail
	return te
}
