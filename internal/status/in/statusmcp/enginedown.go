package statusmcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"time"

	engine "github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/status"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
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
	Commands guidance.Commands
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
	// Host is what the status of an engine that is down reads from the
	// host.
	Host status.EngineHost
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
	stop, ok := d.Host.ReadLastStop(d.Config.StateDirFor(runtime.GOOS))
	if !ok {
		return ""
	}
	if _, holding := d.Host.StartHoldOffUntil(stop, d.ConfigPath, d.Now()); !holding {
		return ""
	}
	return status.EngineGaveUpMessage(d.Host, stop, d.ConfigPath, d.Now())
}

// Tools are the tools of every IMPLEMENTED contract, and status, each
// answering as above.
func (d EngineDown) Tools() []mcpserver.Tool {
	if d.Log == nil || d.Now == nil {
		panic("statusmcp: engine-down tools need a logger and a clock")
	}
	contracts := mcpcontract.MustLoad()
	out := make([]mcpserver.Tool, 0, len(contracts))
	for _, c := range contracts {
		if c.Status != mcpcontract.StatusImplemented && c.Name != guidance.ToolStatus {
			continue
		}
		call := d.unreachable(c.Name)
		if c.Name == guidance.ToolStatus {
			call = d.status
		}
		out = append(out, mcpserver.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: mcpserver.RefuseAdminCredential(c.Name, call)})
	}
	return out
}

func (d EngineDown) status(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, d.invalidArgument(err)
	}
	return status.EngineDownStatusAfterStart(d.Host, d.Name, d.Commands, d.Config, d.ConfigErr, buildinfo.Version, d.Now(), d.startFailure(), d.ConfigPath)
}

func (d EngineDown) unreachable(tool string) func(context.Context, json.RawMessage) (any, error) {
	return func(context.Context, json.RawMessage) (any, error) {
		if status.ConfigUnloadable(d.Config, d.ConfigErr) {
			return nil, d.configInvalid(tool)
		}
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
// configInvalid is ENGINE_UNREACHABLE for an engine.json that does not load:
// the load error, and steps that name no service or engine command.
func (d EngineDown) configInvalid(tool string) error {
	loadErr := d.ConfigErr.Error()
	te := &toolresult.ToolError{
		Code: guidance.CodeUnavailable, Reason: guidance.ReasonEngineUnreachable, ErrorID: uniqueid.New(),
		Message: "the basalt engine cannot start, so " + tool + " cannot run: engine.json cannot be loaded: " + loadErr,
	}
	d.Log.Error("engine config does not load", "tool", tool, "error_id", te.ErrorID)
	b := guidance.NewSteps()
	te.PersonMessage = guidance.ConfigInvalidSteps(b, d.Name)
	steps, err := b.Build()
	if err != nil {
		return err
	}
	te.NextSteps = steps
	return te
}

func (d EngineDown) unreachableError(tool, retry, message string) (*toolresult.ToolError, error) {
	te := &toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonEngineUnreachable, ErrorID: uniqueid.New(), Message: message}
	d.Log.Error("engine unreachable", "tool", tool, "error_id", te.ErrorID)
	b := guidance.NewSteps()
	te.PersonMessage = guidance.EngineUnreachableSteps(b, d.commands(), retry)
	steps, err := b.Build()
	if err != nil {
		return nil, err
	}
	te.NextSteps = steps
	return te, nil
}

// Abandoned is the tool error that answers a tools/call the engine took and
// never answered: UNAVAILABLE ENGINE_UNREACHABLE with its steps. The call
// may have run, so the agent checks status and never repeats it. It is nil
// when the error cannot be built; the caller then answers with
// engine.AbandonedMessage alone.
func (d EngineDown) Abandoned(tool string) *toolresult.ToolError {
	te, err := d.unreachableError(tool, "", engine.AbandonedMessage)
	if err == nil {
		return te
	}
	return nil
}

// commands are d's commands for the operatedBy of the config the shim
// read; PERSON when it read none.
func (d EngineDown) commands() guidance.Commands {
	if d.Config == nil {
		return d.Commands.OperatedBy(mcpcontract.OperatedByPerson)
	}
	return d.Commands.OperatedBy(d.Config.OperatedBy)
}

func (d EngineDown) invalidArgument(err error) *toolresult.ToolError {
	te := &toolresult.ToolError{Code: guidance.CodeInvalidArgument, Message: err.Error()}
	b := guidance.NewSteps()
	guidance.InvalidArgumentSteps(b, te, guidance.Failure{Tool: guidance.ToolStatus})
	te.NextSteps, _ = b.Build() // one fixed step: it cannot fail
	return te
}
