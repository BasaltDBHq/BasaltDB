package statusmcp

import (
	"context"
	"encoding/json"
	"io"
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

// Call is how tool answers while the engine is down, as above: status
// reports, every other tool is UNAVAILABLE. internal/app serves it for every
// IMPLEMENTED contract, and status, and wraps each once.
func (d EngineDown) Call(tool string) func(context.Context, json.RawMessage) (any, error) {
	if d.Log == nil || d.Now == nil {
		panic("statusmcp: engine-down tools need a logger and a clock")
	}
	if tool == guidance.ToolStatus {
		return d.status
	}
	return d.unreachable(tool)
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

// fallbackAgentName names the agent in commands when basalt mcp was given a
// socket whose name is not an agent name.
const fallbackAgentName = "agent"

// LoadEngineDown is what basalt mcp answers with while the engine is down,
// for agent name, with the config at configPath it could read as the
// agent's own user (the shim never runs as root): commands for manager, and
// host's reads of the engine's files.
func LoadEngineDown(name, configPath string, manager guidance.ServiceManager, host status.EngineHost, log *slog.Logger) (EngineDown, error) {
	var cfg *config.Config
	c, cfgErr := config.Load(configPath)
	if cfgErr == nil {
		cfg = &c
	}
	cmdName := name
	if !config.ValidAgentName(cmdName) {
		cmdName = fallbackAgentName
	}
	cmds, err := config.AgentCommands(cmdName, configPath, runtime.GOOS, manager)
	if err != nil {
		return EngineDown{}, err
	}
	if cfg != nil && !cfg.Service() {
		cmds = cmds.Foreground()
	}
	return EngineDown{Name: name, Commands: cmds, Config: cfg, ConfigErr: cfgErr, Log: log, Now: time.Now, ConfigPath: configPath, Host: host}, nil
}

// Server is what basalt mcp answers with itself while the engine is down:
// the engine-down tools, and the answer to a request the engine took but
// closed the connection without answering.
type Server struct {
	*mcpserver.Server
	down EngineDown
}

// NewServer serves tools, the engine-down tools of down that internal/app
// built from down.Call, as an agent's MCP server with instructions.
func NewServer(down EngineDown, instructions string, tools []mcpserver.Tool) Server {
	info := mcpserver.Info{Name: "basalt", Version: buildinfo.Version, Instructions: instructions}
	return Server{Server: mcpserver.NewServer(info, tools...), down: down}
}

// Abandoned answers a request the engine took and never answered
// (AnswerAbandoned).
func (s Server) Abandoned(_ context.Context, out io.Writer, line []byte) error {
	return s.down.AnswerAbandoned(out, line)
}

// AnswerAbandoned answers on out a request line the engine took and never
// answered (it closed the connection: it stopped, or it refused the peer),
// always with an error and never by running the call again: a tools/call
// gets UNAVAILABLE ENGINE_UNREACHABLE with its steps (Abandoned), any other
// request a JSON-RPC error. A notification gets nothing.
func (d EngineDown) AnswerAbandoned(out io.Writer, line []byte) error {
	req, ok := mcpserver.RequestOf(line)
	if !ok {
		return nil
	}
	if req.Method != "tools/call" {
		return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, engine.AbandonedMessage)
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.Params, &p) // a call without a name is still answered
	te := d.Abandoned(p.Name)
	if te == nil {
		return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, engine.AbandonedMessage)
	}
	return mcpserver.WriteToolError(out, req.ID, te)
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
