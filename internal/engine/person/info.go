package person

import (
	"context"
	"encoding/json"
	"fmt"
)

// STATUS and TARGET (CONTRACT.md, The person socket): what basalt status and
// basalt upgrade ask the engine in service mode besides the ledger. Neither
// goes through the guard check, so both answer while the guard is missing
// or outdated, which is when the person needs them.

// AgentInfo answers STATUS and TARGET for one agent.
type AgentInfo struct {
	// Status is the status tool's result for the agent, as JSON.
	Status func(ctx context.Context) (json.RawMessage, error)
	// Target is the database the agent's credential connects to.
	Target TargetDTO
}

// EngineDTO is the running engine as STATUS reports it.
type EngineDTO struct {
	PID    int    `json:"pid"`
	OSUser string `json:"osUser"`
}

// StatusDTO is STATUS's result: the status tool's result and where the
// engine runs. Never the credential, its file name or the config's contents.
type StatusDTO struct {
	Status    json.RawMessage `json:"status"`
	Engine    EngineDTO       `json:"engine"`
	SocketDir string          `json:"socketDir"`
	StateDir  string          `json:"stateDir"`
}

// TargetDTO is TARGET's result: the host, port and database the agent's
// credential connects to, and the Supabase project ref when it names one.
// Nothing secret: no user, no password, no other parameter.
type TargetDTO struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	SupabaseRef string `json:"supabaseRef,omitempty"`
}

// EngineInfo is what STATUS reports about the engine itself.
type EngineInfo struct {
	Engine              EngineDTO
	SocketDir, StateDir string
}

// answerInfo answers STATUS or TARGET for the request's agent.
func (s *Server) answerInfo(ctx context.Context, req Request) Response {
	if err := decodeStrict(req.Params, &emptyParams{}); err != nil {
		return Response{Error: invalid(err)}
	}
	info, ok := s.info[req.Agent]
	if !ok {
		return Response{Error: &Error{Code: CodeUnknownAgent, Message: fmt.Sprintf("the engine serves no agent %q", req.Agent)}}
	}
	if req.Method == MethodTarget {
		return result(info.Target, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	raw, err := info.Status(ctx)
	if err != nil {
		s.log.Error("person socket: status failed", "agent", req.Agent, "err", err)
		return Response{Error: &Error{Code: CodeInternal, Message: "the engine could not build the status; see the engine log"}}
	}
	return result(StatusDTO{Status: raw, Engine: s.engine.Engine, SocketDir: s.engine.SocketDir, StateDir: s.engine.StateDir}, nil)
}

// Status asks STATUS for agent.
func (c Client) Status(ctx context.Context, agent string) (StatusDTO, error) {
	var out StatusDTO
	err := c.call(ctx, agent, MethodStatus, emptyParams{}, &out)
	return out, err
}

// Target asks TARGET for agent.
func (c Client) Target(ctx context.Context, agent string) (TargetDTO, error) {
	var out TargetDTO
	err := c.call(ctx, agent, MethodTarget, emptyParams{}, &out)
	return out, err
}
