package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// A connect-only setup on the engine (CONTRACT.md, Setup from your laptop,
// The engine and a connect-only code). Until the person confirms the
// database the engine collected, the agent is served by ConnectOnly: it
// holds no credential and no connection, status and confirm_database
// answer, and every other tool is refused.

const (
	answerNo = "NO"
)

// --- the result of confirm_database ---

// --- the served agent ---

// ConnectOnly serves an agent whose connect-only setup waits for its
// database: status, confirm_database, and every other tool refused.
type ConnectOnly struct {
	Name       string
	Commands   guidance.Commands
	OperatedBy string
	SameUser   bool
	// StartedBy is why this engine started (hand, mcp or crash).
	StartedBy string
	PagesBase string
	// PagesOrigin is the origin of the local pages when served.
	PagesOrigin   string
	ConnectBudget int
	Vault         VaultReporter
	Handoff       handoff.Handoff
	Log           *slog.Logger
	Now           func() time.Time
	// Errors maps a failure to the contract's tool error; LatestGuardVersion
	// is the basalt_meta version this build installs.
	Errors             guidance.ErrorMap
	LatestGuardVersion func() int
}

// guide is a Service with only what the error guidance reads.
func (c ConnectOnly) guide() *Service {
	s := &Service{deps: Deps{
		Core:   CoreDeps{Name: c.Name, Commands: c.Commands.OperatedBy(c.OperatedBy), Log: c.Log, Now: c.Now, Errors: c.Errors},
		Status: StatusDeps{ConnectBudget: c.ConnectBudget},
	}}
	s.wire()
	return s
}

// Tools are every IMPLEMENTED tool of the contracts: status and
// confirm_database answer, every other tool is refused.
func (c ConnectOnly) Tools() []guidance.Tool {
	if c.Handoff == nil || c.Log == nil || c.Now == nil || c.LatestGuardVersion == nil {
		panic("agent: a connect-only agent needs its hand-off, a logger, a clock and the guard version")
	}
	contracts := mcpcontract.MustLoad()
	out := make([]guidance.Tool, 0, len(contracts))
	for _, ct := range contracts {
		if ct.Status != mcpcontract.StatusImplemented {
			continue
		}
		var call func(context.Context, json.RawMessage) (any, error)
		switch ct.Name {
		case guidance.ToolStatus:
			call = c.status
		case guidance.ToolConfirmDatabase:
			call = c.confirm
		default:
			call = c.refused(ct.Name)
		}
		out = append(out, guidance.Tool{Name: ct.Name, Description: ct.Description, InputSchema: ct.InputSchema, Call: refuseAdminCredential(ct.Name, call)})
	}
	return out
}

func (c ConnectOnly) status(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, c.guide().Failure(guidance.ToolStatus, nil, err)
	}
	return c.Status(ctx)
}

// refused answers every tool but status and confirm_database.
func (c ConnectOnly) refused(tool string) func(context.Context, json.RawMessage) (any, error) {
	return func(_ context.Context, raw json.RawMessage) (any, error) {
		st := c.Handoff.State()
		var err error = &guidance.SetupError{Code: st.Setup.Code, Fingerprint: st.Setup.Fingerprint, Expired: st.Expired, ConnectOnly: !st.Expired}
		if st.Phase == handoff.PhaseConfirm && st.Database != nil {
			err = &guidance.DatabaseNotConfirmedError{SetupID: st.Setup.SetupID, Database: *st.Database}
		}
		return nil, c.guide().Failure(tool, guidance.CallArgs(raw), err)
	}
}

func (c ConnectOnly) confirm(ctx context.Context, raw json.RawMessage) (any, error) {
	var args handoff.ConfirmArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, c.guide().Failure(guidance.ToolConfirmDatabase, nil, err)
	}
	ans, err := c.Handoff.Confirm(ctx, args.SetupID, args.Database, args.Answer == handoff.AnswerYes)
	switch {
	case errors.Is(err, handoff.ErrNotWaiting):
		return nil, c.guide().Failure(guidance.ToolConfirmDatabase, guidance.CallArgs(raw), &guidance.ArgumentError{Message: err.Error()})
	case err != nil:
		return nil, c.guide().Failure(guidance.ToolConfirmDatabase, guidance.CallArgs(raw), err)
	}
	return handoff.NewConfirmResult(ans, c.Commands.OperatedBy(c.OperatedBy))
}

// Status is the status tool of a connect-only agent: the engine answers,
// the guard is UNKNOWN (no credential yet), and the setup says where the
// hand-off stands. While it waits for the address, a status call also
// collects.
func (c ConnectOnly) Status(ctx context.Context) (guidance.StatusReport, error) {
	st := c.Handoff.StatusCollect(ctx)
	cmds := c.Commands.OperatedBy(c.OperatedBy)
	base := c.PagesBase
	if base == "" {
		base = links.DefaultLocal
	}
	r := guidance.StatusReport{
		Agent: c.Name, OperatedBy: operatedBy(c.OperatedBy), Enforcement: enforcement(c.OperatedBy, c.SameUser),
		Engine: guidance.EngineStatus{Reachable: true, Build: buildinfo.Version, StartedBy: startedByEnum(c.StartedBy)},
		Guard:  guidance.GuardStatus{State: guardmodel.GuardUnknown, Build: c.LatestGuardVersion()},
		Pages:  guidance.PagesStatus{Served: c.PagesOrigin != "", URL: base},
	}
	if c.Vault != nil {
		v := c.Vault.VaultStatus()
		r.Vault = &v
	}
	ps := guidance.Problems{Cmds: cmds, ConnectBudget: c.ConnectBudget}
	r.Setup = handoff.ConnectOnlyProblems(st, &ps, c.Now())
	list, err := ps.Sorted()
	if err != nil {
		return guidance.StatusReport{}, err
	}
	r.Problems, r.Ready = list, ready(list)
	return r, nil
}

// --- the served agent's confirm_database ---

// confirmDatabase answers confirm_database on an agent with no connect-only
// setup waiting: INVALID_ARGUMENT.
func (h handlers) confirmDatabase(_ context.Context, raw json.RawMessage) (any, error) {
	var args handoff.ConfirmArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return nil, &guidance.ArgumentError{Message: handoff.ErrNotWaiting.Error()}
}
