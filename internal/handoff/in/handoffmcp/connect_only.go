package handoffmcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	statussvc "github.com/basaltdbhq/basaltdb/internal/status"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// A connect-only setup on the engine (CONTRACT.md, Setup from your laptop,
// The engine and a connect-only code). Until the person confirms the
// database the engine collected, the agent is served by ConnectOnly: it
// holds no credential and no connection, status and confirm_database
// answer, and every other tool is refused.

// --- the result of confirm_database ---

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
	Vault         statussvc.VaultReporter
	Handoff       handoff.Handoff
	Log           *slog.Logger
	Now           func() time.Time
	// Errors maps a failure to the contract's tool error; LatestGuardVersion
	// is the basalt_meta version this build installs.
	Errors             guidance.ErrorMap
	LatestGuardVersion func() int
	// Guide builds the agent's error presenter with only what the error
	// guidance reads, from c: built again for each failure.
	Guide func(c ConnectOnly) Failures
}

// Failures is the agent's error presenter as a connect-only agent calls
// it: each failure as the contract's error body, with its next steps.
type Failures interface {
	Failure(tool string, args map[string]any, err error) *toolresult.ToolError
}

// guide is the agent's error presenter with only what the error guidance
// reads.
func (c ConnectOnly) guide() Failures {
	return c.Guide(c)
}

// Tools are every IMPLEMENTED tool of the contracts: status and
// confirm_database answer, every other tool is refused.
func (c ConnectOnly) Tools() []mcpserver.Tool {
	if c.Handoff == nil || c.Log == nil || c.Now == nil || c.LatestGuardVersion == nil {
		panic("agent: a connect-only agent needs its hand-off, a logger, a clock and the guard version")
	}
	if c.Guide == nil {
		panic("agent: a connect-only agent needs its error guide")
	}
	contracts := mcpcontract.MustLoad()
	out := make([]mcpserver.Tool, 0, len(contracts))
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
		out = append(out, mcpserver.Tool{Name: ct.Name, Description: ct.Description, InputSchema: ct.InputSchema, Call: mcpserver.RefuseAdminCredential(ct.Name, call)})
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
	var args confirmArgs
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
	return statussvc.ConnectOnly(statussvc.Head{
		Agent: c.Name, OperatedBy: c.OperatedBy, SameUser: c.SameUser, Build: buildinfo.Version, StartedBy: c.StartedBy,
		PagesBase: c.PagesBase, PagesOrigin: c.PagesOrigin, Vault: c.Vault,
	}, c.Commands.OperatedBy(c.OperatedBy), c.ConnectBudget, c.LatestGuardVersion(), st, c.Now())
}
