package engine

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// admitFunc refuses a call the agent cannot be served yet (agent.Service.Admit).
type admitFunc func(ctx context.Context) error

// gatedLedger is the person socket's ledger for one agent, admitted on the
// same guard check as the agent's tools: on a guard that is missing or
// misses a breaking migration, every call is refused before it reaches the
// database, so no signed approval or revert is applied there.
type gatedLedger struct {
	inner person.Ledger
	admit admitFunc
}

// check is the person socket's answer for a call the guard check refused:
// REFUSED, with the agent's message (the basalt upgrade or init command).
func (g gatedLedger) check(ctx context.Context) error {
	err := g.admit(ctx)
	if err == nil {
		return nil
	}
	return &person.Error{Code: person.CodeRefused, Message: agent.ToolError(err).Message}
}

func (g gatedLedger) CheckHealth(ctx context.Context, opts ledger.HealthOptions) (ledger.Health, error) {
	if err := g.check(ctx); err != nil {
		return ledger.Health{}, err
	}
	return g.inner.CheckHealth(ctx, opts)
}

func (g gatedLedger) ListChanges(ctx context.Context, p ledger.ChangeListParams) (pagination.Page[ledger.Change], error) {
	if err := g.check(ctx); err != nil {
		return pagination.Page[ledger.Change]{}, err
	}
	return g.inner.ListChanges(ctx, p)
}

func (g gatedLedger) RowChanges(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]ledger.RowChange, error) {
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	return g.inner.RowChanges(ctx, ids)
}

func (g gatedLedger) ListPasskeys(ctx context.Context) ([]ledger.Passkey, error) {
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	return g.inner.ListPasskeys(ctx)
}

func (g gatedLedger) FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	if err := g.check(ctx); err != nil {
		return ledger.Approval{}, err
	}
	return g.inner.FindApproval(ctx, id)
}

func (g gatedLedger) SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	if err := g.check(ctx); err != nil {
		return time.Time{}, err
	}
	return g.inner.SubmitApproval(ctx, id, a)
}

func (g gatedLedger) FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	if err := g.check(ctx); err != nil {
		return ledger.Revert{}, err
	}
	return g.inner.FindRevert(ctx, id)
}

func (g gatedLedger) PreviewRevert(ctx context.Context, s guard.RevertScope) ([]string, error) {
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	return g.inner.PreviewRevert(ctx, s)
}

func (g gatedLedger) PrepareRevert(ctx context.Context, s guard.RevertScope, intent string) (guard.PreparedRevert, error) {
	if err := g.check(ctx); err != nil {
		return guard.PreparedRevert{}, err
	}
	return g.inner.PrepareRevert(ctx, s, intent)
}

func (g gatedLedger) ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guard.AppliedRevert, error) {
	if err := g.check(ctx); err != nil {
		return guard.AppliedRevert{}, err
	}
	return g.inner.ApplyRevert(ctx, id, a)
}

func (g gatedLedger) ListRevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error) {
	if err := g.check(ctx); err != nil {
		return pagination.Page[ledger.RevertLine]{}, err
	}
	return g.inner.ListRevertLines(ctx, p)
}
