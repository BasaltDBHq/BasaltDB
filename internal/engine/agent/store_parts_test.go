package agent

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// The tests fake the agent's store in parts: reads, runs and writes, read
// records, approvals and reverts. parts puts them together as one SQLStore;
// a part left nil panics when called, as a fake that should not be reached.

type reader interface {
	Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error)
}

type runStore interface {
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
	StartRun(ctx context.Context, in action.Intent) error
	Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any) (action.WriteResult, error)
	RecordRefusal(ctx context.Context, r action.Refusal) error
	History(ctx context.Context, p ledger.ChangeListParams) (History, error)
	ListRuns(ctx context.Context, p ledger.RunListParams) (pagination.Page[action.RunSummary], error)
}

type readRecorder interface {
	RecordRead(ctx context.Context, r action.Read) (uuid.UUID, error)
}

type approvalStore interface {
	Approvals
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any) (action.WriteResult, error)
}

type parts struct {
	reader
	runStore
	readRecorder
	approvalStore
	Reverts
}

func (parts) Kind() action.StoreKind { return action.StorePostgres }

func (parts) Capabilities() action.Capabilities { return action.Capabilities{} }

// RevealNonce asks the approvals part for an approval's nonce and the
// reverts part for a revert's.
func (p parts) RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error) {
	if kind == approval.KindRevert {
		return p.Reverts.RevealNonce(ctx, kind, id)
	}
	return p.approvalStore.RevealNonce(ctx, kind, id)
}

// setApprovals and setReverts replace one part of d's store.
func setApprovals(d *Deps, a approvalStore) {
	p, _ := d.Store.(parts)
	p.approvalStore = a
	d.Store = p
}

func setReverts(d *Deps, r Reverts) {
	p, _ := d.Store.(parts)
	p.Reverts = r
	d.Store = p
}

func setRuns(d *Deps, r runStore) {
	p, _ := d.Store.(parts)
	p.runStore = r
	d.Store = p
}
