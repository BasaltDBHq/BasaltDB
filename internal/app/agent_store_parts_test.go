package app

import (
	"context"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
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
	Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any, returned store.Returned) (action.WriteResult, error)
	RecordRefusal(ctx context.Context, r action.Refusal) error
	History(ctx context.Context, p action.ChangeListParams) (changeHistory, error)
	ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunListItem], error)
}

type readRecorder interface {
	RecordRead(ctx context.Context, r action.Read) (uuid.UUID, error)
}

// approvalStore is the approvals part, with the Postgres store's apply of
// an approved write.
type approvalStore interface {
	approvalsvc.Store
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any, returned store.Returned) (action.WriteResult, error)
}

type parts struct {
	reader
	runStore
	readRecorder
	approvalStore
	revertsvc.Store
}

func (parts) Kind() action.StoreKind { return action.StorePostgres }

func (parts) Capabilities() action.Capabilities {
	return action.Capabilities{InStoreSignatureCheck: true}
}

// RevealNonce asks the approvals part for an approval's nonce and the
// reverts part for a revert's.
func (p parts) RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error) {
	if kind == approval.KindRevert {
		return p.Store.RevealNonce(ctx, kind, id)
	}
	return p.approvalStore.RevealNonce(ctx, kind, id)
}

// Check is the Postgres store's policy check, which needs no connection.
func (parts) Check(sql string, tool action.Tool) (action.Statement, error) {
	return store.Check(sql, tool)
}

// HeldFrom is the Postgres store's compare, which needs no connection.
func (parts) HeldFrom(held, sent string) bool {
	return (&store.Store{}).HeldFrom(held, sent)
}

// setApprovals and setReverts replace one part of d's store.
func setApprovals(d *Deps, a approvalStore) {
	p, _ := d.Core.Store.(parts)
	p.approvalStore = a
	useStore(d, p)
}

func setReverts(d *Deps, r revertsvc.Store) {
	p, _ := d.Core.Store.(parts)
	p.Store = r
	useStore(d, p)
}
