package app

import (
	"context"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// The store ports: everything the service asks of the agent's store, on the
// agent's own credential, in action types. The Postgres adapter
// (internal/platform/postgres/store) implements them; the service never imports it.

// agentStore is any store an agent can be bound to: its kind, what the
// engine may rely on, and the ledger kept next to it.
type agentStore interface {
	Kind() action.StoreKind
	Capabilities() action.Capabilities
	agentLedger
}

// agentLedger records the agent's runs, reads and refusals and reads them
// back.
type agentLedger interface {
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
	StartRun(ctx context.Context, in action.Intent) error
	// RecordRead records a read the engine ran (owner decision #7) and
	// returns its change id. It runs after the read's own read-only
	// transaction, so it may write.
	RecordRead(ctx context.Context, r action.Read) (uuid.UUID, error)
	RecordRefusal(ctx context.Context, r action.Refusal) error
	History(ctx context.Context, p action.ChangeListParams) (changeHistory, error)
	ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error)
}

// statementChecker checks a statement against the engine's SQL policy for
// a tool, and returns it as the store will run it, or an
// *action.RefusalError.
type statementChecker interface {
	Check(sql string, tool action.Tool) (action.Statement, error)
}

// SQLStore is a store that speaks SQL: the query and write tools run on it.
type SQLStore interface {
	agentStore
	approvalsvc.Store
	revertsvc.Store
	statementChecker
	// Read runs one read, with the versions of the rows of the statement's
	// sources it can identify.
	Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error)
	// Write runs one write through the guard.
	Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any) (action.WriteResult, error)
	// WriteApproved is Write under the person's signed approval.
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any) (action.WriteResult, error)
}
