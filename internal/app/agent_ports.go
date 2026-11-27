package app

import (
	"context"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/agent/out/sqllang"
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
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
	ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunListItem], error)
}

// statementChecker checks a statement against the engine's SQL policy for
// a tool, and returns it as the store will run it, or an
// *action.RefusalError.
type statementChecker interface {
	Check(sql string, tool action.Tool) (action.Statement, error)
}

// txRows is how a SQL store hands the rows a write returns to the wiring,
// inside the write's transaction, before COMMIT: tx is that transaction,
// driver-free. It is the Postgres store's Returned.
type txRows = func(ctx context.Context, tx sqlport.Port, cols []action.Column, rows []map[string]any) error

// SQLStore is a store that speaks SQL: the query and write tools run on it.
type SQLStore interface {
	agentStore
	approvalsvc.Store
	revertsvc.Store
	statementChecker
	// Read runs one read, with the versions of the rows of the statement's
	// sources it can identify.
	Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error)
	// Write runs one write through the guard, handing the rows it returns
	// to returned before COMMIT.
	Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any, returned txRows) (action.WriteResult, error)
	// WriteApproved is Write under the person's signed approval.
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any, returned txRows) (action.WriteResult, error)
}

// agentDeps are the agent use case's own ports on the agent's store, which
// wire puts together with Core.Store into the agent's store set, and what
// the use case adds around the store.
type agentDeps struct {
	// Data is the store the query and write tools run on.
	Data SQLStore
	// Limits are the read limits the agent's statements run within.
	Limits action.Limits
	// Catalog reads the store's structure for describe; optional, and
	// describe answers INTERNAL when nil.
	Catalog agentsvc.Catalog
	// Classes are the agent's PII classes for describe; optional, and
	// describe fails closed (INTERNAL) when nil: it cannot tell a SECRET
	// column.
	Classes agentsvc.ClassResolver
	// Visibility says whether row-level security hides a table from the
	// agent (the RLS_HIDES_ROWS warning); optional, nothing is hidden when
	// nil.
	Visibility agentsvc.Visibility
	// PII sees every read's rows before they are returned and adds the
	// values of IDENTIFIER columns to the dictionary (M5.1); optional,
	// nothing is added when nil.
	PII agentsvc.PIIObserver
	// Record is the wire record of one change and its rows, as the ledger
	// renders it (run_history).
	Record func(ch action.Change, rows []action.RowChange) any
}

// agentStoreSet is the agent's store set: the ports of its store, the
// family its kind belongs to, and the store's language. SQL is the only
// language the engine has; a store of another family is served none of the
// tools that send a request. wire builds the set once, when the service is
// built, and agentsvc.New keeps a copy: a later change to the ports in
// s.deps.Agent or to the core store does not reach the agent use cases. The
// statement check is the exception: liveChecker reads s.deps.Agent.Data on
// each call.
func (s *Service) agentStoreSet() agentsvc.StoreSet {
	a := &s.deps.Agent
	set := agentsvc.StoreSet{
		Language: sqllang.New(liveChecker{a}), Catalog: a.Catalog, Classes: a.Classes, Visibility: a.Visibility,
	}
	if st := s.deps.Core.Store; st != nil {
		set.Kind, set.Capabilities, set.Ledger = st.Kind(), st.Capabilities(), st
	}
	set.Family = storeFamily(set.Kind)
	if a.Data != nil {
		set.Data = agentData{store: a.Data, limits: a.Limits}
	}
	return set
}

// storeFamily is the family of a store of kind: Postgres and MySQL speak
// SQL; another kind has no family the engine serves yet.
func storeFamily(kind action.StoreKind) agentstore.Family {
	if kind == action.StorePostgres || kind == action.StoreMySQL {
		return agentstore.FamilySQL
	}
	return ""
}

// liveChecker is the SQL store's statement check, read live from the
// service.
type liveChecker struct{ d *agentDeps }

func (l liveChecker) Check(sql string, tool action.Tool) (action.Statement, error) {
	return l.d.Data.Check(sql, tool)
}

// agentData is the SQL store as the agent's query and write use cases run
// on it: a request is passed on as its text and parameters, a write with
// the op its check read.
type agentData struct {
	store  SQLStore
	limits action.Limits
}

func (d agentData) Read(ctx context.Context, req agentstore.Request, stmt action.Statement) (action.ReadResult, error) {
	return d.store.Read(ctx, req.Text, req.Params, stmt)
}

func (d agentData) Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement, returned agentsvc.Returned) (action.WriteResult, error) {
	return d.store.Write(ctx, in, stmt.Op, req.Text, req.Params, txReturned(returned))
}

func (d agentData) WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, req agentstore.Request, stmt action.Statement, returned agentsvc.Returned) (action.WriteResult, error) {
	return d.store.WriteApproved(ctx, in, approvalID, stmt.Op, req.Text, req.Params, txReturned(returned))
}

func (d agentData) Limits() action.Limits { return d.limits }
