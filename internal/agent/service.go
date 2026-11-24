// Package agent is what the engine does for one agent on its own database:
// describe, and the runs, queries and writes it makes, each on the agent's
// scoped credential. The tools that front it are internal/agent/in/agentmcp;
// internal/app wires it with the use cases of the other domains.
package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// Store is what the agent use cases read of the agent's store: its kind and
// the ledger of its runs, reads and refusals.
type Store interface {
	// Kind is the kind of store the agent is bound to.
	Kind() action.StoreKind
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
	StartRun(ctx context.Context, in action.Intent) error
	// RecordRead records a read the engine ran (owner decision #7) and
	// returns its change id. It runs after the read's own read-only
	// transaction, so it may write.
	RecordRead(ctx context.Context, r action.Read) (uuid.UUID, error)
	RecordRefusal(ctx context.Context, r action.Refusal) error
	ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error)
}

// Language is what the agent use cases ask of the store's language: they
// pass a request on and never read its text.
type Language interface {
	// Check checks req against the store's policy for tool and its
	// parameters, and returns it as the store will run it. With an error the
	// statement carries the op the store read, when it read one.
	Check(req agentstore.Request, tool action.Tool) (action.Statement, error)
	// RefusalText is the revision a statement refusal of reason asks for,
	// and false for a reason not fixed by rewriting the request.
	RefusalText(reason string) (string, bool)
	// ReadRow is the request that reads the item of target with key.
	ReadRow(target string, key map[string]any) agentstore.Request
	// ParseName reads a resource's name as the agent writes it; its error
	// says what is wrong with it.
	ParseName(s string) (namespace, name string, err error)
	// PrintName is a resource's name as the agent writes it.
	PrintName(namespace, name string) string
}

// Core is the part of the shared settings the agent use cases read, copied
// when the service is built.
type Core struct {
	Name  string
	Store Store
	// Language is the store's language: the check of a request, the texts
	// of its refusals and steps, and its resource names.
	Language Language
	Log      *slog.Logger
	Now      func() time.Time
	Commands guidance.Commands
	Errors   guidance.ErrorMap
}

// DescribeDeps is what the describe tool reads.
type DescribeDeps struct {
	// Catalog reads the database's structure for describe; optional, and
	// describe answers INTERNAL when nil.
	Catalog Catalog
	// Classes are the agent's PII classes for describe; optional, and
	// describe fails closed (INTERNAL) when nil: it cannot tell a SECRET
	// column.
	Classes ClassResolver
}

// WriteDeps is what the query and write tools use.
type WriteDeps struct {
	// Store checks a statement against the policy and runs it, through the
	// guard for a write.
	Store WriteStore
	// RLS says whether row-level security hides a table from the agent
	// (the RLS_HIDES_ROWS warning); optional, nothing is hidden when nil.
	RLS RLSChecker
	// PII sees every read's rows before they are returned and adds the
	// values of IDENTIFIER columns to the dictionary (M5.1); optional,
	// nothing is added when nil.
	PII PIIObserver
	// Record is the wire record of one change and its rows, as the ledger
	// renders it (run_history).
	Record func(ch action.Change, rows []action.RowChange) any
}

// PIIObserver adds the PII values of rows the agent is about to get to the
// engine's dictionary. An error means a value could not be added: the rows
// are not returned (fail closed). It never logs a value.
type PIIObserver interface {
	Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error
}

type noPII struct{}

func (noPII) Observe(context.Context, []action.Column, []map[string]any) error { return nil }

// Service runs one agent's describe, run, query and write calls. It holds a
// copy of the core settings and its own dependency groups; what it needs
// from the other use cases it names as small ports of its own.
type Service struct {
	core     Core
	describe *DescribeDeps
	write    *WriteDeps
	// update is the newer release the engine knows of, as describe's overview
	// reports it; the status use case owns it and hands it in.
	update    func() *guidance.UpdateInfo
	delivery  Delivery
	approvals Approvals
	upgrade   UpgradeWarner
	next      ApprovalLinker
	steps     Unavailable
}

// Delivery is what the write use case asks of the delivery use case.
type Delivery interface {
	ApprovalReceiptOf(a action.Approval) (linksvc.Receipt, error)
	AwaitWhile(ctx context.Context, wait time.Duration, pending func() bool, refresh func(context.Context) error) error
	DeliverHeld(id uuid.UUID, expires time.Time, answer error)
	NotifyHeldTo(ctx context.Context, n linksvc.HeldNotice) error
}

// Approvals is what the write use case asks of the approval use case: to
// hold a write and to read it back.
type Approvals interface {
	ApprovalNotice(ctx context.Context, id, runID uuid.UUID, req linksvc.SizedRequest, expires time.Time, issue bool) (linksvc.HeldAnswer, error)
	HoldColumns(ctx context.Context, req agentstore.Request) ([]string, error)
	Preview(ctx context.Context, in action.Intent, req agentstore.Request, assigned []string) ([]string, error)
	Hold(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error)
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	// NotFound is the ledger's answer for an approval the role does not hold.
	NotFound() error
	// HoldTooLargeSteps and ApprovalRequiredSteps are the steps and the
	// person's message of the errors a held write answers with.
	HoldTooLargeSteps(b *guidance.Steps, te *toolresult.ToolError) string
	ApprovalRequiredSteps(b *guidance.Steps, te *toolresult.ToolError) string
}

// UpgradeWarner gives the warnings of a guard that can be upgraded, for run_start.
type UpgradeWarner interface {
	UpgradeWarnings(ctx context.Context) []toolresult.Warning
}

// ApprovalLinker puts the link of a held write into an error answer.
type ApprovalLinker interface {
	ApprovalLinkError(te *toolresult.ToolError, n linksvc.HeldAnswer) *toolresult.ToolError
}

// Unavailable builds the steps and the person's message of an UNAVAILABLE
// error, which the status and handoff use cases own.
type Unavailable interface {
	UnavailableSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string
}

// New returns the service over core and its dependency groups. A nil
// Catalog, Classes, RLS or PII is replaced, in the group itself, by one that
// fails closed or does nothing. Give it the other use cases it asks with
// SetPorts before it serves a write.
func New(core Core, describe *DescribeDeps, write *WriteDeps, update func() *guidance.UpdateInfo) *Service {
	if describe.Catalog == nil {
		describe.Catalog = noCatalog{}
	}
	if describe.Classes == nil {
		describe.Classes = noClasses{}
	}
	if write.RLS == nil {
		write.RLS = noRLS{}
	}
	if write.PII == nil {
		write.PII = noPII{}
	}
	return &Service{core: core, describe: describe, write: write, update: update}
}

// SetPorts gives the service the use cases it asks: the delivery of held
// actions, the approvals, the upgrade warnings of run_start, the link of an
// approval error and the steps of an UNAVAILABLE error.
func (ds *Service) SetPorts(delivery Delivery, approvals Approvals, upgrade UpgradeWarner, next ApprovalLinker, steps Unavailable) {
	ds.delivery, ds.approvals, ds.upgrade, ds.next, ds.steps = delivery, approvals, upgrade, next, steps
}

// StatementTimeout is the agent's statement timeout, 0 when the service
// knows no catalog.
func (ds *Service) StatementTimeout() time.Duration {
	if ds.describe.Catalog == nil {
		return 0
	}
	return ds.describe.Catalog.Limits().StatementTimeout
}
