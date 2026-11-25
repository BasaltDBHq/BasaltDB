// Package agent is what the engine does for one agent on its own database:
// describe, and the runs, queries and writes it makes, each on the agent's
// scoped credential. The tools that front it are internal/agent/in/agentmcp;
// internal/app wires it with the use cases of the other domains.
package agent

import (
	"context"
	"errors"
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

// Ledger is the ledger kept next to the agent's store: its runs, reads and
// refusals.
type Ledger interface {
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
// pass a request on and never read its text, and they read the store's
// error messages only through it.
type Language interface {
	// Check checks req against the store's policy for tool and its
	// parameters, and returns it as the store will run it. With an error the
	// statement carries the op the store read, when it read one.
	Check(req agentstore.Request, tool action.Tool) (action.Statement, error)
	// RefusalText is the revision a statement refusal of reason asks for,
	// and false for a reason not fixed by rewriting the request.
	RefusalText(reason string) (string, bool)
	// LimitText is the revision a request that ran into a limit asks for,
	// by the QUERY_TIMEOUT reason; any other reason is the statement
	// timeout's.
	LimitText(reason string) string
	// Args is a request as the store family's query and write tools take
	// it, for the call a next step repeats.
	agentstore.RequestArgs
	// ReadRow is the request that reads the item of target with key.
	ReadRow(target string, key map[string]any) agentstore.Request
	// StaleTarget reads the target and key of the item a STALE_READ
	// message names; its error says what it could not read.
	StaleTarget(message string) (target string, key map[string]any, err error)
	// DeniedTarget is the resource a permission-denied message names, and
	// false when it names none.
	DeniedTarget(message string) (string, bool)
	// NoKeyTarget is the resource a refusal for a missing primary key
	// names, and false when it names none.
	NoKeyTarget(message string) (string, bool)
	// ParseName reads a resource's name as the agent writes it; its error
	// says what is wrong with it.
	ParseName(s string) (namespace, name string, err error)
	// PrintName is a resource's name as the agent writes it.
	PrintName(namespace, name string) string
}

// Data is the part of the agent's store the query and write tools run on.
// It is given a request as it came and the statement Language.Check made of
// it.
type Data interface {
	// Read runs one read, with the versions of the items of the
	// statement's sources it can identify.
	Read(ctx context.Context, req agentstore.Request, stmt action.Statement) (action.ReadResult, error)
	// Write runs one write through the guard.
	Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement) (action.WriteResult, error)
	// WriteApproved is Write under the person's signed approval.
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, req agentstore.Request, stmt action.Statement) (action.WriteResult, error)
	// Limits are the read limits the agent's requests run within.
	Limits() action.Limits
}

// Visibility says whether the store hides every item of a target from the
// agent (row-level security for Postgres). It returns the target's name as
// the store writes it, or "" when the target is not hidden.
type Visibility interface {
	Hides(ctx context.Context, target string) (string, error)
}

// StoreSet is the agent's store as the agent use cases read it, built by
// the wiring for the store's kind. The service may read Capabilities; it
// never switches on the kind.
type StoreSet struct {
	// Kind is the kind of store the agent is bound to, as describe reports it.
	Kind action.StoreKind
	// Family picks the tools the agent is served.
	Family       agentstore.Family
	Capabilities action.Capabilities
	// Language is the store's language: the check of a request, the texts
	// of its refusals and steps, and its resource names.
	Language Language
	// Data runs the reads and writes; without it every one fails as an
	// engine defect (INTERNAL).
	Data Data
	// Catalog reads the store's structure for describe; without it describe
	// answers INTERNAL.
	Catalog Catalog
	// Ledger is the ledger of the agent's runs.
	Ledger Ledger
	// Classes are the agent's PII classes for describe; without them
	// describe fails closed (INTERNAL): it cannot tell a SECRET field.
	Classes ClassResolver
	// Visibility says what the store hides from the agent (the
	// RLS_HIDES_ROWS warning); optional, nothing is hidden when nil.
	Visibility Visibility
}

// Core is the part of the shared settings the agent use cases read, copied
// when the service is built.
type Core struct {
	Name     string
	Log      *slog.Logger
	Now      func() time.Time
	Commands guidance.Commands
	Errors   guidance.ErrorMap
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
// copy of the core settings and the agent's store set; what it needs
// from the other use cases it names as small ports of its own.
type Service struct {
	core  Core
	store StoreSet
	// pii sees every read's rows before they are returned.
	pii PIIObserver
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

// New returns the service over core and the agent's store. A nil Data,
// Catalog or Classes is replaced by one that fails closed, and a nil pii by
// one that adds nothing; a nil Visibility hides nothing. Give it the other
// use cases it asks with SetPorts before it serves a write.
func New(core Core, store StoreSet, pii PIIObserver, update func() *guidance.UpdateInfo) *Service {
	if store.Data == nil {
		store.Data = noData{}
	}
	if store.Catalog == nil {
		store.Catalog = noCatalog{}
	}
	if store.Classes == nil {
		store.Classes = noClasses{}
	}
	if pii == nil {
		pii = noPII{}
	}
	return &Service{core: core, store: store, pii: pii, update: update}
}

// SetPorts gives the service the use cases it asks: the delivery of held
// actions, the approvals, the upgrade warnings of run_start, the link of an
// approval error and the steps of an UNAVAILABLE error.
func (ds *Service) SetPorts(delivery Delivery, approvals Approvals, upgrade UpgradeWarner, next ApprovalLinker, steps Unavailable) {
	ds.delivery, ds.approvals, ds.upgrade, ds.next, ds.steps = delivery, approvals, upgrade, next, steps
}

// StatementTimeout is the agent's statement timeout, 0 when the service
// knows no store data or its Data has zero Limits.
func (ds *Service) StatementTimeout() time.Duration {
	return ds.store.Data.Limits().StatementTimeout
}

// Family is the family of the agent's store: it picks the tools the agent
// is served.
func (ds *Service) Family() agentstore.Family { return ds.store.Family }

// noData serves a service built without the store's data: every read and
// write is an engine defect (INTERNAL), and it knows no limits.
type noData struct{}

var errNoData = errors.New("agent: no store data configured")

func (noData) Read(context.Context, agentstore.Request, action.Statement) (action.ReadResult, error) {
	return action.ReadResult{}, errNoData
}

func (noData) Write(context.Context, action.Intent, agentstore.Request, action.Statement) (action.WriteResult, error) {
	return action.WriteResult{}, errNoData
}

func (noData) WriteApproved(context.Context, action.Intent, uuid.UUID, agentstore.Request, action.Statement) (action.WriteResult, error) {
	return action.WriteResult{}, errNoData
}

func (noData) Limits() action.Limits { return action.Limits{} }
