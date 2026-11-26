package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// Catalog reads the structure of the store the agent can see, on the
// agent's own credential (CONTRACT.md, describe), in the store-neutral types
// of core/agentstore. The store's adapter fills the content; the service
// decides what is hidden.
type Catalog interface {
	// Resources lists the readable resources by namespace and name, and
	// counts the ones in user namespaces the agent cannot read.
	Resources(ctx context.Context) ([]agentstore.Resource, int, error)
	// Find returns namespace.name, or false when it is absent or unreadable.
	Find(ctx context.Context, namespace, name string) (agentstore.Resource, bool, error)
	// Describe reads one resource Find or Resources returned.
	Describe(ctx context.Context, ref agentstore.ResourceRef) (agentstore.Detail, error)
	// Guarded reports whether basalt init guards the resource, so its
	// writes run under the write policy; false where the guard predates
	// the record of it.
	Guarded(ctx context.Context, ref agentstore.ResourceRef) (bool, error)
	// Search finds readable resources by name, field or comment; exclude
	// lists fields never matched or named.
	Search(ctx context.Context, q string, exclude []agentstore.FieldRef, after *agentstore.Cursor, limit int) ([]agentstore.Match, error)
	// Structure is the sorted structure lines the catalog fingerprint hashes.
	Structure(ctx context.Context) ([]string, error)
	// Database is the database the credential connects to.
	Database() string
	// Host is the host that database is on (name and host only, never a
	// user, port or credential).
	Host() string
}

// ClassResolver is the agent's PII classification, by field.
type ClassResolver interface {
	// Resolve is the classes of refs, in their order.
	Resolve(ctx context.Context, refs []agentstore.FieldRef) ([]pii.Class, error)
	// Secrets lists the SECRET fields: describe never lists, matches or
	// names them.
	Secrets(ctx context.Context) ([]agentstore.FieldRef, error)
	// CatalogFingerprint is agent_pii_catalog.fingerprint as hex, empty
	// before the first basalt classify.
	CatalogFingerprint(ctx context.Context) (string, error)
}

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
	// Write runs one write through the guard. It hands the rows the write
	// returns to returned inside the write's transaction, before it
	// commits; an error from returned rolls the write back and is returned
	// as is.
	Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement, returned Returned) (action.WriteResult, error)
	// WriteApproved is Write under the person's signed approval.
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, req agentstore.Request, stmt action.Statement, returned Returned) (action.WriteResult, error)
	// Limits are the read limits the agent's requests run within.
	Limits() action.Limits
}

// Visibility says whether the store hides every item of a target from the
// agent (row-level security for Postgres). It returns the target's name as
// the store writes it, or "" when the target is not hidden.
type Visibility interface {
	Hides(ctx context.Context, target string) (string, error)
}

// PIIObserver adds the PII values of rows the agent is about to get to the
// engine's dictionary. An error means a value could not be added: the rows
// are not returned (fail closed). It never logs a value.
type PIIObserver interface {
	// Observe sees a read's rows, reading the classes on its own.
	Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error
	// ObserveReturned sees a write's returned rows before the write
	// commits, reading the classes through classes: the write's own
	// transaction, so the classes are the ones in force in it.
	ObserveReturned(ctx context.Context, classes pii.Classes, cols []action.Column, rows []map[string]any) error
}

// Returned is how a store hands the rows a write returns to the agent's
// PII port: inside the write's transaction, before it commits, with
// classes reading the PII classes in that same transaction. The store
// calls it only when the write returned rows.
type Returned func(ctx context.Context, classes pii.Classes, cols []action.Column, rows []map[string]any) error

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
	// Hold holds a write for the person's approval; a refusal to record
	// as a refused write comes as an *approvalsvc.HoldRefusalError.
	Hold(ctx context.Context, in action.Intent, req agentstore.Request, op action.Op) (approvalsvc.HeldWrite, error)
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
