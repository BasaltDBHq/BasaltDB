package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// The store ports: everything the service asks of the agent's store, on the
// agent's own credential, in action types. The Postgres adapter
// (internal/platform/postgres/store) implements them; the service never imports it.

// Store is any store an agent can be bound to: its kind, what the engine
// may rely on, and the ledger kept next to it.
type Store interface {
	Kind() action.StoreKind
	Capabilities() action.Capabilities
	Ledger
}

// Ledger records the agent's runs, reads and refusals and reads them back.
type Ledger interface {
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
	StartRun(ctx context.Context, in action.Intent) error
	// RecordRead records a read the engine ran (owner decision #7) and
	// returns its change id. It runs after the read's own read-only
	// transaction, so it may write.
	RecordRead(ctx context.Context, r action.Read) (uuid.UUID, error)
	RecordRefusal(ctx context.Context, r action.Refusal) error
	History(ctx context.Context, p action.ChangeListParams) (History, error)
	ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error)
}

// Approvals holds writes for the person's approval and relays their
// signature.
type Approvals interface {
	// HoldColumns returns the columns whose new values the person's
	// approval binds for a held write, or an *action.RefusalError
	// (NOT_REPEATABLE) for a write that cannot be run again the same way.
	HoldColumns(ctx context.Context, sql string, params []any) ([]string, error)
	Preview(ctx context.Context, in action.Intent, sql string, params []any, assigned []string) ([]string, error)
	Hold(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error)
	TableColumns(ctx context.Context, table string) ([]string, error)
	SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error)
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	ListApprovals(ctx context.Context, p action.ApprovalListParams) (pagination.Page[action.Approval], error)
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
	// RevealNonce is the reveal nonce of an approval or revert the role
	// holds (approval.KindApprove or approval.KindRevert).
	RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error)
	// OpenReveal checks the person's reveal proof for a held write and
	// returns the ticket of the re-run preview; RevealPreview re-runs the
	// held write in a preview that rolls back and reads its hidden rows.
	OpenReveal(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) ([]byte, error)
	RevealPreview(ctx context.Context, in action.Intent, op action.Op, sql string, params []any, id uuid.UUID, ticket []byte) ([]approval.RevealedRow, error)
}

// Reverts previews reverts, reads the large plans the agent prepared and
// applies batches of them. Signing a revert is not an agent's to do: it
// needs the person's passkey. ApplyRevert only relays an assertion the
// person's page made, through the local pages or the Vault (CONTRACT.md,
// Local pages); no MCP tool reaches it, and the store verifies the
// signature.
type Reverts interface {
	// PreviewRevert reads one page of the preview of scope, after the line
	// whose hash is after, with the preview's totals and large values left
	// out.
	PreviewRevert(ctx context.Context, scope action.Scope, after string, limit int) (action.PreviewPage, error)
	// RevertedBy is the change record of the latest revert that covered scope
	// (a revert's own change, which request_revert accepts to redo the work),
	// or uuid.Nil when none did.
	RevertedBy(ctx context.Context, scope action.Scope) (uuid.UUID, error)
	PrepareRevert(ctx context.Context, scope action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error)
	HasChange(ctx context.Context, id uuid.UUID) (bool, error)
	// HasTaskRun reports whether the agent has a run with this task id.
	HasTaskRun(ctx context.Context, id uuid.UUID) (bool, error)
	FindRevert(ctx context.Context, id uuid.UUID) (action.Revert, error)
	RevertLines(ctx context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error)
	ApplyRevertBatch(ctx context.Context, id uuid.UUID, lines []int) (action.BatchResult, error)
	ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error)
	// RescopeRevert and ResetRevert change a pending revert's scope for the
	// person, and put it back to the proposal for the agent's reissue, each
	// canceled past timeout.
	RescopeRevert(ctx context.Context, req action.RescopeRequest, timeout time.Duration) (action.RescopedRevert, error)
	ResetRevert(ctx context.Context, id uuid.UUID, timeout time.Duration) (action.RescopedRevert, error)
	// RevertNonce is the rescope nonce of a revert the role prepared.
	RevertNonce(ctx context.Context, id uuid.UUID) ([]byte, error)
	// RejectRevert marks a pending revert REJECTED for the person, with the
	// scope token of a widened revert (nil before a widen).
	RejectRevert(ctx context.Context, id uuid.UUID, note string, token []byte) (action.RejectedRevert, error)
	// ListOpenReverts lists the role's PENDING and APPLYING reverts, keyset
	// on the revert id (list_pending, LP-1).
	ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error)
	// RevealNonce is the reveal nonce of a revert the role prepared
	// (approval.KindRevert); RevealRevertRows returns the values of its
	// redacted lines for the person's reveal proof.
	RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error)
	RevealRevertRows(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) (action.RevealedRevert, error)
}

// statementChecker checks a statement against the engine's SQL policy for
// a tool, and returns it as the store will run it, or an
// *action.RefusalError.
type statementChecker interface {
	Check(sql string, tool action.Tool) (action.Statement, error)
}

// SQLStore is a store that speaks SQL: the query and write tools run on it.
type SQLStore interface {
	Store
	Approvals
	Reverts
	statementChecker
	// Read runs one read, with the versions of the rows of the statement's
	// sources it can identify.
	Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error)
	// Write runs one write through the guard.
	Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any) (action.WriteResult, error)
	// WriteApproved is Write under the person's signed approval.
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any) (action.WriteResult, error)
}
