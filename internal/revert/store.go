package revert

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// StoreSet is the revert's store as the revert use case reads it, built by
// the wiring for the store's kind and copied once when the service is
// built. The service reads the store only through it.
type StoreSet struct {
	// Kind is the kind of store the agent is bound to.
	Limits  Limits
	Records Records
	Undo    Undo
	Proofs  Proofs
}

// Limits are the store's time limits on a revert's calls.
type Limits struct {
	// Prepare is the longest a prepare, a rescope or a reset of a revert
	// runs in the store before it is canceled.
	Prepare time.Duration
}

// Records reads the ledger of the agent's reverts. It never changes data.
type Records interface {
	FindRevert(ctx context.Context, id uuid.UUID) (action.Revert, error)
	RevertLines(ctx context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error)
	// ListOpenReverts lists the role's PENDING and APPLYING reverts, keyset
	// on the revert id (list_pending, LP-1).
	ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error)
	// RevertedBy is the change record of the latest revert that covered scope
	// (a revert's own change, which request_revert accepts to redo the work),
	// or uuid.Nil when none did.
	RevertedBy(ctx context.Context, scope action.Scope) (uuid.UUID, error)
	HasChange(ctx context.Context, id uuid.UUID) (bool, error)
	// HasTaskRun reports whether the agent has a run with this task id.
	HasTaskRun(ctx context.Context, id uuid.UUID) (bool, error)
	// RevertNonce is the rescope nonce of a revert the role prepared.
	RevertNonce(ctx context.Context, id uuid.UUID) ([]byte, error)
	// RevealNonce is the reveal nonce of a revert the role prepared
	// (approval.KindRevert).
	RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error)
}

// Undo is the agent's side: what a revert would do, storing it for the
// person, and applying batches of a plan the person signed. Signing a
// revert is not an agent's to do: it needs the person's passkey.
type Undo interface {
	// PreviewRevert reads one page of the preview of scope, after the line
	// whose hash is after, with the preview's totals and large values left
	// out.
	PreviewRevert(ctx context.Context, scope action.Scope, after string, limit int) (action.PreviewPage, error)
	PrepareRevert(ctx context.Context, scope action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error)
	// ResetRevert puts a pending revert back to the proposal for the agent's
	// reissue, canceled past timeout.
	ResetRevert(ctx context.Context, id uuid.UUID, timeout time.Duration) (action.RescopedRevert, error)
	// ApplyRevertBatch applies lines of a plan the person signed; the store
	// checks each line against that plan.
	ApplyRevertBatch(ctx context.Context, id uuid.UUID, lines []int) (action.BatchResult, error)
}

// Proofs is the person's side: the page's calls, through the local pages or
// the Vault (CONTRACT.md, Local pages); no MCP tool reaches them. ApplyRevert
// only relays an assertion the person's page made, and the store verifies
// the signature.
type Proofs interface {
	ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error)
	// RescopeRevert changes a pending revert's scope for the person,
	// canceled past timeout.
	RescopeRevert(ctx context.Context, req action.RescopeRequest, timeout time.Duration) (action.RescopedRevert, error)
	// RejectRevert marks a pending revert REJECTED for the person, with the
	// scope token of a widened revert (nil before a widen).
	RejectRevert(ctx context.Context, id uuid.UUID, note string, token []byte) (action.RejectedRevert, error)
	// RevealRevertRows returns the values of a revert's redacted lines for
	// the person's reveal proof.
	RevealRevertRows(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) (action.RevealedRevert, error)
}

// Store is a store with all three sides of a revert, as the wiring builds a
// StoreSet from it.
type Store interface {
	Records
	Undo
	Proofs
}

// missingPorts names the ports of set that are nil.
func (set StoreSet) missingPorts() []string {
	var out []string
	if set.Records == nil {
		out = append(out, "Records")
	}
	if set.Undo == nil {
		out = append(out, "Undo")
	}
	if set.Proofs == nil {
		out = append(out, "Proofs")
	}
	return out
}
