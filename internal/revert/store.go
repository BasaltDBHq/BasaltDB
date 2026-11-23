package revert

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Store previews reverts, reads the large plans the agent prepared and
// applies batches of them. Signing a revert is not an agent's to do: it
// needs the person's passkey. ApplyRevert only relays an assertion the
// person's page made, through the local pages or the Vault (CONTRACT.md,
// Local pages); no MCP tool reaches it, and the store verifies the
// signature.
type Store interface {
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
