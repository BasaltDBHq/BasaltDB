package approval

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Store holds writes for the person's approval and relays their
// signature.
type Store interface {
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
