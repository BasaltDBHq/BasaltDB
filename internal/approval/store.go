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

// StoreSet is the approval's store as the approval use case reads it: the
// store's kind and capabilities and its ports, built by the wiring and
// copied once when the service is built. The service reads the store only
// through it.
type StoreSet struct {
	Kind         action.StoreKind
	Capabilities action.Capabilities
	Records      Records
	Holds        Holds
	Proofs       Proofs
}

// Records reads the ledger of the agent's held writes. It never changes
// data.
type Records interface {
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	ListApprovals(ctx context.Context, p action.ApprovalListParams) (pagination.Page[action.Approval], error)
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
	// RevealNonce is the reveal nonce of an approval or revert the role
	// holds (approval.KindApprove or approval.KindRevert).
	RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error)
}

// Holds is the agent's side: holding a write for the person's approval.
type Holds interface {
	// HoldColumns returns the columns whose new values the person's
	// approval binds for a held write, or an *action.RefusalError
	// (NOT_REPEATABLE) for a write that cannot be run again the same way.
	HoldColumns(ctx context.Context, sql string, params []any) ([]string, error)
	Preview(ctx context.Context, in action.Intent, sql string, params []any, assigned []string) ([]string, error)
	Hold(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error)
}

// Proofs is the person's side: the page's calls, through the local pages or
// the Vault (CONTRACT.md, Local pages); no MCP tool reaches them.
// SubmitApproval only relays an assertion the person's page made, and the
// store verifies the signature.
type Proofs interface {
	SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error)
	// RevealHeld checks the person's reveal proof for a held write,
	// re-runs it in a preview that rolls back and reads its hidden rows.
	RevealHeld(ctx context.Context, id uuid.UUID, held HeldRun, proof passkey.Assertion, key []byte) ([]approval.RevealedRow, error)
}

// Store is a store with all three sides of a held write, as the wiring
// builds a StoreSet from it.
type Store interface {
	Records
	Holds
	Proofs
}

// missingPorts names the ports of set that are nil.
func (set StoreSet) missingPorts() []string {
	var out []string
	if set.Records == nil {
		out = append(out, "Records")
	}
	if set.Holds == nil {
		out = append(out, "Holds")
	}
	if set.Proofs == nil {
		out = append(out, "Proofs")
	}
	return out
}
