package approval

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// StoreSet is the approval's store as the approval use case reads it: its
// ports, built by the wiring and copied once when the service is built. The
// service reads the store only through them. The wiring checks the store's
// capabilities before it builds the set: the store must check the person's
// signature itself (InStoreSignatureCheck).
type StoreSet struct {
	Records Records
	Holds   Holds
	Proofs  Proofs
}

// Records reads the ledger of the agent's held writes. It never changes
// data.
type Records interface {
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	ListApprovals(ctx context.Context, p approvalstore.ApprovalListParams) (pagination.Page[action.Approval], error)
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
	// RevealNonce is the reveal nonce of an approval or revert the role
	// holds (approval.KindApprove or approval.KindRevert).
	RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error)
}

// Holds is the agent's side: holding a write for the person's approval.
type Holds interface {
	// Preview runs a held write in a preview that changes nothing and
	// returns its lines and the fields whose new values the person's
	// approval binds. It refuses a write that cannot be run again the same
	// way with an *action.RefusalError (NOT_REPEATABLE), and marks an error
	// of the preview run as *approvalstore.PreviewFailedError; any other error (the
	// store's catalog read failing) comes unmarked.
	Preview(ctx context.Context, in action.Intent, req action.Request) (approvalstore.HeldPreview, error)
	// Hold stores a held write for the person's approval.
	Hold(ctx context.Context, in action.Intent, r approvalstore.HoldRequest) (approvalstore.Held, error)
	// WithdrawApproval withdraws a held write of the agent's while it waits
	// for the person, with the agent's reason: when it was withdrawn, nil
	// when it was no longer waiting (left as it is).
	WithdrawApproval(ctx context.Context, id uuid.UUID, reason string) (*time.Time, error)
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

// Store is a store with all three sides of a held write, which a StoreSet
// can take in each of its ports.
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
