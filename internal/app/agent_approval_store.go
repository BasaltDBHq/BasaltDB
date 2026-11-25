package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// approvalDeps is what held writes use: the approval's store, from which
// the wiring builds its store set, and the approval use case's other
// dependencies.
type approvalDeps struct {
	approvalsvc.Deps
	// Store is the approval's store: its ledger records, the agent's holds
	// and the person's proofs.
	Store approvalAdapter
}

// approvalAdapter is the approval's store as the store adapter serves it:
// the approval's records and holds ports, and the person's proofs with a
// reveal that takes the held run's parts, since an adapter cannot name the
// approval's own types.
type approvalAdapter interface {
	approvalsvc.Records
	approvalsvc.Holds
	SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error)
	RevealHeld(ctx context.Context, id uuid.UUID, in action.Intent, req approval.HeldRequest, proof passkey.Assertion, key []byte) ([]approval.RevealedRow, error)
}

// approvalProofs is the approval's Proofs port over the approval's store.
type approvalProofs struct{ store approvalAdapter }

func (p approvalProofs) SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	return p.store.SubmitApproval(ctx, id, a)
}

func (p approvalProofs) RevealHeld(ctx context.Context, id uuid.UUID, held approvalsvc.HeldRun, proof passkey.Assertion, key []byte) ([]approval.RevealedRow, error) {
	return p.store.RevealHeld(ctx, id, held.Intent, held.Request, proof, key)
}

// approvalStoreSet is the approval's store set: the kind and capabilities
// of the agent's store and the ports of the approval's store.
func (s *Service) approvalStoreSet() approvalsvc.StoreSet {
	var set approvalsvc.StoreSet
	if st := s.deps.Core.Store; st != nil {
		set.Kind, set.Capabilities = st.Kind(), st.Capabilities()
	}
	if a := s.deps.Approval.Store; a != nil {
		set.Records, set.Holds, set.Proofs = a, a, approvalProofs{a}
	}
	return set
}

// noApprovalStore is the approval store of an agent served without a
// database (newGuide): its error guidance never reaches the store, and a
// call that did would panic, as on a nil store.
type noApprovalStore struct{ approvalAdapter }
