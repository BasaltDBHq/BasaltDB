package app

import (
	"context"

	"github.com/google/uuid"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// approvalDeps is what held writes use: the approval's store, from which
// the wiring builds its store set, and the approval use case's other
// dependencies.
type approvalDeps struct {
	approvalsvc.Deps
	// Store is the approval's store: its ledger records, the agent's holds
	// and the person's proofs.
	Store approvalsvc.Store
	// Columns reads each resource's fields in the store's order for the pages;
	// optional, and the pages show the order the rows carry when nil.
	Columns linksvc.ColumnOrder
}

// approvalStoreSet is the approval's store set: the ports of the
// approval's store. NewService has already refused a store that does not
// check the person's signature itself.
func (s *Service) approvalStoreSet() approvalsvc.StoreSet {
	var set approvalsvc.StoreSet
	if a := s.deps.Approval.Store; a != nil {
		set.Records, set.Holds, set.Proofs = a, a, a
	}
	return set
}

// noApprovalStore is the approval store of an agent served without a
// database (newGuide): its error guidance never reaches the store, and a
// call that did would panic, as on a nil store.
type noApprovalStore struct{ approvalsvc.Store }

// approvalReads answers the delivery use case's reads of the approval
// records, the four linksvc.ApprovalReads declares: the passkeys and a held
// write from the approval's store, and the resources' field order from the
// column-order adapter.
type approvalReads struct {
	records approvalsvc.Records
	columns linksvc.ColumnOrder
}

var _ linksvc.ApprovalReads = approvalReads{}

func (r approvalReads) Passkeys(ctx context.Context) ([]passkey.Credential, error) {
	return r.records.Passkeys(ctx)
}

func (r approvalReads) FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	return r.records.FindApproval(ctx, id)
}

func (r approvalReads) HasColumns() bool { return r.columns != nil }

func (r approvalReads) ColumnOrder(ctx context.Context, resources []string) (map[string][]string, error) {
	return r.columns.ColumnOrder(ctx, resources)
}
