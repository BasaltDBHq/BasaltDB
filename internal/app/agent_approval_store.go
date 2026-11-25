package app

import (
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
)

// approvalDeps is what held writes use: the approval's store, from which
// the wiring builds its store set, and the approval use case's other
// dependencies.
type approvalDeps struct {
	approvalsvc.Deps
	// Store is the approval's store: its ledger records, the agent's holds
	// and the person's proofs.
	Store approvalsvc.Store
}

// approvalStoreSet is the approval's store set: the kind and capabilities
// of the agent's store and the ports of the approval's store.
func (s *Service) approvalStoreSet() approvalsvc.StoreSet {
	var set approvalsvc.StoreSet
	if st := s.deps.Core.Store; st != nil {
		set.Kind, set.Capabilities = st.Kind(), st.Capabilities()
	}
	if a := s.deps.Approval.Store; a != nil {
		set.Records, set.Holds, set.Proofs = a, a, a
	}
	return set
}

// noApprovalStore is the approval store of an agent served without a
// database (newGuide): its error guidance never reaches the store, and a
// call that did would panic, as on a nil store.
type noApprovalStore struct{ approvalsvc.Store }
