package app

import (
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// revertDeps is what reverts use: the revert's store, from which the
// wiring builds its store set, and the revert use case's other
// dependencies.
type revertDeps struct {
	revertsvc.Deps
	// Store is the revert's store: its ledger records, the agent's undo
	// and the person's proofs.
	Store revertsvc.Store
}

// revertStoreSet is the revert's store set: the kind and capabilities of
// the agent's store, the ports of the revert's store, and the store's time
// limits. Postgres is the only store built: its prepare runs under the
// limit of one MCP call.
func (s *Service) revertStoreSet() revertsvc.StoreSet {
	set := revertsvc.StoreSet{Limits: revertsvc.Limits{Prepare: guardmodel.MCPPrepareTimeout}}
	if r := s.deps.Revert.Store; r != nil {
		set.Records, set.Undo, set.Proofs = r, r, r
	}
	return set
}

// noRevertStore is the revert store of an agent served without a database
// (newGuide): its error guidance never reaches the store, and a call that
// did would panic, as on a nil store.
type noRevertStore struct{ revertsvc.Store }
