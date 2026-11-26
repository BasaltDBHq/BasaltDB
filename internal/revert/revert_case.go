package revert

import (
	"context"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Service is the revert use case: previewing, planning, requesting, applying,
// rescoping, rejecting and revealing a revert. It holds a reference to the
// shared core group and to its own RevertDeps, holds a copy of the revert's
// store set, and owns the reverts the person
// rescoped through this engine. What it needs from the other use cases it names
// as small ports of its own.
type Service struct {
	core     Core
	store    StoreSet
	deps     *Deps
	runs     RunFinder
	delivery Delivery
	describe Describe
	admit    Admitter
	// rescopes are the reverts the person rescoped through this engine, in
	// memory only (CONTRACT.md, Rescope, widen and reject).
	rescopes *rescopes
}

// New returns the service over core and the revert's store set. It panics
// on a set with a nil port, since the service reads the store only through
// them, and on a set without a prepare time limit, which a store may read
// as no limit at all.
func New(core Core, store StoreSet, deps *Deps, runs RunFinder, delivery Delivery, describe Describe, admit Admitter) *Service {
	if missing := store.missingPorts(); len(missing) > 0 {
		panic("revert: store set missing ports: " + strings.Join(missing, ", "))
	}
	if store.Limits.Prepare <= 0 {
		panic("revert: store set has no prepare time limit")
	}
	return &Service{core: core, store: store, deps: deps, runs: runs, delivery: delivery, describe: describe, admit: admit, rescopes: newRescopes()}
}

// ListOpenReverts lists the role's PENDING and APPLYING reverts, for the
// approval use case's pending list.
func (rc *Service) ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	return rc.store.Records.ListOpenReverts(ctx, p)
}
