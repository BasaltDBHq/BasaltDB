package approval

import (
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Core is the part of the shared settings the approval use case reads,
// the same as the revert use case's.
type Core = guidance.HeldCore

// Deps is what held writes use besides the store set: the ledger's list
// sort.
type Deps struct {
	// SortSpec whitelists the approval list sort.
	SortSpec pagination.SortSpec
}
