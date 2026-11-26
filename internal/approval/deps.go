package approval

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Core is the part of the shared settings the approval use case reads.
type Core struct {
	Name       string
	Log        *slog.Logger
	Now        func() time.Time
	Commands   guidance.Commands
	Errors     guidance.ErrorMap
	PagesBase  string
	LinkBudget int
}

// Deps is what held writes use besides the store set: the ledger's list
// sort.
type Deps struct {
	// SortSpec whitelists the approval list sort.
	SortSpec pagination.SortSpec
}
