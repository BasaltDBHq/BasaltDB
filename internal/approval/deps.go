package approval

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
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

// Deps is what held writes use besides the store set: the ledger's values
// the agent maps to tool errors and the pages' column order.
type Deps struct {
	// ErrNotFound is the ledger's answer for an approval the role does not
	// hold.
	ErrNotFound error
	// SortSpec whitelists the approval list sort.
	SortSpec pagination.SortSpec
	// Columns reads each table's columns in table order for the pages;
	// optional, and the pages show the order the rows carry when nil.
	Columns linksvc.ColumnOrder
}
