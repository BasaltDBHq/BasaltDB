package revert

import (
	"context"
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Core is what the revert use case reads of the agent's shared settings: who
// the agent is, the log and clock, the commands the person runs, how errors map
// to the contract, where the pages are and the longest long link. It is a copy
// taken when the service is built.
type Core struct {
	Name       string
	Log        *slog.Logger
	Now        func() time.Time
	Commands   guidance.Commands
	Errors     guidance.ErrorMap
	PagesBase  string
	LinkBudget int
}

// Deps is what reverts use.
type Deps struct {
	Store Store
	// ErrNotFound is the ledger's answer for a revert the role did not
	// prepare.
	ErrNotFound error
	// AfterAnswer runs f after the answer of the Vault session ctx belongs
	// to (false: there is none). RotateSession moves that session onto
	// token.
	AfterAnswer   func(ctx context.Context, f func()) bool
	RotateSession func(ctx context.Context, token channel.LinkToken) bool
}
