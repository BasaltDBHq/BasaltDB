package revert

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Core is what the revert use case reads of the agent's shared settings,
// the same as the approval use case's.
type Core = guidance.HeldCore

// Deps is what reverts use.
type Deps struct {
	// AfterAnswer runs f after the answer of the Vault session ctx belongs
	// to (false: there is none). RotateSession moves that session onto
	// token.
	AfterAnswer   func(ctx context.Context, f func()) bool
	RotateSession func(ctx context.Context, token channel.LinkToken) bool
}
