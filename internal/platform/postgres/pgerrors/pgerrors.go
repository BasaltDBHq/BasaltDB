// Package pgerrors is the agent's error map filled with the Postgres
// adapters' error values: the one copy the engine wires and the tests use.
package pgerrors

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
)

// Map is the adapters' error values the agent maps to tool errors.
func Map() guidance.ErrorMap {
	return guidance.ErrorMap{
		InvalidParams: ledger.ErrInvalidParams,
		InvalidIntent: guard.ErrInvalidIntent,
		RowTooLarge: func(err error) (string, bool) {
			var rl *resultsize.RowTooLargeError
			if errors.As(err, &rl) {
				return rl.Error(), true
			}
			return "", false
		},
	}
}
