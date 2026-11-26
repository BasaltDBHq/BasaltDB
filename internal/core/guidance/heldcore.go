package guidance

import (
	"log/slog"
	"time"
)

// HeldCore is what the approval and revert use cases read of the agent's
// shared settings: who the agent is, the log and clock, the commands the
// person runs, how errors map to the contract, where the pages are and the
// longest long link. Each takes a copy when it is built.
type HeldCore struct {
	Name       string
	Log        *slog.Logger
	Now        func() time.Time
	Commands   Commands
	Errors     ErrorMap
	PagesBase  string
	LinkBudget int
}
