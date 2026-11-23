package guardmodel

import (
	"errors"
	"time"
)

// Prepare time limits (agent-assisted revert design, Preparing). The
// person's CLI may take minutes on a large scope; an MCP call stays under
// the 2 minutes after which Claude Code moves a tool call to the
// background.
const (
	CLIPrepareTimeout = 10 * time.Minute
	MCPPrepareTimeout = 100 * time.Second
)

// ErrPrepareTimeout is a timeout shorter than the millisecond
// statement_timeout counts in, where 0 would mean no limit at all.
var ErrPrepareTimeout = errors.New("guard: a prepare timeout must be at least 1 ms")

// Outcomes of a batched plan's lines (CONTRACT.md, Revert, Large plans).
const (
	OutcomePending  = "PENDING"
	OutcomeRestored = "RESTORED"
	OutcomeSkipped  = "SKIPPED"
)
