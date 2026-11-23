package guidance

import "time"

// Kinds of list_pending items (owner decision LP-1).
const (
	KindApproval = "APPROVAL"
	KindRevert   = "REVERT"
)

// DefaultApprovalWait is how long a write with approvalId waits for the
// person's signature when the call does not say (CONTRACT.md, Waiting
// write), under the 2 minutes after which Claude Code moves a tool call to
// the background.
const DefaultApprovalWait = 90 * time.Second
