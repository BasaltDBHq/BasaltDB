package action

import (
	"time"

	"github.com/google/uuid"
)

// What the withdraw tool withdraws (CONTRACT.md, MCP tools, withdraw).
const (
	WithdrawHeldWrite      = "APPROVAL"
	WithdrawRevert         = "REVERT"
	WithdrawPluginApproval = "PLUGIN_APPROVAL"
)

// Withdrawal is the answer of a withdraw: the item, of Kind, as the store
// records it after the call. Status is WITHDRAWN when the agent withdrew it,
// now or earlier, and otherwise the status it kept: it was no longer waiting
// for the person, and nothing changed.
type Withdrawal struct {
	Kind   string
	ID     uuid.UUID
	Status string
	// WithdrawnAt and Reason are set on a WITHDRAWN item: when it was
	// withdrawn and the reason the agent gave.
	WithdrawnAt *time.Time
	Reason      string
	// Name and Instance name the plugin of a plugin approval.
	Name, Instance string
}

// Withdrawn reports whether the item reads WITHDRAWN.
func (w Withdrawal) Withdrawn() bool { return w.Status == ApprovalWithdrawn }
