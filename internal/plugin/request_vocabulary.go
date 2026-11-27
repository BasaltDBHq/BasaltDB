package plugin

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// The states of a request_plugin result.
const (
	PluginStatePending  = "PENDING"
	PluginStateApproved = "APPROVED"
	PluginStateRunning  = "RUNNING"
	PluginStateNarrowed = "NARROWED"
	PluginStateRemoved  = "REMOVED"
	PluginStateEnded    = "ENDED"
	// PluginStateWithdrawn is an approval the agent withdrew before the
	// person signed it (the wait form only; PLUGIN_LIST reads it ENDED).
	PluginStateWithdrawn = "WITHDRAWN"
)

// The PLUGIN_REFUSED reasons the tool gives itself, and the one the engine
// gives an agent whose OS user it does not let change plugins (CONTRACT.md,
// Error codes).
const (
	ReasonPluginAgentOperated   = "AGENT_OPERATED"
	ReasonPluginSameUserMode    = "SAME_USER_MODE"
	ReasonPluginNoLocalPages    = "NO_LOCAL_PAGES"
	ReasonPluginNoPortalLink    = "NO_PORTAL_LINK"
	ReasonPluginAgentNotAllowed = "AGENT_NOT_ALLOWED"
)

// PluginOpen is one request to open a plugin approval.
type PluginOpen struct {
	// UploadID is the upload basalt mcp made of the source; nil opens a new
	// approval for the installed copy.
	UploadID    *uuid.UUID
	Name        string
	Instance    string
	Executables []string
	// Agents is the entry's full new list; nil is the default: the caller
	// alone for a new entry, the entry's agents for an existing one.
	Agents []string
}

// PluginOpened is an approval opened, or a narrowing applied.
type PluginOpened struct {
	Name, Instance, Version string
	Agents                  []string
	Narrowed                bool
	ApprovalID              uuid.UUID
	ExpiresAt               time.Time
	BindingText             string
}

// PluginApprovalState is one approval as the wait reads it. State is
// PENDING, APPROVED, RUNNING or ENDED.
type PluginApprovalState struct {
	Name, Instance string
	Agents         []string
	State          string
	ExpiresAt      time.Time
	// WithdrawReason is the agent's reason on a WITHDRAWN approval.
	WithdrawReason string
}

// PluginRefusedError is PLUGIN_REFUSED with its reason, from the engine.
type PluginRefusedError struct {
	Reason, Message string
}

func (r *PluginRefusedError) Error() string { return r.Message }

// ErrPluginNotFound: no entry, or no approval, the caller may reach.
var ErrPluginNotFound = errors.New("the engine keeps no such plugin or plugin approval for this agent")
