package mcp

import "github.com/basaltdbhq/basaltdb/internal/core/toolresult"

// The agent-facing result types live in core/toolresult. They are true
// aliases, so *mcp.ToolError and *toolresult.ToolError are one type.
type (
	ToolError      = toolresult.ToolError
	NextStep       = toolresult.NextStep
	Link           = toolresult.Link
	ApprovalNotice = toolresult.ApprovalNotice
	Warning        = toolresult.Warning
)

const (
	ActorAgent  = toolresult.ActorAgent
	ActorPerson = toolresult.ActorPerson

	ActionCallTool            = toolresult.ActionCallTool
	ActionReviseCall          = toolresult.ActionReviseCall
	ActionRetrySmallerBatches = toolresult.ActionRetrySmallerBatches
	ActionAskPerson           = toolresult.ActionAskPerson
	ActionEndTurn             = toolresult.ActionEndTurn
	ActionStop                = toolresult.ActionStop
	ActionOpenLink            = toolresult.ActionOpenLink
	ActionRunCommand          = toolresult.ActionRunCommand
	ActionTellAgent           = toolresult.ActionTellAgent
	ActionSendRequest         = toolresult.ActionSendRequest

	WarningRLSHidesRows          = toolresult.WarningRLSHidesRows
	WarningGuardUpgradeAvailable = toolresult.WarningGuardUpgradeAvailable
)

// DocsURL is the docs page anchor for an error code.
func DocsURL(code string) string { return toolresult.DocsURL(code) }
