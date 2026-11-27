package guidance

import (
	"sync"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

var catalog = sync.OnceValue(func() mcpcontract.NextSteps {
	c, err := mcpcontract.LoadNextSteps()
	if err != nil {
		panic(err) // the catalog is embedded: a failure is a build defect
	}
	return c
})

// Catalog is the next steps catalog (api/mcp/errors/next-steps.json), loaded
// once.
func Catalog() mcpcontract.NextSteps { return catalog() }

// Reasons of the catalog (api/mcp/errors/next-steps.json) the engine sets
// itself, beyond the ones ToolError reads from the guard.
const (
	ReasonHeld                = "HELD"
	ReasonHeldNoPages         = "HELD_NO_PAGES"
	ReasonNoPasskey           = "NO_PASSKEY"
	ReasonWaitEnded           = "WAIT_ENDED"
	ReasonNoRowsNow           = "NO_ROWS_NOW"
	ReasonAlreadyUsed         = action.ReasonAlreadyUsed
	ReasonDifferentWrite      = action.ReasonDifferentWrite
	ReasonNotThisAgent        = action.ReasonNotThisAgent
	ReasonLineInvalid         = action.ReasonLineInvalid
	ReasonPlanNotSigned       = action.ReasonPlanNotSigned
	ReasonDatabaseUnreachable = action.ReasonDatabaseUnreachable
	ReasonTooManyConnections  = action.ReasonTooManyConnections
	ReasonCredentialRejected  = action.ReasonCredentialRejected
	ReasonGuardMissing        = action.ReasonGuardMissing
	ReasonGuardOutdated       = "GUARD_OUTDATED"
	ReasonEngineUnreachable   = "ENGINE_UNREACHABLE"
	ReasonPagesOff            = "PAGES_OFF"
	ReasonSetupPending        = "SETUP_PENDING"
	ReasonSetupExpired        = "SETUP_EXPIRED"
	ReasonRun                 = "RUN"
	ReasonChange              = "CHANGE"
	ReasonApproval            = "APPROVAL"
	ReasonLink                = "LINK"
	ReasonLinkReset           = "LINK_RESET"

	ToolWrite         = "write"
	ToolQuery         = "query"
	ToolListPending   = "list_pending"
	ToolRequestPlugin = "request_plugin"
	ToolWithdraw      = "withdraw"
	ToolRunHistory    = "run_history"
	ToolPreviewRevert = "preview_revert"
	ArgRunID          = "runId"
	ArgApprovalID     = "approvalId"
	ArgChangeID       = "changeId"
	ArgWaitApproval   = "waitForApproval"
	ToolDescribe      = "describe"
	ArgQuery          = "query"
	ArgResource       = "resource"
)

// Reasons of the error cases request_revert returns (CONTRACT.md, Next
// steps per code).
const (
	ReasonRevert              = "REVERT"
	ReasonBadSignature        = action.ReasonBadSignature
	ReasonPasskeyRevoked      = action.ReasonPasskeyRevoked
	ReasonRowsChanged         = action.ReasonRowsChanged
	ReasonPlanFinished        = action.ReasonPlanFinished
	ReasonNotSigned           = action.ReasonNotSigned
	ReasonWithdrawn           = action.ReasonWithdrawn
	ReasonRevealRefused       = action.ReasonRevealRefused
	ReasonNotFinished         = "NOT_FINISHED"
	ReasonReadsOnly           = "READS_ONLY"
	ReasonAllChangedByPeople  = "ALL_CHANGED_BY_PEOPLE"
	ReasonAlreadyReverted     = "ALREADY_REVERTED"
	ToolRequestRevert         = "request_revert"
	ToolRevertPlan            = "revert_plan"
	ToolApplyRevertBatch      = "apply_revert_batch"
	ToolListRuns              = "list_runs"
	ArgRevertID               = "revertId"
	ArgWaitForSignature       = "waitForSignature"
	StepEndTurnPersonActsNext = "End your turn: the person acts next."
)

// ReasonDatabaseNotConfirmed: the engine collected the database's
// address and the person has not confirmed it yet.
const ReasonDatabaseNotConfirmed = "DATABASE_NOT_CONFIRMED"

const ToolStatus = "status"
