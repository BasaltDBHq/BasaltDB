package agent

import (
	"encoding/json"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agentkit"
)

// The shared vocabulary moved to agentkit; these keep the names the package and its
// callers use.

type (
	Commands                  = agentkit.Commands
	ServiceManager            = agentkit.ServiceManager
	Tool                      = agentkit.Tool
	ArgumentError             = agentkit.ArgumentError
	ErrorMap                  = agentkit.ErrorMap
	SetupError                = agentkit.SetupError
	DatabaseNotConfirmedError = agentkit.DatabaseNotConfirmedError
	PageError                 = agentkit.PageError
	Problem                   = agentkit.Problem
	Problems                  = agentkit.Problems
)

const (
	CodeIntentRequired          = agentkit.CodeIntentRequired
	CodeStaleRead               = agentkit.CodeStaleRead
	CodeStatementRefused        = agentkit.CodeStatementRefused
	CodeRowLimitExceeded        = agentkit.CodeRowLimitExceeded
	CodeQueryTimeout            = agentkit.CodeQueryTimeout
	CodeApprovalRequired        = agentkit.CodeApprovalRequired
	CodeApprovalExpired         = agentkit.CodeApprovalExpired
	CodeApprovalInvalid         = agentkit.CodeApprovalInvalid
	CodeNothingToRevert         = agentkit.CodeNothingToRevert
	CodeRevertInvalid           = agentkit.CodeRevertInvalid
	CodeRevertExpired           = agentkit.CodeRevertExpired
	CodePermissionDenied        = agentkit.CodePermissionDenied
	CodeNotFound                = agentkit.CodeNotFound
	CodeSQLError                = agentkit.CodeSQLError
	CodeInvalidArgument         = agentkit.CodeInvalidArgument
	CodeUnavailable             = agentkit.CodeUnavailable
	CodeInternal                = agentkit.CodeInternal
	ReasonTimeLimit             = agentkit.ReasonTimeLimit
	ReasonRowLimit              = agentkit.ReasonRowLimit
	ReasonSizeLimit             = agentkit.ReasonSizeLimit
	ReasonRowTooLarge           = agentkit.ReasonRowTooLarge
	ReasonStaleCursor           = agentkit.ReasonStaleCursor
	ReasonNoPrimaryKey          = agentkit.ReasonNoPrimaryKey
	ReasonNotAllowed            = agentkit.ReasonNotAllowed
	ReasonScopeFilter           = agentkit.ReasonScopeFilter
	ReasonScopeFilterCap        = agentkit.ReasonScopeFilterCap
	personTime                  = agentkit.PersonTime
	databaseUnreachableMessage  = agentkit.DatabaseUnreachableMessage
	tooManyConnectionsAsk       = agentkit.TooManyConnectionsAsk
	passkeyInitText             = agentkit.PasskeyInitText
	askAgentForRegisterLinkText = agentkit.AskAgentForRegisterLinkText
)

var setupCode = agentkit.SetupCode

func NewCommands(agent, configPath, goos string, manager ServiceManager) (Commands, error) {
	return agentkit.NewCommands(agent, configPath, goos, manager)
}

func shellQuote(s string) string {
	return agentkit.ShellQuote(s)
}

func callArgs(raw json.RawMessage) map[string]any {
	return agentkit.CallArgs(raw)
}

func decodeArgs(raw json.RawMessage, v any) error {
	return agentkit.DecodeArgs(raw, v)
}

func timeText(t time.Time) string {
	return agentkit.TimeText(t)
}

func sizeLimitError() *toolresult.ToolError {
	return agentkit.SizeLimitError()
}

func messageTooLarge(tool string, err error, te *toolresult.ToolError) *toolresult.ToolError {
	return agentkit.MessageTooLarge(tool, err, te)
}

func storeError(err error) *action.StoreError {
	return agentkit.StoreError(err)
}

func ledgerCode(err error) (guardmodel.Code, bool) {
	return agentkit.LedgerCode(err)
}

func storeDetail(err error) string {
	return agentkit.StoreDetail(err)
}

func scopeRefusal(err error) (detail, hint string, ok bool) {
	return agentkit.ScopeRefusal(err)
}

func timedOut(err error) bool {
	return agentkit.TimedOut(err)
}

func sentinel(err, target error) bool {
	return agentkit.Sentinel(err, target)
}

func approvalExpiredSteps(b *guidance.Steps) {
	agentkit.ApprovalExpiredSteps(b)
}

func tooManyConnectionsMessage(cmds Commands) string {
	return agentkit.TooManyConnectionsMessage(cmds)
}

func fixSteps(b *guidance.Steps, cmds Commands, reason string) string {
	return agentkit.FixSteps(b, cmds, reason)
}

func remoteSetupSteps(b *guidance.Steps, cmds Commands, problem string) string {
	return agentkit.RemoteSetupSteps(b, cmds, problem)
}

func engineUnreachableSteps(b *guidance.Steps, cmds Commands, tool string) string {
	return agentkit.EngineUnreachableSteps(b, cmds, tool)
}

func setupExpiredSteps(b *guidance.Steps, cmds Commands) string {
	return agentkit.SetupExpiredSteps(b, cmds)
}

func setupPendingSteps(b *guidance.Steps, cmds Commands, code, fingerprint string, blocking bool, budget int) (string, []toolresult.Link) {
	return agentkit.SetupPendingSteps(b, cmds, code, fingerprint, blocking, budget)
}
