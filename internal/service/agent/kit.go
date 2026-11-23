package agent

import (
	"encoding/json"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agentkit"
)

// The shared vocabulary moved to agentkit; these keep the names the package and its
// callers use.

type (
	Commands                  = agentkit.Commands
	ServiceManager            = agentkit.ServiceManager
	Steps                     = agentkit.Steps
	Tool                      = agentkit.Tool
	ArgumentError             = agentkit.ArgumentError
	ErrorMap                  = agentkit.ErrorMap
	SetupError                = agentkit.SetupError
	DatabaseNotConfirmedError = agentkit.DatabaseNotConfirmedError
	PageError                 = agentkit.PageError
	MessageBuilder            = agentkit.MessageBuilder
	MessageBlock              = agentkit.MessageBlock
	Problem                   = agentkit.Problem
	Problems                  = agentkit.Problems
)

const (
	MaxStepTextLength           = agentkit.MaxStepTextLength
	MaxPersonMessageLength      = agentkit.MaxPersonMessageLength
	MaxRetryRows                = agentkit.MaxRetryRows
	MaxWaitSeconds              = agentkit.MaxWaitSeconds
	LabelConnect                = agentkit.LabelConnect
	ConnectStepText             = agentkit.ConnectStepText
	ConnectOnlyStepText         = agentkit.ConnectOnlyStepText
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
	reasonHeld                  = agentkit.ReasonHeld
	reasonHeldNoPages           = agentkit.ReasonHeldNoPages
	reasonNoPasskey             = agentkit.ReasonNoPasskey
	reasonWaitEnded             = agentkit.ReasonWaitEnded
	reasonNoRowsNow             = agentkit.ReasonNoRowsNow
	reasonAlreadyUsed           = agentkit.ReasonAlreadyUsed
	reasonDifferentWrite        = agentkit.ReasonDifferentWrite
	reasonNotThisAgent          = agentkit.ReasonNotThisAgent
	reasonLineInvalid           = agentkit.ReasonLineInvalid
	reasonPlanNotSigned         = agentkit.ReasonPlanNotSigned
	reasonDatabaseUnreachable   = agentkit.ReasonDatabaseUnreachable
	reasonTooManyConnections    = agentkit.ReasonTooManyConnections
	reasonCredentialRejected    = agentkit.ReasonCredentialRejected
	reasonGuardMissing          = agentkit.ReasonGuardMissing
	reasonGuardOutdated         = agentkit.ReasonGuardOutdated
	reasonEngineUnreachable     = agentkit.ReasonEngineUnreachable
	reasonPagesOff              = agentkit.ReasonPagesOff
	reasonSetupPending          = agentkit.ReasonSetupPending
	reasonSetupExpired          = agentkit.ReasonSetupExpired
	reasonRun                   = agentkit.ReasonRun
	reasonChange                = agentkit.ReasonChange
	reasonApproval              = agentkit.ReasonApproval
	reasonLink                  = agentkit.ReasonLink
	reasonLinkReset             = agentkit.ReasonLinkReset
	toolWrite                   = agentkit.ToolWrite
	toolQuery                   = agentkit.ToolQuery
	toolListPending             = agentkit.ToolListPending
	toolRunHistory              = agentkit.ToolRunHistory
	toolPreviewRevert           = agentkit.ToolPreviewRevert
	argRunID                    = agentkit.ArgRunID
	argApprovalID               = agentkit.ArgApprovalID
	argChangeID                 = agentkit.ArgChangeID
	argWaitApproval             = agentkit.ArgWaitApproval
	reasonRevert                = agentkit.ReasonRevert
	reasonBadSignature          = agentkit.ReasonBadSignature
	reasonPasskeyRevoked        = agentkit.ReasonPasskeyRevoked
	reasonRowsChanged           = agentkit.ReasonRowsChanged
	reasonPlanFinished          = agentkit.ReasonPlanFinished
	reasonNotSigned             = agentkit.ReasonNotSigned
	reasonNotFinished           = agentkit.ReasonNotFinished
	reasonReadsOnly             = agentkit.ReasonReadsOnly
	reasonAllChangedByPeople    = agentkit.ReasonAllChangedByPeople
	reasonAlreadyReverted       = agentkit.ReasonAlreadyReverted
	toolRequestRevert           = agentkit.ToolRequestRevert
	toolRevertPlan              = agentkit.ToolRevertPlan
	toolApplyRevertBatch        = agentkit.ToolApplyRevertBatch
	toolListRuns                = agentkit.ToolListRuns
	argRevertID                 = agentkit.ArgRevertID
	argWaitForSignature         = agentkit.ArgWaitForSignature
	stepEndTurnPersonActsNext   = agentkit.StepEndTurnPersonActsNext
	reasonDatabaseNotConfirmed  = agentkit.ReasonDatabaseNotConfirmed
	toolStatus                  = agentkit.ToolStatus
	databaseUnreachableMessage  = agentkit.DatabaseUnreachableMessage
	tooManyConnectionsAsk       = agentkit.TooManyConnectionsAsk
	passkeyInitText             = agentkit.PasskeyInitText
	askAgentForRegisterLinkText = agentkit.AskAgentForRegisterLinkText
)

var (
	ErrStepText = agentkit.ErrStepText
	setupCode   = agentkit.SetupCode
)

func NewCommands(agent, configPath, goos string, manager ServiceManager) (Commands, error) {
	return agentkit.NewCommands(agent, configPath, goos, manager)
}

func shellQuote(s string) string {
	return agentkit.ShellQuote(s)
}

func agentStep(action, text string) toolresult.NextStep {
	return agentkit.AgentStep(action, text)
}

func personStep(action, text string) toolresult.NextStep {
	return agentkit.PersonStep(action, text)
}

func callTool(tool string, args map[string]any, text string) toolresult.NextStep {
	return agentkit.CallTool(tool, args, text)
}

func openLink(url, text string) toolresult.NextStep {
	return agentkit.OpenLink(url, text)
}

func sentence(s string) string {
	return agentkit.Sentence(s)
}

func NewSteps() *Steps {
	return agentkit.NewSteps()
}

func withSendRequest(steps []toolresult.NextStep, f *links.RequestFile) []toolresult.NextStep {
	return agentkit.WithSendRequest(steps, f)
}

func sendRequestText(f *links.RequestFile) string {
	return agentkit.SendRequestText(f)
}

func CheckPersonMessage(message string) error {
	return agentkit.CheckPersonMessage(message)
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

func ConnectLink(code string, budget int) string {
	return agentkit.ConnectLink(code, budget)
}

func ConnectMessage(lead, url, fingerprint string) (string, []toolresult.Link) {
	return agentkit.ConnectMessage(lead, url, fingerprint)
}

func ConnectOnlyMessage(lead, url, fingerprint string) (string, []toolresult.Link) {
	return agentkit.ConnectOnlyMessage(lead, url, fingerprint)
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

func newMessage() *MessageBuilder {
	return agentkit.NewMessage()
}

func plainText(s string) string {
	return agentkit.PlainText(s)
}

func clip(s string, n int) string {
	return agentkit.Clip(s, n)
}

func shown(s string, n int) string {
	return agentkit.Shown(s, n)
}

func fitToSteps(message string, steps []toolresult.NextStep) string {
	return agentkit.FitToSteps(message, steps)
}

func severityRank(s string) int {
	return agentkit.SeverityRank(s)
}

func problemEntry(code string) (mcpcontract.ProblemSteps, bool) {
	return agentkit.ProblemEntry(code)
}

func catalog() mcpcontract.NextSteps {
	return agentkit.Catalog()
}

func approvalExpiredSteps(b *Steps) {
	agentkit.ApprovalExpiredSteps(b)
}

func tooManyConnectionsMessage(cmds Commands) string {
	return agentkit.TooManyConnectionsMessage(cmds)
}

func fixSteps(b *Steps, cmds Commands, reason string) string {
	return agentkit.FixSteps(b, cmds, reason)
}

func remoteSetupSteps(b *Steps, cmds Commands, problem string) string {
	return agentkit.RemoteSetupSteps(b, cmds, problem)
}

func engineUnreachableSteps(b *Steps, cmds Commands, tool string) string {
	return agentkit.EngineUnreachableSteps(b, cmds, tool)
}

func setupExpiredSteps(b *Steps, cmds Commands) string {
	return agentkit.SetupExpiredSteps(b, cmds)
}

func setupPendingSteps(b *Steps, cmds Commands, code, fingerprint string, blocking bool, budget int) (string, []toolresult.Link) {
	return agentkit.SetupPendingSteps(b, cmds, code, fingerprint, blocking, budget)
}
