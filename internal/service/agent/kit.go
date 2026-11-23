package agent

import (
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agentkit"
)

// The shared vocabulary moved to agentkit; these keep the names the package and its
// callers use.

type (
	Commands                  = agentkit.Commands
	ServiceManager            = agentkit.ServiceManager
	ErrorMap                  = agentkit.ErrorMap
	DatabaseNotConfirmedError = agentkit.DatabaseNotConfirmedError
	Problem                   = agentkit.Problem
	Problems                  = agentkit.Problems
)

const (
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
