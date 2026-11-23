package agent

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agentkit"
)

// The shared vocabulary moved to agentkit; these keep the names the package and its
// callers use.

type (
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

// NewCommands returns the commands for agent. configPath is the absolute
// path the engine was started with ("" when the default); goos picks the
// default path and the service manager (runtime.GOOS when empty); manager
// is the service manager's commands.
func NewCommands(agent, configPath, goos string, manager guidance.ServiceManager) (guidance.Commands, error) {
	if !config.ValidAgentName(agent) {
		return guidance.Commands{}, fmt.Errorf("%q is not a valid agent name", agent)
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if configPath != "" && !filepath.IsAbs(configPath) {
		return guidance.Commands{}, fmt.Errorf("config path %q must be absolute", configPath)
	}
	return guidance.NewCommands(agent, configPath, config.DefaultPath(goos), goos, manager), nil
}

func approvalExpiredSteps(b *guidance.Steps) {
	agentkit.ApprovalExpiredSteps(b)
}

func tooManyConnectionsMessage(cmds guidance.Commands) string {
	return agentkit.TooManyConnectionsMessage(cmds)
}

func fixSteps(b *guidance.Steps, cmds guidance.Commands, reason string) string {
	return agentkit.FixSteps(b, cmds, reason)
}

func remoteSetupSteps(b *guidance.Steps, cmds guidance.Commands, problem string) string {
	return agentkit.RemoteSetupSteps(b, cmds, problem)
}

func engineUnreachableSteps(b *guidance.Steps, cmds guidance.Commands, tool string) string {
	return agentkit.EngineUnreachableSteps(b, cmds, tool)
}

func setupExpiredSteps(b *guidance.Steps, cmds guidance.Commands) string {
	return agentkit.SetupExpiredSteps(b, cmds)
}

func setupPendingSteps(b *guidance.Steps, cmds guidance.Commands, code, fingerprint string, blocking bool, budget int) (string, []toolresult.Link) {
	return agentkit.SetupPendingSteps(b, cmds, code, fingerprint, blocking, budget)
}
