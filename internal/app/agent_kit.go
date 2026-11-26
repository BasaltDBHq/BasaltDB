package app

import (
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// newCommands returns the commands for agent (config.AgentCommands).
func newCommands(agent, configPath, goos string, manager guidance.ServiceManager) (guidance.Commands, error) {
	return config.AgentCommands(agent, configPath, goos, manager)
}
