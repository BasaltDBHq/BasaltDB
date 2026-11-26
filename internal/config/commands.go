package config

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// AgentCommands returns the commands the person runs for agent. configPath
// is the absolute path the engine was started with ("" when the default);
// goos picks the default path and the service manager (runtime.GOOS when
// empty); manager is the service manager's commands.
func AgentCommands(agent, configPath, goos string, manager guidance.ServiceManager) (guidance.Commands, error) {
	if !ValidAgentName(agent) {
		return guidance.Commands{}, fmt.Errorf("%q is not a valid agent name", agent)
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if configPath != "" && !filepath.IsAbs(configPath) {
		return guidance.Commands{}, fmt.Errorf("config path %q must be absolute", configPath)
	}
	return guidance.NewCommands(agent, configPath, DefaultPath(goos), goos, manager), nil
}
