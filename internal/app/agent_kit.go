package app

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// newCommands returns the commands for agent. configPath is the absolute
// path the engine was started with ("" when the default); goos picks the
// default path and the service manager (runtime.GOOS when empty); manager
// is the service manager's commands.
func newCommands(agent, configPath, goos string, manager guidance.ServiceManager) (guidance.Commands, error) {
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
