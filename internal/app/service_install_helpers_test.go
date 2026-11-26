package app

import (
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/osusers"
)

// agentInstall is the agent a service install places (setup.AgentInstall).
type agentInstall = setup.AgentInstall

// serviceInstaller is basalt service install on the real host, as
// engineCLIHost.RunServiceAt runs it.
func serviceInstaller() setup.ServiceInstaller {
	return setup.ServiceInstaller{Host: setupHost{}, Users: osusers.Users{}}
}
