package osservice

import "github.com/basaltdbhq/basaltdb/internal/core/guidance"

// Manager is the host's service manager, for the agent's commands: the one
// copy the engine wires and the tests use.
func Manager() guidance.ServiceManager {
	return guidance.ServiceManager{StartCommand: StartCommand, RestartArgs: RestartArgs}
}
