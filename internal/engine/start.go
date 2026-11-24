package engine

import (
	"fmt"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// StateDirMode keeps the engine's state to its own OS user.
const StateDirMode = 0o700

// AgentOSUIDs is the uid of every configured agent's OS user, by agent
// name. An OS user that does not resolve stops the engine: the person
// socket must never mistake an agent's user for the person (fail closed).
func AgentOSUIDs(agents []config.Agent, lookup func(string) (uint32, error)) (map[string]uint32, error) {
	out := make(map[string]uint32, len(agents))
	for _, a := range agents {
		uid, err := lookup(a.OSUser)
		if err != nil {
			return nil, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		out[a.Name] = uid
	}
	return out, nil
}

// EnsureOwnDirs makes and tightens the folders a same-user engine owns: its
// state directory, and its socket directory when every agent's OS user is
// the engine's own (a socket directory other users reach stays 0755). A
// service engine's folders are the service manager's.
func EnsureOwnDirs(cfg config.Config, agentUIDs map[string]uint32, euid int) error {
	if cfg.Service() {
		return nil
	}
	dirs := []string{cfg.StateDirFor(runtime.GOOS)}
	own := true
	for _, uid := range agentUIDs {
		own = own && int(uid) == euid
	}
	if own {
		dirs = append(dirs, cfg.SocketDir)
	}
	return ensurePrivateDirs(euid, dirs...)
}
