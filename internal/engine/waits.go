package engine

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// WaitsForConfig: a service engine on a first install, started before its
// config exists (CONTRACT.md, The local setup page). It runs as its own OS
// user from the system config path, whose folder the install made, and
// finds no engine.json there yet, in a folder it owns. It then serves only the setup page and
// waits for the config instead of exiting.
func WaitsForConfig(t Terminal, euid int, configPath string) bool {
	return WaitsForConfigAt(t, euid, configPath, config.DefaultPath(runtime.GOOS))
}

// WaitsForConfigAt is WaitsForConfig with the system config path given.
func WaitsForConfigAt(t Terminal, euid int, configPath, systemPath string) bool {
	if euid == 0 || configPath != systemPath {
		return false
	}
	if _, err := os.Lstat(configPath); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	// The install made the folder for this engine's own user: a folder
	// anyone else owns is not this engine's to wait in.
	dir, err := os.Lstat(filepath.Dir(configPath))
	if err != nil || !dir.IsDir() {
		return false
	}
	owner, ok := t.InfoOwnerUID(dir)
	return ok && owner == euid
}

// EnginePath is the absolute path of the engine config, which the engine
// names in the commands it gives the person.
func EnginePath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// SocketAgents are the agents with a socket in dir.
func SocketAgents(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".sock")
		if ok && e.Type()&os.ModeSocket != 0 && config.ValidAgentName(name) {
			names = append(names, name)
		}
	}
	return names
}

// ShimAgent names the agent in status when basalt mcp was given only a
// socket path: the socket's base name.
func ShimAgent(name, socket string) string {
	if name != "" {
		return name
	}
	return strings.TrimSuffix(filepath.Base(socket), ".sock")
}

// SuperviseConfig is the config the supervisor needs (its socket and state
// folders): the config file's, or, for a service engine whose config does
// not exist yet, the defaults its child waits with (WaitsForConfig).
func SuperviseConfig(t Terminal, euid int, configPath string) (config.Config, error) {
	if WaitsForConfig(t, euid, configPath) {
		return config.Config{
			SocketDir: config.DefaultSocketDir(runtime.GOOS), StateDir: config.DefaultStateDir(runtime.GOOS),
		}, nil
	}
	return t.LoadEngineConfigAs(euid, configPath)
}
