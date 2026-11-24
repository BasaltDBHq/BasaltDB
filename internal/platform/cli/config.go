package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// DiscoverConfig is the engine.json a command finds by itself
// (config.Discover): the one at system, else the one in the person's own
// config directory. root has no per-user config: its engine config is the
// system one.
func DiscoverConfig(h Machine, system string) (string, error) {
	user := ""
	if h.Euid() != 0 {
		if base, err := h.UserConfigDir(); err == nil {
			user = config.UserPath(base)
		}
	}
	return config.Discover(system, user)
}

// ConfigOrFallback is the config a person command reads: the --config value,
// or, when --config was not given, PerUserConfigFallback of the default.
// AgentConfigsError is DiscoverConfigFor's error when two engine configs
// exist and the agent is in both or in neither.
type AgentConfigsError struct {
	Agent, System, User string
	InBoth              bool
}

func (e *AgentConfigsError) Error() string {
	if e.InBoth {
		return fmt.Sprintf("agent %q is in both engine configs, %s and %s: remove it from the one you do not use", e.Agent, e.System, e.User)
	}
	return fmt.Sprintf("agent %q is in neither engine config, %s or %s", e.Agent, e.System, e.User)
}

// DiscoverConfigFor is DiscoverConfig for a command that names its agent:
// when two configs exist, the one that holds the agent. It refuses when
// both hold it or neither does. holds says whether the config at a path
// holds the agent. Without an agent the plain rule stays.
func DiscoverConfigFor(h Machine, system, agent string, holds func(path string) bool) (string, error) {
	path, err := DiscoverConfig(h, system)
	var both *config.BothConfigsError
	if agent == "" || !errors.As(err, &both) {
		return path, err
	}
	inSystem, inUser := holds(both.System), holds(both.User)
	switch {
	case inSystem && !inUser:
		return both.System, nil
	case inUser && !inSystem:
		return both.User, nil
	}
	return "", &AgentConfigsError{Agent: agent, System: both.System, User: both.User, InBoth: inSystem}
}

// HoldsAgent says whether cfg lists the agent.
func HoldsAgent(cfg config.Config, agent string) bool {
	return slices.ContainsFunc(cfg.Agents, func(a config.Agent) bool { return a.Name == agent })
}

func ConfigOrFallback(h Machine, fs *flag.FlagSet, path string) string {
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "config" })
	if given {
		return path
	}
	return PerUserConfigFallback(h, path)
}

// PerUserConfigFallback is the config a command reads when --config is not
// given: the system path, unless this is not root, nothing is installed
// there, and init left a config in the user's own config directory.
func PerUserConfigFallback(h Machine, system string) string {
	if h.Euid() == 0 {
		return system
	}
	if _, err := os.Stat(system); !errors.Is(err, fs.ErrNotExist) {
		return system
	}
	base, err := h.UserConfigDir()
	if err != nil {
		return system
	}
	user := filepath.Join(base, config.UserDirName, "engine.json")
	if _, err := os.Stat(user); err != nil {
		return system
	}
	return user
}

// LoadEngineConfig reads the engine config at path for this person CLI.
func LoadEngineConfig(c *IO, path string) (config.Config, error) {
	return LoadEngineConfigAs(c.Shell, c.Host.Euid(), path)
}

// LoadEngineConfigAs reads the engine config at path for a process with
// effective uid euid: config.Load's read, or as root the hardened read
// (loadConfigAsRoot, opening through sh). basalt engine started as root
// reads its config here too.
func LoadEngineConfigAs(sh TrustedOpener, euid int, path string) (config.Config, error) {
	cfg, _, err := ReadEngineConfigAs(sh, euid, path)
	return cfg, err
}

// ReadEngineConfigAs is LoadEngineConfigAs that also returns the bytes it
// read: the engine's plugin watch reads engine.json here on every change,
// with the engine's euid, so as root it gets the same hardened read as the
// engine's start, and compares the bytes that read returned. The bytes are
// nil when the read refused or could not read the file, and set with the
// error when the file was read and does not parse or breaks a rule
// (config.LoadOpenRaw).
func ReadEngineConfigAs(sh TrustedOpener, euid int, path string) (config.Config, []byte, error) {
	if euid != 0 {
		return config.LoadOpenRaw(path, os.Open)
	}
	return loadConfigAsRoot(sh, path)
}

// TrustedOpener opens a file for root without following a link
// (Host.OSOpenTrustedFile): all the hardened config read needs of a Host.
type TrustedOpener interface {
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
}
