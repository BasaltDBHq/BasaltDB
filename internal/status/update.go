// Package status is the engine's status for a person and an agent: here,
// the newer-release notice the CLI prints (CONTRACT.md, Update notice).
package status

import (
	"errors"
	"io/fs"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// The newer-release notice (CONTRACT.md, Update notice): every command but
// the long-running ones prints one line on stderr when a newer release is
// out. The line comes from a cache refreshed at most once a day; the
// refresh runs beside the command and the command waits for it only
// briefly, so an offline machine never stalls.

// RefreshGrace is the longest a finished command waits for the refresh.
const RefreshGrace = time.Second

// NoUpdateLine are the commands that print no notice: the engine and the
// MCP server run for long and tell agents through MCP, help is a page.
var NoUpdateLine = []string{"engine", "mcp", "help", "-h", "--help"}

// Host is what the update check reads from the environment and the build:
// the environment's off switch and the version of a build with no release
// number.
type Host interface {
	// UpdateDisabled reports whether the environment turns the check off.
	UpdateDisabled(getenv func(string) string) bool
	// UpdateDevVersion is the version of a build with no release number.
	UpdateDevVersion() string
}

// Terminal is the engine config a command would read by default, as the
// CLI shell finds and reads it.
type Terminal interface {
	// Euid is the effective user id.
	Euid() int
	// DiscoverConfig is the engine.json a command finds by itself, system
	// being the system path.
	DiscoverConfig(system string) (string, error)
	// LoadEngineConfigAs reads the engine config at path for a process
	// with effective uid euid.
	LoadEngineConfigAs(euid int, path string) (config.Config, error)
}

// UpdateOff reports whether the check is turned off: the environment, or
// updateCheck OFF in the config a command would read by default. When that
// config exists but this person cannot read it (service mode: engine.json
// is the engine's own, 0600), the check stays off, so an admin's opt-out is
// never overridden by a failed read; the engine's own notice reaches the
// agent. No config at all means nobody opted out.
func UpdateOff(getenv func(string) string, h Host, t Terminal) bool {
	if h.UpdateDisabled(getenv) || buildinfo.Version == h.UpdateDevVersion() {
		return true
	}
	path, derr := t.DiscoverConfig(config.DefaultPath(runtime.GOOS))
	if derr != nil {
		// Two configs: the command itself reports it; the system one decides.
		path = config.DefaultPath(runtime.GOOS)
	}
	cfg, err := t.LoadEngineConfigAs(t.Euid(), path)
	switch {
	case err == nil:
		return !cfg.UpdateCheckOn()
	case errors.Is(err, fs.ErrNotExist):
		return false
	}
	return true
}

// UpdateNotice is the newer-release notice as the CLI prints it: its line
// and whether the newer release is a security fix. Status owns it; the
// update check's own notice is converted where the command table runs.
type UpdateNotice struct {
	Line     string
	Security bool
}
