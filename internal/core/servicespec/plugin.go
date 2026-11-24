package servicespec

import (
	"crypto/sha256"
	"encoding/hex"
)

// Plugin users (CONTRACT.md, Plugins, Isolation and trust): in service mode
// each local plugin entry runs as its own OS user, named from its (name,
// instance), so two entries never share one.
const (
	// PluginUnitPrefix starts every plugin unit's name and the Linux plugin
	// user's; DarwinPluginUserPrefix is the macOS user's (system accounts
	// start with '_').
	PluginUnitPrefix       = "basalt-plugin-"
	DarwinPluginUserPrefix = "_basalt-plugin-"

	// maxPluginUser is the longest plugin user name Basalt makes, on both
	// OSes: useradd's limit on Linux, and a cap well inside what macOS tools
	// show in full.
	maxPluginUser = 32
	// pluginNameHashHex is how many hex digits of the entry's hash a
	// shortened user name keeps.
	pluginNameHashHex = 12

	goosDarwin = "darwin"
)

// PluginNames are the names and paths of one local entry's unit, user and
// socket.
type PluginNames struct {
	// Unit is the systemd unit (basalt-plugin-<name>-<instance>.service) on
	// Linux and the launchd label (dev.basaltdb.plugin-<name>-<instance>) on
	// macOS. It is never shortened, so it records the entry's real name.
	Unit string
	// UnitPath is the unit file or the launch daemon's plist.
	UnitPath string
	// User is the entry's OS user and group: basalt-plugin-<name>-<instance>
	// on Linux, _basalt-plugin-<name>-<instance> on macOS, shortened by
	// PluginUser when longer than 32 characters.
	User string
	// SocketDir is <base>/run/<User>; Socket is the socket in it.
	SocketDir string
	Socket    string
	// Log is the file the plugin's stderr goes to and LogRule the newsyslog
	// rule that caps it: on macOS only, empty on Linux, where stderr goes to
	// the journal under the unit.
	Log, LogRule string
}

// PluginUser is the OS user of entry (name, instance) on goos: the prefix,
// the name, '-', the instance. When that is longer than 32 characters it is
// shortened to the prefix, the start of "<name>-<instance>", '-', '0' and
// the first 12 hex digits of the SHA-256 of "<name>/<instance>". An
// unshortened name always ends in its instance, which starts with a letter,
// so a shortened one (ending in '0' and hex digits after the last '-') never
// equals one.
func PluginUser(goos, name, instance string) string {
	prefix := PluginUnitPrefix
	if goos == goosDarwin {
		prefix = DarwinPluginUserPrefix
	}
	full := name + "-" + instance
	if len(prefix)+len(full) <= maxPluginUser {
		return prefix + full
	}
	sum := sha256.Sum256([]byte(name + "/" + instance))
	tail := "-0" + hex.EncodeToString(sum[:])[:pluginNameHashHex]
	keep := maxPluginUser - len(prefix) - len(tail)
	return prefix + full[:keep] + tail
}

// PluginEntry is one local plugin entry its unit runs: the installed copy
// it runs from and what its manifest says to run.
type PluginEntry struct {
	Name, Instance string
	// Dir is the installed copy's directory, absolute; the command runs
	// there and finds its files there.
	Dir string
	// Command is the manifest's endpoint.local.command, relative to Dir;
	// Args are its endpoint.local.args.
	Command string
	Args    []string
	// Egress is the manifest's network.egress: empty runs the plugin without
	// network on Linux (network: ENFORCED).
	Egress []string
	// MemoryMB is the manifest's resources.memoryMB; 0 is 1024.
	MemoryMB int
	// Enabled starts the unit; a disabled entry's unit is written and
	// stays stopped.
	Enabled bool
}

// PluginHost is what a plugin's unit keeps from the plugin, and who may
// reach its socket.
type PluginHost struct {
	GOOS string
	// EngineUser is the engine's OS user; its group, of the same name, is
	// the socket directory's group.
	EngineUser string
	// Hidden are the paths the plugin can never reach on Linux: the config
	// directory, the engine's state and socket directories and every
	// credential file.
	ConfigDir, StateDir, SocketDir string
	CredentialFiles                []string
}
