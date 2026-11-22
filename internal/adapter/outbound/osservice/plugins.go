package osservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Plugin units (CONTRACT.md, Plugins, Isolation and trust): in service mode
// each local plugin entry runs under its own service unit, as its own OS
// user, listening on its own socket in its own directory. Every name comes
// from the entry's (name, instance), so two entries share none of them.
const (
	// pluginUnitPrefix starts every plugin unit's name and the Linux plugin
	// user's; darwinPluginUserPrefix is the macOS user's (system accounts
	// start with '_').
	pluginUnitPrefix       = "basalt-plugin-"
	darwinPluginUserPrefix = "_basalt-plugin-"
	pluginLabelPrefix      = "dev.basaltdb.plugin-"

	// maxPluginUser is the longest plugin user name Basalt makes, on both
	// OSes: useradd's limit on Linux, and a cap well inside what macOS tools
	// show in full.
	maxPluginUser = 32
	// pluginNameHashHex is how many hex digits of the entry's hash a
	// shortened user name keeps.
	pluginNameHashHex = 12

	// PluginSocketName is the socket's file name in the entry's directory.
	PluginSocketName = "p.sock"
	// pluginRunDirName is the directory under the service base that holds
	// each entry's socket directory.
	pluginRunDirName = "run"
	// pluginSocketDirMode: the plugin's user makes its socket there, the
	// engine's group reaches it, no one else can. The setgid bit gives the
	// socket the engine's group on Linux; macOS does that for every file.
	pluginSocketDirMode = os.ModeSetgid | 0o750
	// pluginUmask leaves the socket readable and writable by the engine's
	// group and closed to others.
	pluginUmask = 0o007
	// defaultPluginMemoryMB is a plugin's memory limit when its manifest
	// sets no resources.memoryMB.
	defaultPluginMemoryMB = 1024

	systemdUnitDir   = "/etc/systemd/system/"
	launchDaemonsDir = "/Library/LaunchDaemons/"

	// darwinPluginLogDir holds each macOS plugin's stderr log: root's, mode
	// 0755, in a directory that is root's too, so only root can put a file
	// or a link in it.
	darwinPluginLogDir = darwinLogDir + "/plugins"
	// newsyslogDir holds the rule that caps each plugin's log; /etc is a
	// root-owned link to /private/etc, which the install follows.
	newsyslogDir = "/etc/newsyslog.d/"
	// pluginLogMode is the log's mode: the plugin's user writes it, root
	// reads it, no one else can.
	pluginLogMode = 0o600
	// pluginLogMaxKB is the size, in KiB, past which newsyslog moves the log
	// aside, and pluginLogKeep how many moved copies it keeps.
	pluginLogMaxKB = 1024
	pluginLogKeep  = 1
	// rotatedSuffix ends the name of the one copy newsyslog moved aside.
	rotatedSuffix = ".0"

	// SocketEnv is the one variable a plugin's unit sets: its socket's path
	// (CONTRACT.md, Plugins, Transports).
	SocketEnv = "BASALT_PLUGIN_SOCKET"
)

// The entry key's patterns (CONTRACT.md, Plugins, Manifest and Config),
// checked again here: every name below is built from them.
var (
	pluginNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	pluginInstancePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// safePathPattern is what a path in a unit may hold without quoting.
	safePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)
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

// PluginBase is the service-mode plugin base directory on goos:
// /opt/basalt on Linux, /Library/Basalt on macOS. It holds the
// installed copies, the trust store and the plugins' socket directories.
func PluginBase(goos string) (string, error) {
	root, err := pluginmodel.Root(pluginmodel.ModeService, goos, "")
	if err != nil {
		return "", err
	}
	return filepath.Dir(root), nil
}

// PluginRunDir is the directory that holds each entry's socket directory.
func PluginRunDir(goos string) (string, error) {
	base, err := PluginBase(goos)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, pluginRunDirName), nil
}

// errPluginKey: a name or instance that breaks its pattern never reaches a
// unit, a user name or a path.
var errPluginKey = errors.New("plugin name or instance is not valid")

// NamesFor are the names of entry (name, instance) on goos.
func NamesFor(goos, name, instance string) (PluginNames, error) {
	if !pluginNamePattern.MatchString(name) || !pluginInstancePattern.MatchString(instance) {
		return PluginNames{}, errPluginKey
	}
	if goos != goosLinux && goos != goosDarwin {
		return PluginNames{}, fmt.Errorf("plugin units install on linux and darwin, not %s", goos)
	}
	run, err := PluginRunDir(goos)
	if err != nil {
		return PluginNames{}, err
	}
	full := name + "-" + instance
	n := PluginNames{User: PluginUser(goos, name, instance)}
	if goos == goosDarwin {
		n.Unit = pluginLabelPrefix + full
		n.UnitPath = launchDaemonsDir + n.Unit + ".plist"
		n.Log = filepath.Join(darwinPluginLogDir, n.User+".log")
		n.LogRule = newsyslogDir + pluginUnitPrefix + full + ".conf"
	} else {
		n.Unit = pluginUnitPrefix + full + ".service"
		n.UnitPath = systemdUnitDir + n.Unit
	}
	n.SocketDir = filepath.Join(run, n.User)
	n.Socket = filepath.Join(n.SocketDir, PluginSocketName)
	return n, nil
}

// PluginUser is the OS user of entry (name, instance) on goos: the prefix,
// the name, '-', the instance. When that is longer than 32 characters it is
// shortened to the prefix, the start of "<name>-<instance>", '-', '0' and
// the first 12 hex digits of the SHA-256 of "<name>/<instance>". An
// unshortened name always ends in its instance, which starts with a letter,
// so a shortened one (ending in '0' and hex digits after the last '-') never
// equals one.
func PluginUser(goos, name, instance string) string {
	prefix := pluginUnitPrefix
	if goos == goosDarwin {
		prefix = darwinPluginUserPrefix
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

// commandPath is the command's absolute path inside the copy.
func (p PluginEntry) commandPath() string {
	return filepath.Join(p.Dir, filepath.FromSlash(p.Command))
}

func (p PluginEntry) memoryMB() int {
	if p.MemoryMB > 0 {
		return p.MemoryMB
	}
	return defaultPluginMemoryMB
}

// errUnsafeArg: a value that could change a unit's meaning if written into
// it (a line break, another control character, invalid UTF-8, a lone ';').
var errUnsafeArg = errors.New("holds a character a service unit cannot carry safely")

func (p PluginEntry) validate() error {
	if !pluginNamePattern.MatchString(p.Name) || !pluginInstancePattern.MatchString(p.Instance) {
		return errPluginKey
	}
	if !safePathPattern.MatchString(p.Dir) || filepath.Clean(p.Dir) != p.Dir {
		return fmt.Errorf("plugin %s-%s: its installed copy's path is not a plain absolute path", p.Name, p.Instance)
	}
	if c := path.Clean(p.Command); c != p.Command || path.IsAbs(c) || c == "." || strings.HasPrefix(c, "../") || c == ".." ||
		!safePathPattern.MatchString("/"+c) {
		return fmt.Errorf("plugin %s-%s: its command is not a plain path inside its copy", p.Name, p.Instance)
	}
	for i, a := range p.Args {
		if err := checkUnitValue(a); err != nil {
			return fmt.Errorf("plugin %s-%s: argument %d %w", p.Name, p.Instance, i+1, err)
		}
	}
	return nil
}

// checkUnitValue refuses a value that is not plain text on one line.
func checkUnitValue(s string) error {
	if !utf8.ValidString(s) || s == ";" {
		return errUnsafeArg
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return errUnsafeArg
		}
	}
	return nil
}

// systemdExecWord quotes one ExecStart word: always in double quotes, with
// '\' and '"' escaped and '%' and '$' doubled, so the service manager reads
// back exactly s, expanding nothing.
func systemdExecWord(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`
}

// systemdPath writes a path for a path list setting (ReadWritePaths,
// InaccessiblePaths) or Environment: as it is when it holds only letters,
// digits and "._/-", else in double quotes with '\' and '"' escaped and '%'
// doubled (these settings expand specifiers, not variables). prefix ("-"
// for a path that may be missing) goes inside the word.
func systemdPath(prefix, p string) string {
	if safePathPattern.MatchString(p) {
		return prefix + p
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + prefix + r.Replace(p) + `"`
}

func (h PluginHost) validate() error {
	if h.EngineUser == "" || h.EngineUser == rootUser {
		return errors.New("plugin units need the engine's own OS user, not root")
	}
	for _, p := range h.hidden() {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s is not an absolute path", p)
		}
		if err := checkUnitValue(p); err != nil {
			return fmt.Errorf("path %w", err)
		}
	}
	return nil
}

// hidden are the paths a plugin unit makes inaccessible.
func (h PluginHost) hidden() []string { return append(h.hiddenDirs(), h.hiddenFiles()...) }

// hiddenDirs are the config directory and the engine's state and socket
// directories, each once.
func (h PluginHost) hiddenDirs() []string {
	return uniquePaths(nil, h.ConfigDir, h.StateDir, h.SocketDir)
}

// hiddenFiles are the credential files outside the hidden directories,
// each once. A file inside the config directory is hidden with it, so no
// agent's name is written into a unit (units are world-readable), and an
// agent added there leaves every plugin's unit as it is.
func (h PluginHost) hiddenFiles() []string {
	dirs := h.hiddenDirs()
	var files []string
	for _, f := range h.CredentialFiles {
		if !slices.ContainsFunc(dirs, func(d string) bool { return within(d, f) }) {
			files = append(files, f)
		}
	}
	return uniquePaths(dirs, files...)[len(dirs):]
}

// within reports whether p is dir or lies under it.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func uniquePaths(have []string, more ...string) []string {
	out := slices.Clone(have)
	for _, p := range more {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// PluginNetwork is how a local entry's network is recorded on goos in
// service mode: ENFORCED with an empty egress on Linux (it runs without
// network), DECLARED with a non-empty one, NOT_ENFORCED on macOS.
func PluginNetwork(goos string, egress []string) string {
	switch {
	case goos == goosDarwin:
		return "NOT_ENFORCED"
	case len(egress) == 0:
		return "ENFORCED"
	}
	return "DECLARED"
}

// SystemdPluginUnit renders entry p's Linux unit. The plugin runs as its
// own user from its installed copy, with only its socket directory
// writable, without the config directory, the engine's state and socket
// directories and every credential file, and, with an empty egress,
// without network.
func SystemdPluginUnit(h PluginHost, p PluginEntry) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if err := h.validate(); err != nil {
		return "", err
	}
	n, err := NamesFor(goosLinux, p.Name, p.Instance)
	if err != nil {
		return "", err
	}
	argv := []string{systemdExecWord(p.commandPath())}
	for _, a := range p.Args {
		argv = append(argv, systemdExecWord(a))
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by basalt for plugin %[1]s, instance %[2]s; basalt rewrites it.
[Unit]
Description=BasaltDB plugin %[1]s (instance %[2]s)
StartLimitIntervalSec=0
After=%[11]s
BindsTo=%[11]s
PartOf=%[11]s

[Service]
Type=simple
User=%[3]s
Group=%[3]s
ExecStart=%[4]s
WorkingDirectory=%[5]s
Environment=%[6]s=%[10]s
UMask=%04[7]o
Restart=always
RestartSec=2s
MemoryMax=%[8]dM
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ProtectProc=invisible
ProcSubset=pid
CapabilityBoundingSet=
RestrictNamespaces=yes
RemoveIPC=yes
PrivateIPC=yes
SystemCallFilter=~chmod fchmod fchmodat fchmodat2
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=%[12]s
ReadWritePaths=%[9]s
`, p.Name, p.Instance, n.User, strings.Join(argv, " "), p.Dir,
		SocketEnv, pluginUmask, p.memoryMB(), n.SocketDir, n.Socket, SystemdUnitName, addressFamilies(p.Egress))
	for _, dir := range h.hiddenDirs() {
		// The directories always exist; a missing one stops the unit.
		fmt.Fprintf(&b, "InaccessiblePaths=%s\n", systemdPath("", dir))
	}
	for _, f := range h.hiddenFiles() {
		// A missing credential file has nothing to hide.
		fmt.Fprintf(&b, "InaccessiblePaths=%s\n", systemdPath("-", f))
	}
	if len(p.Egress) == 0 {
		b.WriteString("PrivateNetwork=yes\n")
	}
	// Enabled with the engine: starting the engine starts it, and it stops
	// and restarts with the engine, so its namespace is built again each
	// time the engine's socket directory is.
	b.WriteString("\n[Install]\nWantedBy=" + SystemdUnitName + "\n")
	return b.String(), nil
}

// addressFamilies are the socket families a plugin may open: Unix sockets
// only with an empty egress, the internet too with a non-empty one.
func addressFamilies(egress []string) string {
	if len(egress) == 0 {
		return "AF_UNIX"
	}
	return "AF_UNIX AF_INET AF_INET6"
}

// UserClash is the first other entry in others whose OS user is the same
// as entry (name, instance)'s on Linux or macOS, or nil. Two entries never
// share a user: basalt plugin add refuses one that would.
func UserClash(name, instance string, others []pluginmodel.EntryKey) *pluginmodel.EntryKey {
	for _, o := range others {
		if o.Name == name && o.Instance == instance {
			continue
		}
		for _, goos := range []string{goosLinux, goosDarwin} {
			if PluginUser(goos, o.Name, o.Instance) == PluginUser(goos, name, instance) {
				return &o
			}
		}
	}
	return nil
}

// LaunchdPluginDaemon renders entry p's macOS launch daemon. The plugin runs
// as its own user from its installed copy; macOS file modes keep it from the
// engine's files. Its stderr goes to its own log (PluginNames.Log), which
// the install makes before the daemon loads, and its network is not
// enforced.
func LaunchdPluginDaemon(h PluginHost, p PluginEntry) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if err := h.validate(); err != nil {
		return "", err
	}
	n, err := NamesFor(goosDarwin, p.Name, p.Instance)
	if err != nil {
		return "", err
	}
	var args strings.Builder
	for _, a := range append([]string{p.commandPath()}, p.Args...) {
		args.WriteString("\n\t\t<string>" + xmlEscape(a) + "</string>")
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%[1]s</string>
	<key>ProgramArguments</key>
	<array>%[2]s
	</array>
	<key>UserName</key>
	<string>%[3]s</string>
	<key>GroupName</key>
	<string>%[3]s</string>
	<key>WorkingDirectory</key>
	<string>%[4]s</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>%[5]s</key>
		<string>%[6]s</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Umask</key>
	<integer>%[7]d</integer>
	<key>StandardErrorPath</key>
	<string>%[9]s</string>
	<key>HardResourceLimits</key>
	<dict>
		<key>ResidentSetSize</key>
		<integer>%[8]d</integer>
	</dict>
</dict>
</plist>
`, n.Unit, args.String(), n.User, xmlEscape(p.Dir), SocketEnv, xmlEscape(n.Socket), pluginUmask,
		int64(p.memoryMB())*bytesPerMB, xmlEscape(n.Log)), nil
}

// NewsyslogPluginRule renders the newsyslog rule that caps macOS entry
// (name, instance)'s stderr log: past 1 MiB newsyslog moves the log to
// <log>.0, dropping the copy moved before, and makes a new empty log owned
// by the plugin's user, mode 0600. N: no process is signaled; B: newsyslog
// writes no turnover line into the new log, which holds only the plugin's
// own output. newsyslog
// checks the size on its own schedule, and launchd opens the log when it
// starts the plugin, so a plugin that keeps running goes on writing to the
// moved copy until it is started again.
func NewsyslogPluginRule(name, instance string) (string, error) {
	n, err := NamesFor(goosDarwin, name, instance)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`# Written by basalt for plugin %[1]s, instance %[2]s; basalt rewrites it.
# logfilename	[owner:group]	mode	count	size	when	flags
%[3]s	%[4]s:%[4]s	%03[5]o	%[6]d	%[7]d	*	NB
`, name, instance, n.Log, n.User, pluginLogMode, pluginLogKeep, pluginLogMaxKB), nil
}

// HostFor is the plugin host of the engine configured by cfg (at
// configPath, on goos), run as engineUser: what its plugin units hide.
func HostFor(cfg config.Config, goos, configPath, engineUser string) PluginHost {
	h := PluginHost{
		GOOS: goos, EngineUser: engineUser, ConfigDir: filepath.Dir(configPath),
		StateDir: cfg.StateDirFor(goos), SocketDir: cfg.SocketDir,
	}
	if h.SocketDir == "" {
		h.SocketDir = config.DefaultSocketDir(goos)
	}
	// Every agent's credential file. A remote entry's auth.credentialFile is
	// not listed: the engine reads it only when it is the engine user's
	// alone (mode 0600 or narrower), so no plugin user can, and listing it
	// would make adding a remote entry change every local entry's unit.
	for _, a := range cfg.Agents {
		h.CredentialFiles = append(h.CredentialFiles, a.Store.CredentialFile)
	}
	return h
}

// EntryFor is config entry p, its installed copy verified as v, as its
// unit runs it; false for a remote entry, which has no unit.
func EntryFor(p config.Plugin, v pluginmodel.Verified) (PluginEntry, bool) {
	l := v.Manifest.Endpoint.Local
	if l == nil {
		return PluginEntry{}, false
	}
	k := p.Key()
	e := PluginEntry{
		Name: k.Name, Instance: k.Instance, Dir: v.Dir, Command: l.Command, Args: l.Args,
		Egress: v.Manifest.Network.Egress, Enabled: p.Enabled,
	}
	if r := v.Manifest.Resources; r != nil {
		e.MemoryMB = r.MemoryMB
	}
	return e, true
}

// PluginUnit is the unit p's entry needs on h.GOOS, byte for byte: what
// install writes, and what the engine compares the installed unit with
// before it connects.
func PluginUnit(h PluginHost, p PluginEntry) (string, error) { return pluginUnit(h, p) }

// pluginUnit renders p's unit on h.GOOS.
func pluginUnit(h PluginHost, p PluginEntry) (string, error) {
	if h.GOOS == goosDarwin {
		return LaunchdPluginDaemon(h, p)
	}
	return SystemdPluginUnit(h, p)
}

// idAllocator hands out macOS ids free as both a uid and a gid, never the
// same one twice in a plan.
type idAllocator struct {
	used map[int]bool
}

func newIDAllocator(ctx context.Context, sys System) (*idAllocator, error) {
	users, err := sys.Output(ctx, "dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	groups, err := sys.Output(ctx, "dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	return &idAllocator{used: usedIDs(users + "\n" + groups)}, nil
}

func (a *idAllocator) next() (int, error) {
	id, err := freeID(a.used)
	if err != nil {
		return 0, err
	}
	a.used[id] = true
	return id, nil
}

// PluginBaseSteps make the plugin base and its run directory, root's and
// 0755, before any plugin's unit, and on macOS the plugins' log directory,
// root's and 0755 too. On Linux a base that cannot be made safely (a
// directory above it that someone other than root can write) fails its
// step, as any other unsafe path does; the engine is already started by
// then. On macOS the plugin steps come before the engine's daemon, so the
// step is skipped with the cause and the engine still installs.
func PluginBaseSteps(goos string) ([]Step, error) {
	base, err := PluginBase(goos)
	if err != nil {
		return nil, err
	}
	run := filepath.Join(base, pluginRunDirName)
	if goos != goosDarwin {
		return []Step{
			{Kind: StepMkdir, Path: base, Mode: openDirMode},
			{Kind: StepMkdir, Path: run, Mode: openDirMode},
		}, nil
	}
	return []Step{
		{Kind: StepMkdir, Path: base, Mode: openDirMode, Note: rootOnlyNote(base)},
		{Kind: StepMkdir, Path: run, Mode: openDirMode, Note: rootOnlyNote(base)},
		{Kind: StepMkdir, Path: darwinPluginLogDir, Mode: openDirMode, Note: rootOnlyNote(darwinPluginLogDir)},
	}, nil
}

// rootOnlyNote is why a macOS plugin base step may be skipped.
func rootOnlyNote(dir string) string {
	return "plugins cannot be installed until every directory above " + dir + " is owned by root and writable by root only"
}

// PluginUserInGroup says that a plugin's OS user is in the engine's group,
// which reaches every plugin socket and the engine's config directory, and
// names the command that takes it out.
func PluginUserInGroup(goos, pluginUser, engineGroup string) string {
	fix := "sudo gpasswd -d " + pluginUser + " " + engineGroup
	if goos == goosDarwin {
		fix = "sudo dseditgroup -o edit -d " + pluginUser + " -t user " + engineGroup
	}
	return "its OS user " + pluginUser + " is in the engine's group " + engineGroup +
		", which reaches every plugin socket and the engine's config; take it out of that group: " + fix
}

// PluginInstallSteps create entry p's OS user when missing, its socket
// directory (the user's, in the engine's group, 02750), on macOS its stderr
// log (the user's, 0600, kept when it exists) and the newsyslog rule that
// caps it, and its unit, then start it when it is enabled and stop it when
// it is not. ids, on macOS, hands out the new user's id.
func pluginInstallSteps(sys System, h PluginHost, p PluginEntry, ids *idAllocator) ([]Step, error) {
	unit, err := pluginUnit(h, p)
	if err != nil {
		return nil, err
	}
	n, err := NamesFor(h.GOOS, p.Name, p.Instance)
	if err != nil {
		return nil, err
	}
	var steps []Step
	if sys.UserExists(n.User) {
		in, err := sys.InGroup(n.User, h.EngineUser)
		if err != nil {
			return nil, fmt.Errorf("plugin %s/%s: the groups of its OS user %s cannot be read, so it cannot be checked: %w", p.Name, p.Instance, n.User, err)
		}
		if in {
			return nil, fmt.Errorf("plugin %s/%s: %s", p.Name, p.Instance, PluginUserInGroup(h.GOOS, n.User, h.EngineUser))
		}
	} else {
		if h.GOOS == goosDarwin {
			id, err := ids.next()
			if err != nil {
				return nil, err
			}
			steps = append(steps, darwinAccountSteps(n.User, strconv.Itoa(id), "BasaltDB plugin "+p.Name+" "+p.Instance)...)
		} else {
			steps = append(steps, run("useradd", "--system", "--user-group", "--no-create-home",
				"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
				"--comment", "BasaltDB plugin "+p.Name+" "+p.Instance, n.User))
		}
	}
	steps = append(steps, Step{Kind: StepMkdir, Path: n.SocketDir, Mode: pluginSocketDirMode, Owner: n.User, Group: h.EngineUser})
	if h.GOOS == goosDarwin {
		rule, err := NewsyslogPluginRule(p.Name, p.Instance)
		if err != nil {
			return nil, err
		}
		label := "system/" + n.Unit
		steps = append(steps,
			// Before the daemon loads, so launchd opens a file the plugin's
			// user owns rather than making one; an existing log is kept.
			Step{Kind: StepCreate, Path: n.Log, Mode: pluginLogMode, Owner: n.User},
			Step{Kind: StepWrite, Path: n.LogRule, Content: rule},
			Step{Kind: StepWrite, Path: n.UnitPath, Content: unit},
			bootout(label),
		)
		if !p.Enabled {
			// A plist in LaunchDaemons loads at boot unless it is disabled.
			return append(steps, run("launchctl", "disable", label)), nil
		}
		return append(steps,
			run("launchctl", "enable", label),
			run("launchctl", "bootstrap", "system", n.UnitPath),
		), nil
	}
	steps = append(steps, Step{Kind: StepWrite, Path: n.UnitPath, Content: unit}, run("systemctl", "daemon-reload"))
	if !p.Enabled {
		return append(steps, tryRun("systemctl", "disable", "--now", n.Unit)), nil
	}
	return append(steps, run("systemctl", "enable", n.Unit), run("systemctl", "restart", n.Unit)), nil
}

// PluginInstallPlan is pluginInstallSteps for each of ps, after the base
// directories (on macOS after the log directory's steps too): what basalt
// plugin add, enable and disable run in service mode for one entry, and
// service install for every local entry.
func PluginInstallPlan(ctx context.Context, sys System, h PluginHost, ps []PluginEntry) ([]Step, error) {
	if len(ps) == 0 {
		return nil, nil
	}
	steps, err := PluginBaseSteps(h.GOOS)
	if err != nil {
		return nil, err
	}
	var ids *idAllocator
	if h.GOOS == goosDarwin {
		if ids, err = newIDAllocator(ctx, sys); err != nil {
			return nil, err
		}
		// A Mac set up by an earlier install has the engine user's log
		// directory: plugin add and enable fix it as service install does,
		// so no separate step is needed before a plugin's log can be made.
		steps = append(darwinLogSteps(h.EngineUser), steps...)
	}
	more, err := pluginEntriesSteps(sys, h, ps, ids)
	if err != nil {
		return nil, err
	}
	return append(steps, more...), nil
}

func pluginEntriesSteps(sys System, h PluginHost, ps []PluginEntry, ids *idAllocator) ([]Step, error) {
	var steps []Step
	seen := map[string]bool{}
	for _, p := range ps {
		n, err := NamesFor(h.GOOS, p.Name, p.Instance)
		if err != nil {
			return nil, err
		}
		if seen[n.User] {
			return nil, fmt.Errorf("plugin %s-%s: two entries would share the OS user %s", p.Name, p.Instance, n.User)
		}
		seen[n.User] = true
		more, err := pluginInstallSteps(sys, h, p, ids)
		if err != nil {
			return nil, err
		}
		steps = append(steps, more...)
	}
	return steps, nil
}

// bootout unloads a launch daemon; one that is not loaded is not an error.
func bootout(label string) Step {
	return Step{Kind: StepRun, Args: []string{"launchctl", "bootout", label}, Note: "it was not loaded"}
}

// PluginStopSteps stop entry (name, instance)'s unit and keep it, its user,
// its directory and, on macOS, its log and log rule: basalt plugin disable
// in service mode.
func PluginStopSteps(goos, name, instance string) ([]Step, error) {
	n, err := NamesFor(goos, name, instance)
	if err != nil {
		return nil, err
	}
	if goos == goosDarwin {
		label := "system/" + n.Unit
		return []Step{bootout(label), run("launchctl", "disable", label)}, nil
	}
	return []Step{tryRun("systemctl", "disable", "--now", n.Unit)}, nil
}

// PluginRemoveSteps stop and delete exactly what pluginInstallSteps made for
// entry (name, instance): its unit, on macOS its log rule, its log and the
// one copy newsyslog moved aside, its socket directory and, when it exists,
// its OS user and group. Names come from the entry, never from a listing.
func PluginRemoveSteps(sys System, goos, name, instance string) ([]Step, error) {
	n, err := NamesFor(goos, name, instance)
	if err != nil {
		return nil, err
	}
	installed := sys.Exists(n.UnitPath)
	hasUser := sys.UserExists(n.User)
	if !installed && !hasUser && !sys.Exists(n.SocketDir) && !hasLog(sys, n) {
		// Nothing of this entry is on the machine (a remote entry).
		return nil, nil
	}
	var steps []Step
	if goos == goosDarwin {
		if installed {
			steps = append(steps, bootout("system/"+n.Unit))
		}
		// The rule before the log, so newsyslog never rotates a log being
		// removed.
		steps = append(steps,
			Step{Kind: StepRemove, Path: n.UnitPath},
			Step{Kind: StepRemove, Path: n.LogRule},
			Step{Kind: StepRemove, Path: n.Log},
			Step{Kind: StepRemove, Path: n.Log + rotatedSuffix},
		)
	} else {
		if installed {
			steps = append(steps, tryRun("systemctl", "disable", "--now", n.Unit))
		}
		steps = append(steps, Step{Kind: StepRemove, Path: n.UnitPath}, tryRun("systemctl", "daemon-reload"))
	}
	steps = append(steps, Step{Kind: StepRemoveTree, Path: n.SocketDir})
	if hasUser {
		if goos == goosDarwin {
			steps = append(steps,
				run("dscl", ".", "-delete", "/Users/"+n.User),
				run("dscl", ".", "-delete", "/Groups/"+n.User),
			)
		} else {
			// useradd --user-group made the group; userdel deletes it with
			// the user.
			steps = append(steps, run("userdel", n.User))
		}
	}
	return steps, nil
}

// hasLog reports whether a macOS entry's log, its moved copy or its rule is
// on the machine; a Linux entry has none.
func hasLog(sys System, n PluginNames) bool {
	if n.Log == "" {
		return false
	}
	return sys.Exists(n.Log) || sys.Exists(n.Log+rotatedSuffix) || sys.Exists(n.LogRule)
}
