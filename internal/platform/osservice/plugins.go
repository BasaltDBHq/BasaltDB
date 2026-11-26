package osservice

import (
	"context"
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

	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginpath"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Plugin units (CONTRACT.md, Plugins, Isolation and trust): in service mode
// each local plugin entry runs under its own service unit, as its own OS
// user, listening on its own socket in its own directory. Every name comes
// from the entry's (name, instance), so two entries share none of them.
const (
	// pluginUnitPrefix starts every plugin unit's name and the Linux plugin
	// user's; darwinPluginUserPrefix is the macOS user's
	// (servicespec.PluginUser).
	pluginUnitPrefix       = servicespec.PluginUnitPrefix
	darwinPluginUserPrefix = servicespec.DarwinPluginUserPrefix
	pluginLabelPrefix      = "dev.basaltdb.plugin-"

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

// PluginBase is the service-mode plugin base directory on goos:
// /opt/basalt on Linux, /Library/Basalt on macOS. It holds the
// installed copies, the trust store and the plugins' socket directories.
func PluginBase(goos string) (string, error) {
	root, err := pluginpath.Root(pluginmodel.ModeService, goos, "")
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
func NamesFor(goos, name, instance string) (servicespec.PluginNames, error) {
	if !pluginNamePattern.MatchString(name) || !pluginInstancePattern.MatchString(instance) {
		return servicespec.PluginNames{}, errPluginKey
	}
	if goos != goosLinux && goos != goosDarwin {
		return servicespec.PluginNames{}, fmt.Errorf("plugin units install on linux and darwin, not %s", goos)
	}
	run, err := PluginRunDir(goos)
	if err != nil {
		return servicespec.PluginNames{}, err
	}
	full := name + "-" + instance
	n := servicespec.PluginNames{User: servicespec.PluginUser(goos, name, instance)}
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

// commandPath is p's command's absolute path inside the copy.
func commandPath(p servicespec.PluginEntry) string {
	return filepath.Join(p.Dir, filepath.FromSlash(p.Command))
}

// memoryMB is p's memory limit: its manifest's, or the default.
func memoryMB(p servicespec.PluginEntry) int {
	if p.MemoryMB > 0 {
		return p.MemoryMB
	}
	return defaultPluginMemoryMB
}

// errUnsafeArg: a value that could change a unit's meaning if written into
// it (a line break, another control character, invalid UTF-8, a lone ';').
var errUnsafeArg = errors.New("holds a character a service unit cannot carry safely")

// validateEntry refuses an entry whose names or paths a unit cannot carry.
func validateEntry(p servicespec.PluginEntry) error {
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

// validateHost refuses a host whose user or paths a unit cannot carry.
func validateHost(h servicespec.PluginHost) error {
	if h.EngineUser == "" || h.EngineUser == rootUser {
		return errors.New("plugin units need the engine's own OS user, not root")
	}
	for _, p := range hidden(h) {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s is not an absolute path", p)
		}
		if err := checkUnitValue(p); err != nil {
			return fmt.Errorf("path %w", err)
		}
	}
	return nil
}

// hidden are the paths h's plugin units make inaccessible.
func hidden(h servicespec.PluginHost) []string { return append(hiddenDirs(h), hiddenFiles(h)...) }

// hiddenDirs are the config directory and the engine's state and socket
// directories, each once.
func hiddenDirs(h servicespec.PluginHost) []string {
	return uniquePaths(nil, h.ConfigDir, h.StateDir, h.SocketDir)
}

// hiddenFiles are the credential files outside the hidden directories,
// each once. A file inside the config directory is hidden with it, so no
// agent's name is written into a unit (units are world-readable), and an
// agent added there leaves every plugin's unit as it is.
func hiddenFiles(h servicespec.PluginHost) []string {
	dirs := hiddenDirs(h)
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

// SystemdPluginUnit renders entry p's Linux unit. The plugin runs as its
// own user from its installed copy, with only its socket directory
// writable, without the config directory, the engine's state and socket
// directories and every credential file, and, with an empty egress,
// without network.
func SystemdPluginUnit(h servicespec.PluginHost, p servicespec.PluginEntry) (string, error) {
	if err := validateEntry(p); err != nil {
		return "", err
	}
	if err := validateHost(h); err != nil {
		return "", err
	}
	n, err := NamesFor(goosLinux, p.Name, p.Instance)
	if err != nil {
		return "", err
	}
	argv := []string{systemdExecWord(commandPath(p))}
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
		SocketEnv, pluginUmask, memoryMB(p), n.SocketDir, n.Socket, servicespec.SystemdUnitName, addressFamilies(p.Egress))
	for _, dir := range hiddenDirs(h) {
		// The directories always exist; a missing one stops the unit.
		fmt.Fprintf(&b, "InaccessiblePaths=%s\n", systemdPath("", dir))
	}
	for _, f := range hiddenFiles(h) {
		// A missing credential file has nothing to hide.
		fmt.Fprintf(&b, "InaccessiblePaths=%s\n", systemdPath("-", f))
	}
	if len(p.Egress) == 0 {
		b.WriteString("PrivateNetwork=yes\n")
	}
	// Enabled with the engine: starting the engine starts it, and it stops
	// and restarts with the engine, so its namespace is built again each
	// time the engine's socket directory is.
	b.WriteString("\n[Install]\nWantedBy=" + servicespec.SystemdUnitName + "\n")
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

// LaunchdPluginDaemon renders entry p's macOS launch daemon. The plugin runs
// as its own user from its installed copy; macOS file modes keep it from the
// engine's files. Its stderr goes to its own log (servicespec.PluginNames.Log), which
// the install makes before the daemon loads, and its network is not
// enforced.
func LaunchdPluginDaemon(h servicespec.PluginHost, p servicespec.PluginEntry) (string, error) {
	if err := validateEntry(p); err != nil {
		return "", err
	}
	if err := validateHost(h); err != nil {
		return "", err
	}
	n, err := NamesFor(goosDarwin, p.Name, p.Instance)
	if err != nil {
		return "", err
	}
	var args strings.Builder
	for _, a := range append([]string{commandPath(p)}, p.Args...) {
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
		int64(memoryMB(p))*bytesPerMB, xmlEscape(n.Log)), nil
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

// PluginUnit is the unit p's entry needs on h.GOOS, byte for byte: what
// install writes, and what the engine compares the installed unit with
// before it connects.
func PluginUnit(h servicespec.PluginHost, p servicespec.PluginEntry) (string, error) {
	return pluginUnit(h, p)
}

// pluginUnit renders p's unit on h.GOOS.
func pluginUnit(h servicespec.PluginHost, p servicespec.PluginEntry) (string, error) {
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
func pluginInstallSteps(sys System, h servicespec.PluginHost, p servicespec.PluginEntry, ids *idAllocator) ([]Step, error) {
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

func pluginEntriesSteps(sys System, h servicespec.PluginHost, ps []servicespec.PluginEntry, ids *idAllocator) ([]Step, error) {
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
