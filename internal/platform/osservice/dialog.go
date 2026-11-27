package osservice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// The system's administrator dialogs (CONTRACT.md, The administrator
// dialog). Both are run by absolute path, so a program on PATH cannot
// stand in for them.
const (
	osascriptPath = "/usr/bin/osascript"
	pkexecPath    = "/usr/bin/pkexec"
	shPath        = "/bin/sh"

	// pkexecDismissed and pkexecNotAuthorized are pkexec's exit codes when
	// the person closed the dialog, and when no authentication agent
	// answered or the person may not act as root.
	pkexecDismissed     = 126
	pkexecNotAuthorized = 127

	// linuxSysUIDMax is the highest system uid when /etc/login.defs
	// names no SYS_UID_MAX.
	linuxSysUIDMax = 999

	// linuxPluginBase and darwinPluginBase are the plugin base the script
	// makes (PluginBase), and pluginRunDirName the folder of the entries'
	// sockets in it.
	linuxPluginBase  = "/opt/basalt"
	darwinPluginBase = "/Library/Basalt"

	// unitEnd ends the here-document that carries the unit.
	unitEnd = "END_OF_ENGINE_UNIT"
)

// ScriptHelpersEnd marks the end of the install script's helper functions,
// and ScriptPreflightEnd the end of its checks: nothing before it creates
// or changes anything.
const (
	ScriptHelpersEnd   = "# end of helpers\n"
	ScriptPreflightEnd = "# end of checks: nothing above creates anything\n"
)

// ErrDialogScript: the person answered, and the script stopped. The other
// outcomes of a dialog run are servicespec.ErrNoDialog and
// servicespec.ErrDialogCancelled.
var ErrDialogScript = errors.New("the administrator dialog's script stopped")

// safeBinary is what a binary path in the install script may hold: no
// space, quote, backslash, dollar or newline, so it means the same in the
// shell, the unit and the plist without quoting.
var safeBinary = regexp.MustCompile(`^/[A-Za-z0-9._+/-]+$`)

// DialogPaths are the absolute paths of the dialog programs on goos.
func DialogPaths(goos string) ([]string, error) {
	switch goos {
	case goosDarwin:
		return []string{osascriptPath}, nil
	case goosLinux:
		return []string{pkexecPath}, nil
	}
	return nil, fmt.Errorf("the engine service installs on linux and darwin, not %s", goos)
}

// DialogCommand is the command that asks the person, through the system's
// administrator dialog, to run script as root: osascript "with
// administrator privileges" on macOS, showing prompt (the script and the
// prompt are arguments of the AppleScript, never part of its text), pkexec
// on Linux (with no text prompt of its own, so only a desktop's dialog can
// answer; it shows polkit's generic text, not prompt).
func DialogCommand(goos, prompt, script string) ([]string, error) {
	switch goos {
	case goosDarwin:
		return []string{
			osascriptPath, "-e", "on run argv", "-e", "do shell script (item 1 of argv) with prompt (item 2 of argv) with administrator privileges", "-e", "end run", script, prompt,
		}, nil
	case goosLinux:
		return []string{pkexecPath, "--disable-internal-agent", shPath, "-c", script}, nil
	}
	return nil, fmt.Errorf("the engine service installs on linux and darwin, not %s", goos)
}

// DialogError is what a dialog run that exited with code, writing stderr,
// means: nil on success, else ErrNoDialog, ErrDialogCancelled or
// ErrDialogScript with what the dialog said.
func DialogError(goos string, code int, stderr string, runErr error) error {
	if runErr == nil {
		return nil
	}
	said := strings.TrimSpace(stderr)
	switch {
	case goos == goosLinux && code == pkexecDismissed,
		goos == goosDarwin && strings.Contains(said, "(-128)"):
		return servicespec.ErrDialogCancelled
	case goos == goosLinux && code == pkexecNotAuthorized:
		return fmt.Errorf("%w (pkexec: %s)", servicespec.ErrNoDialog, orRunErr(said, runErr))
	case goos == goosDarwin && (strings.Contains(said, "(-1713)") || strings.Contains(said, "(-60007)")):
		return fmt.Errorf("%w (osascript: %s)", servicespec.ErrNoDialog, said)
	}
	return fmt.Errorf("%w: %s", ErrDialogScript, orRunErr(said, runErr))
}

func orRunErr(said string, err error) string {
	if said != "" {
		return said
	}
	return err.Error()
}

// UnitPath is the engine service's unit file on goos.
func UnitPath(goos string) string {
	if goos == goosDarwin {
		return LaunchdPlist
	}
	return SystemdUnitPath
}

// SystemSpec is the engine service every first install starts with: the
// system config path, the engine's own user and the default memory limit.
func SystemSpec(goos, binary string) servicespec.Spec {
	return servicespec.Spec{GOOS: goos, Binary: binary, ConfigPath: config.DefaultPath(goos), User: DefaultUser(goos)}
}

// Source is the basalt binary the install or the restart copies to the
// service's own path (ServiceBinary): the running binary's resolved path,
// and the SHA-256 of what basalt read there before it asked for the
// password, with its size in bytes: the script copies that many bytes and
// no more.
type Source struct {
	Path   string
	SHA256 string
	Size   int64
}

// sha256Hex is a SHA-256 as lowercase hex.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReadSource is path as a Source: its content's SHA-256 and size, read now.
func ReadSource(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return Source{}, fmt.Errorf("read the basalt binary %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return Source{}, fmt.Errorf("read the basalt binary %s: %w", path, err)
	}
	return Source{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

// copies reports whether src is copied to the service's path on goos: it
// is not that path already.
func (src Source) copies(goos string) bool { return src.Path != ServiceBinary(goos) }

// validate refuses a source the script cannot name safely: a relative or
// unclean path, a control character, a SHA-256 that is not lowercase hex,
// or no size.
func (src Source) validate() error {
	if !filepath.IsAbs(src.Path) || filepath.Clean(src.Path) != src.Path || strings.ContainsFunc(src.Path, unicode.IsControl) {
		return fmt.Errorf("the basalt binary's path %q has characters the service install does not take; run basalt from a plain path such as /usr/local/bin/basalt", src.Path)
	}
	if !sha256Hex.MatchString(src.SHA256) {
		return fmt.Errorf("the basalt binary %s has no SHA-256 to check its copy against", src.Path)
	}
	if src.Size <= 0 {
		return fmt.Errorf("the basalt binary %s has no size to copy", src.Path)
	}
	return nil
}

// sourceCheck checks, before anything is created, the folder of the
// service's copy (when it exists) and that its path is no symlink, and that
// the source is a file. A folder above the copy that is not root's alone
// (an older Homebrew layout gives /usr/local to the person's account) stops
// the script with the folder and its owner named (trusted's line) and why;
// the dialog cannot take that folder from its owner, so the message does not
// send the person round to basalt init again.
func sourceCheck(goos string, src Source) string {
	dest := ServiceBinary(goos)
	return fmt.Sprintf(`src=%[1]s
[ -f "$src" ] || fail "$src is not a file"
( trusted %[2]s "" ) ||
	fail "the engine service runs its own copy of basalt at %[3]s, and the folder named above is not one only root can change, so its owner could replace what the service runs. Nothing was changed. The service can be installed once that folder belongs to root and only root can write it; on a Mac whose older Homebrew gave /usr/local to your account, that is a change to your Homebrew setup to make yourself"
no_link %[4]s
`, shellQuote(src.Path), scriptWord(filepath.Dir(dest)), dest, scriptWord(dest))
}

// copyBinary makes the folders of the service's copy root's, copies the
// source there (checked against its SHA-256) and checks the copy as the
// unit will run it.
func copyBinary(goos string, src Source) string {
	dest := ServiceBinary(goos)
	var b strings.Builder
	for _, dir := range serviceBinaryDirs(goos) {
		fmt.Fprintf(&b, "make_root_dir %s %04o\n", scriptWord(dir), openDirMode)
	}
	fmt.Fprintf(&b, "copy_binary \"$src\" %s %s %d\n", scriptWord(dest), src.SHA256, src.Size)
	b.WriteString(binaryCheck(dest))
	return b.String()
}

// serviceBinaryDirs are the folders above the service's copy the script
// makes when they are missing, outermost first.
func serviceBinaryDirs(goos string) []string {
	dir := filepath.Dir(ServiceBinary(goos))
	if goos == goosDarwin {
		return []string{filepath.Dir(dir), dir}
	}
	return []string{dir}
}

// shellQuote is s as one single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// InstallScript is the script the administrator dialog runs on a first
// install, built from constants and the running binary only (its resolved
// path and SHA-256): no agent, flag, environment or working directory
// reaches it. It copies that binary to the service's own path
// (ServiceBinary), root's, mode 0755, unless it runs from there, creates
// the engine's OS user and its system directories, writes the unit that
// runs `<service binary> engine --config <system path> --supervise`, and
// starts it. Every directory it writes in is reached from / without
// following a symlink anyone but root controls, and a directory on the way
// owned by anyone but root or the engine's user, or writable by group or
// others, stops it.
func InstallScript(goos string, src Source) (string, error) {
	if err := src.validate(); err != nil {
		return "", err
	}
	binary := ServiceBinary(goos)
	if !safeBinary.MatchString(binary) {
		return "", fmt.Errorf("the service's basalt path %q has characters the service install does not take", binary)
	}
	spec := SystemSpec(goos, binary)
	if err := validateSpec(spec); err != nil {
		return "", err
	}
	steps, err := installSteps(goos, spec)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(scriptHelpers(goos))
	b.WriteString(breakingHelpers)
	b.WriteString(ScriptHelpersEnd)
	// Every check runs before anything is created: a refused folder never
	// leaves a new OS user or folder behind.
	if src.copies(goos) {
		b.WriteString(sourceCheck(goos, src))
	} else {
		b.WriteString(binaryCheck(binary))
	}
	b.WriteString(installPreflight(goos, spec))
	b.WriteString(ScriptPreflightEnd)
	if src.copies(goos) {
		b.WriteString(copyBinary(goos, src))
	}
	// A config left by a release before the last breaking one is moved
	// aside first: the install then starts from no config.
	b.WriteString(breakingReset(goos))
	b.WriteString(steps)
	return b.String(), nil
}

// installPreflight checks the engine's account and every folder the
// install writes in, changing nothing.
func installPreflight(goos string, spec servicespec.Spec) string {
	if goos == goosDarwin {
		return darwinPreflight(spec)
	}
	return linuxPreflight(spec)
}

// installSteps makes the engine's account and folders, writes the unit and
// starts it: the install script's steps after its checks.
func installSteps(goos string, spec servicespec.Spec) (string, error) {
	body := linuxScript(spec)
	unit := SystemdUnit(spec)
	start := "systemctl daemon-reload\nsystemctl enable --now " + servicespec.SystemdUnitName + "\n"
	if goos == goosDarwin {
		body = darwinScript(spec)
		unit = LaunchdDaemon(spec)
		start = "launchctl bootstrap system " + LaunchdPlist + "\nlaunchctl enable system/" + servicespec.LaunchdLabel + "\n"
	}
	if strings.Contains(unit, "\n"+unitEnd+"\n") {
		return "", errors.New("the unit holds the script's own end marker")
	}
	return body + fmt.Sprintf("put_file %s <<'%s'\n%s%s\n%s", scriptWord(UnitPath(goos)), unitEnd, unit, unitEnd, start), nil
}

// scriptHelpers are the shell functions the install script uses. stat
// reads a path's own owner and mode, never a link's target, on both
// systems.
func scriptHelpers(goos string) string {
	uid, mode, sum := "stat -c %u", "stat -c %a", "sha256sum"
	if goos == goosDarwin {
		uid, mode, sum = "stat -f %u", "stat -f %Lp", "shasum -a 256"
	}
	return `set -eu
# pkexec's own 126 and 127 mean a dismissed dialog and no dialog: the
# script's failures (a missing command exits 127) end with 1 instead.
trap 'rc=$?; [ "$rc" -ne 126 ] && [ "$rc" -ne 127 ] || exit 1' EXIT
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 022
cd /
fail() { echo "basalt: $*" >&2; exit 1; }
uid_of() { ` + uid + ` "$1"; }
mode_of() { ` + mode + ` "$1"; }
# trusted DIR UID: walk DIR from / and stop on a symlink root does not own,
# or a directory owned by anyone but root or UID, or writable by group or
# others. A root-owned symlink is followed (macOS /etc, /var). The walk ends
# at the first missing directory, which make_dir then makes.
trusted() {
	p=
	rest=${1#/}
	hops=0
	while [ -n "$rest" ]; do
		c=${rest%%/*}
		case $rest in */*) rest=${rest#*/} ;; *) rest= ;; esac
		[ -n "$c" ] || continue
		p=$p/$c
		if [ -L "$p" ]; then
			[ "$(uid_of "$p")" = 0 ] || fail "$p is a symlink root does not own"
			hops=$((hops + 1))
			[ "$hops" -le 16 ] || fail "$1: too many symlinks"
			t=$(readlink "$p")
			case $t in /*) ;; *) t=${p%/*}/$t ;; esac
			rest=${t#/}${rest:+/$rest}
			p=
			continue
		fi
		[ -e "$p" ] || return 0
		[ -d "$p" ] || fail "$p is not a directory"
		u=$(uid_of "$p")
		[ "$u" = 0 ] || [ "$u" = "$2" ] || fail "$p is owned by uid $u, not root"
		[ $((0$(mode_of "$p") & 022)) -eq 0 ] || fail "$p is writable by group or others"
	done
}
# check_dir DIR UID: the walk, and DIR itself is no symlink.
check_dir() {
	trusted "$1" "$2"
	[ ! -L "$1" ] || fail "$1 is a symlink"
}
# no_link PATH: PATH is no symlink.
no_link() {
	[ ! -L "$1" ] || fail "$1 is a symlink"
}
# make_dir DIR MODE OWNER GROUP: make DIR when it is missing; one that
# exists must pass the walk. mkdir never follows a link at DIR, and chown -h
# changes only DIR itself. A DIR it made and cannot give to OWNER is removed
# again. An existing DIR root owns (left by an install that stopped) is
# given to OWNER only when it holds nothing but folders: find never
# follows a link.
make_dir() {
	check_dir "$1" "$engine_uid"
	if [ -d "$1" ]; then
		if [ "$3" != 0 ] && [ "$(uid_of "$1")" = 0 ]; then
			[ -z "$(find "$1" -mindepth 1 ! -type d -print | head -n 1)" ] ||
				fail "$1 is owned by root and holds files, so basalt does not give it to $3; remove it and run basalt init again"
			chown -h "$3:$4" "$1"
			chmod "$2" "$1"
		fi
		return 0
	fi
	mkdir -m "$2" "$1"
	if ! chown -h "$3:$4" "$1"; then
		rmdir "$1"
		fail "$1 could not be given to $3:$4"
	fi
}
# make_root_dir DIR MODE: make DIR root's when it is missing; one that
# exists must be root's and pass the walk.
make_root_dir() {
	check_dir "$1" ""
	[ -d "$1" ] && return 0
	mkdir -m "$2" "$1"
	chown -h 0:0 "$1"
}
# put_file PATH: write stdin to PATH, mode 0644, in a directory only root
# can change, replacing the file whole.
put_file() {
	trusted "${1%/*}" ""
	no_link "$1"
	t=$1.basalt-new
	rm -f "$t"
	(umask 077 && cat >"$t")
	chmod 0644 "$t"
	mv -f "$t" "$1"
}
sha256_of() { ` + sum + ` "$1" | awk '{ print $1 }'; }
# copy_binary SRC DEST SUM SIZE: copy SRC to DEST, root's, mode 0755, in a
# directory only root can change, replacing an older copy whole (a rename,
# never a write into the file the service runs). DEST is never a symlink.
# SRC must be a plain file, not a symlink, right before it is read, and at
# most SIZE bytes are read (a device or a pipe swapped in never makes root
# read on). The copy is first written root-only and must have SUM, the
# SHA-256 of the basalt that asked for the password, or it is removed: a SRC
# changed or swapped since then is never installed.
copy_binary() {
	trusted "${2%/*}" ""
	no_link "$2"
	t=$2.basalt-new
	rm -f "$t"
	[ -f "$1" ] && [ ! -L "$1" ] || fail "$1 is not a plain file, so it was not copied to $2; run basalt init again"
	if ! (umask 077 && head -c "$4" <"$1" >"$t"); then
		rm -f "$t"
		fail "$1 could not be copied to $2, the engine service's own copy; run basalt init again"
	fi
	if [ "$(sha256_of "$t")" != "$3" ]; then
		rm -f "$t"
		fail "$1 changed after basalt init read it, so it was not copied to $2; run basalt init again"
	fi
	chown 0:0 "$t"
	chmod 0755 "$t"
	mv -f "$t" "$2"
}
`
}

// binaryCheck re-checks, as root, the binary the unit runs: every folder
// above it root's and not writable by group or others, and the file itself
// a plain root-owned file nobody else can write.
func binaryCheck(binary string) string {
	return fmt.Sprintf(`bin=%s
trusted "${bin%%/*}" ""
no_link "$bin"
[ -f "$bin" ] || fail "$bin is not a file"
[ "$(uid_of "$bin")" = 0 ] || fail "$bin is not owned by root"
[ $((0$(mode_of "$bin") & 022)) -eq 0 ] || fail "$bin is writable by group or others"
`, binary)
}

// shellCheck refuses an existing account whose login shell is not one
// that refuses a login; shellCmd prints its shell.
func shellCheck(user, shellCmd string) string {
	return fmt.Sprintf(`	shell=$(%[2]s)
	case $shell in
	/usr/sbin/nologin | /sbin/nologin | /usr/bin/false | /bin/false) ;;
	*) fail "the OS user %[1]s exists with the login shell $shell; basalt takes over only a system account that cannot log in" ;;
	esac
`, user, shellCmd)
}

// linuxPreflight checks an existing engine account (a system uid, up to
// SYS_UID_MAX, and no login shell; no group of that name without the user)
// and every folder the script writes in. A user whose group is missing gets
// it back with the user's own gid, when no other group holds that gid.
func linuxPreflight(s servicespec.Spec) string {
	u := s.User
	return fmt.Sprintf(`engine_uid=
make_group=
if id -u %[1]s >/dev/null 2>&1; then
	engine_uid=$(id -u %[1]s)
	sys_max=$(awk '$1 == "SYS_UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null || true)
	case $sys_max in '' | *[!0-9]*) sys_max=%[4]d ;; esac
	[ "$engine_uid" -ge 1 ] && [ "$engine_uid" -le "$sys_max" ] ||
		fail "the OS user %[1]s exists with uid $engine_uid, not a system account (1 to $sys_max); basalt does not take it over"
%[5]s	engine_gid=$(id -g %[1]s)
	if ! getent group %[1]s >/dev/null 2>&1; then
		! getent group "$engine_gid" >/dev/null 2>&1 ||
			fail "the OS user %[1]s has no group %[1]s, and its group id $engine_gid belongs to another group; basalt does not take it over"
		make_group=1
	fi
elif getent group %[1]s >/dev/null 2>&1; then
	fail "the group %[1]s exists without the OS user %[1]s; basalt does not take it over"
fi
check_dir %[2]s "$engine_uid"
trusted %[3]s ""
no_link %[6]s
check_dir %[7]s ""
check_dir %[8]s ""
`, u, scriptWord(filepath.Dir(s.ConfigPath)), scriptWord(filepath.Dir(SystemdUnitPath)), linuxSysUIDMax,
		shellCheck(u, "getent passwd "+u+" | cut -d: -f7"), scriptWord(SystemdUnitPath),
		scriptWord(linuxPluginBase), scriptWord(linuxPluginBase+"/"+pluginRunDirName))
}

// darwinPreflight checks an existing engine account (uid 300 to 499, no
// login shell; no group of that name without the user, whose gid dscl
// would change) and every folder and file the script writes in. A user
// whose group is missing (a removal that could not delete the user) gets
// its group back with the user's own gid, when that gid is a system id no
// other group holds.
func darwinPreflight(s servicespec.Spec) string {
	u := s.User
	return fmt.Sprintf(`engine_uid=
make_group=
if id -u %[1]s >/dev/null 2>&1; then
	engine_uid=$(id -u %[1]s)
	[ "$engine_uid" -ge %[2]d ] && [ "$engine_uid" -le %[3]d ] ||
		fail "the OS user %[1]s exists with uid $engine_uid, not a system account (%[2]d to %[3]d); basalt does not take it over"
%[4]s	if ! dscl . -read /Groups/%[1]s >/dev/null 2>&1; then
		engine_gid=$(dscl . -read /Users/%[1]s PrimaryGroupID | awk '{ print $2 }')
		case $engine_gid in '' | *[!0-9]*) fail "the OS user %[1]s has no group %[1]s and no group id; basalt does not take it over" ;; esac
		[ "$engine_gid" -ge %[2]d ] && [ "$engine_gid" -le %[3]d ] ||
			fail "the OS user %[1]s has no group %[1]s, and its group id $engine_gid is not a system id (%[2]d to %[3]d); basalt does not take it over"
		if dscl . -list /Groups PrimaryGroupID | awk -v id="$engine_gid" '$NF == id { f = 1 } END { exit !f }'; then
			fail "the OS user %[1]s has no group %[1]s, and its group id $engine_gid belongs to another group; basalt does not take it over"
		fi
		make_group=1
	fi
elif dscl . -read /Groups/%[1]s >/dev/null 2>&1; then
	fail "the group %[1]s exists without the OS user %[1]s; basalt does not take it over"
fi
check_dir %[5]s "$engine_uid"
check_dir %[6]s "$engine_uid"
check_dir %[7]s "$engine_uid"
check_dir %[8]s "$engine_uid"
no_link %[9]s
trusted %[10]s ""
no_link %[11]s
`, u, darwinIDMin, darwinIDMax,
		shellCheck(u, "dscl . -read /Users/"+u+" UserShell | awk '{ print $2 }'"),
		scriptWord(filepath.Dir(s.ConfigPath)), scriptWord(config.DefaultSocketDir(goosDarwin)),
		scriptWord(config.DefaultStateDir(goosDarwin)), scriptWord(darwinLogDir), scriptWord(darwinLogFile),
		scriptWord(filepath.Dir(LaunchdPlist)), scriptWord(LaunchdPlist))
}

// linuxScript creates the engine's user and its config directory; systemd
// makes the runtime and state directories from the unit.
func linuxScript(s servicespec.Spec) string {
	u := s.User
	return fmt.Sprintf(`if [ -z "$engine_uid" ]; then
	useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin %[1]s
elif [ -n "$make_group" ]; then
	groupadd --system --gid "$engine_gid" %[1]s
fi
engine_uid=$(id -u %[1]s)
make_dir %[2]s %04[3]o %[1]s %[1]s
make_root_dir %[4]s %04[5]o
make_root_dir %[6]s %04[5]o
`, u, scriptWord(filepath.Dir(s.ConfigPath)), configDirMode,
		scriptWord(linuxPluginBase), openDirMode, scriptWord(linuxPluginBase+"/"+pluginRunDirName))
}

// darwinScript creates the engine's hidden system account with the lowest
// free id from 300 to 499, picked as root when the script runs, then its
// directories and its log.
func darwinScript(s servicespec.Spec) string {
	u := s.User
	configDir := filepath.Dir(s.ConfigPath)
	return fmt.Sprintf(`if [ -z "$engine_uid" ]; then
	used=$(dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID)
	id=%[2]d
	while [ "$id" -le %[3]d ] && printf '%%s\n' "$used" | awk -v id="$id" '$NF == id { f = 1 } END { exit !f }'; do
		id=$((id + 1))
	done
	[ "$id" -le %[3]d ] || fail "no free system id between %[2]d and %[3]d"
	dscl . -create /Groups/%[1]s
	dscl . -create /Groups/%[1]s PrimaryGroupID "$id"
	dscl . -create /Users/%[1]s
	dscl . -create /Users/%[1]s UniqueID "$id"
	dscl . -create /Users/%[1]s PrimaryGroupID "$id"
	dscl . -create /Users/%[1]s UserShell /usr/bin/false
	dscl . -create /Users/%[1]s NFSHomeDirectory /var/empty
	dscl . -create /Users/%[1]s RealName 'BasaltDB engine'
	dscl . -create /Users/%[1]s IsHidden 1
elif [ -n "$make_group" ]; then
	dscl . -create /Groups/%[1]s
	dscl . -create /Groups/%[1]s PrimaryGroupID "$engine_gid"
fi
engine_uid=$(id -u %[1]s)
make_dir %[4]s %04[5]o %[1]s %[1]s
make_dir %[6]s %04[7]o %[1]s %[1]s
make_dir %[8]s %04[9]o %[1]s %[1]s
make_dir %[10]s %04[11]o 0 0
log=%[12]s
no_link "$log"
[ -e "$log" ] || (umask 077 && : >"$log")
[ -f "$log" ] || fail "$log is not a file"
chown -h %[1]s:%[1]s "$log"
chmod %04[13]o "$log"
# The plugin base, root's: best effort on macOS, as the service install
# does; plugins cannot be installed until it can be made.
( make_root_dir %[14]s %04[5]o && make_root_dir %[15]s %04[5]o && make_root_dir %[16]s %04[5]o ) ||
	echo "basalt: plugins cannot be installed until every folder above %[14]s is owned by root and writable by root only" >&2
`, u, darwinIDMin, darwinIDMax,
		scriptWord(configDir), openDirMode,
		scriptWord(config.DefaultSocketDir(goosDarwin)), runtimeDirMode,
		scriptWord(config.DefaultStateDir(goosDarwin)), darwinStateDirMode,
		scriptWord(darwinLogDir), openDirMode,
		scriptWord(darwinLogFile), engineLogMode,
		scriptWord(darwinPluginBase), scriptWord(darwinPluginBase+"/"+pluginRunDirName), scriptWord(darwinPluginLogDir))
}

// scriptWord is a constant path as one shell word: single-quoted when it
// has a space. The constants hold no quote.
func scriptWord(s string) string {
	if strings.ContainsAny(s, " \t") {
		return "'" + s + "'"
	}
	return s
}
