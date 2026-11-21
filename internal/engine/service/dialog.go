package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
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

	// unitEnd ends the here-document that carries the unit.
	unitEnd = "END_OF_ENGINE_UNIT"
)

// ScriptHelpersEnd marks the end of the install script's helper functions.
const ScriptHelpersEnd = "# end of helpers\n"

// Errors of an administrator dialog run.
var (
	// ErrNoDialog: no administrator dialog can be shown here (an SSH
	// session, a machine without a desktop).
	ErrNoDialog = errors.New("no administrator dialog is available here")
	// ErrDialogCancelled: the person closed the dialog.
	ErrDialogCancelled = errors.New("the administrator dialog was cancelled")
	// ErrDialogScript: the person answered, and the install script stopped.
	ErrDialogScript = errors.New("the engine service install stopped")
)

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
// administrator privileges" on macOS (the script is an argument of the
// AppleScript, never part of its text), pkexec on Linux (with no text
// prompt of its own, so only a desktop's dialog can answer).
func DialogCommand(goos, script string) ([]string, error) {
	switch goos {
	case goosDarwin:
		return []string{
			osascriptPath, "-e", "on run argv", "-e", "do shell script (item 1 of argv) with administrator privileges", "-e", "end run", script,
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
		return ErrDialogCancelled
	case goos == goosLinux && code == pkexecNotAuthorized:
		return fmt.Errorf("%w (pkexec: %s)", ErrNoDialog, orRunErr(said, runErr))
	case goos == goosDarwin && (strings.Contains(said, "(-1713)") || strings.Contains(said, "(-60007)")):
		return fmt.Errorf("%w (osascript: %s)", ErrNoDialog, said)
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
func SystemSpec(goos, binary string) Spec {
	return Spec{GOOS: goos, Binary: binary, ConfigPath: config.DefaultPath(goos), User: DefaultUser(goos)}
}

// InstallScript is the script the administrator dialog runs on a first
// install, built from constants and the resolved path of the running
// binary only: no agent, flag, environment or working directory reaches it.
// It creates the engine's OS user and its system directories, writes the
// unit that runs `<binary> engine --config <system path> --supervise`, and
// starts it. Every directory it writes in is reached from / without
// following a symlink anyone but root controls, and a directory on the way
// owned by anyone but root or the engine's user, or writable by group or
// others, stops it.
func InstallScript(goos, binary string) (string, error) {
	if !safeBinary.MatchString(binary) || filepath.Clean(binary) != binary {
		return "", fmt.Errorf("the basalt binary's path %q has characters the service install does not take; install basalt at a plain path such as /usr/local/bin/basalt", binary)
	}
	spec := SystemSpec(goos, binary)
	if err := spec.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(scriptHelpers(goos))
	b.WriteString(ScriptHelpersEnd)
	switch goos {
	case goosLinux:
		b.WriteString(linuxScript(spec))
	case goosDarwin:
		b.WriteString(darwinScript(spec))
	}
	unit := SystemdUnit(spec)
	start := "systemctl daemon-reload\nsystemctl enable --now " + SystemdUnitName + "\n"
	if goos == goosDarwin {
		unit = LaunchdDaemon(spec)
		start = "launchctl bootstrap system " + LaunchdPlist + "\nlaunchctl enable system/" + LaunchdLabel + "\n"
	}
	if strings.Contains(unit, "\n"+unitEnd+"\n") {
		return "", errors.New("the unit holds the script's own end marker")
	}
	fmt.Fprintf(&b, "put_file %s <<'%s'\n%s%s\n%s", scriptWord(UnitPath(goos)), unitEnd, unit, unitEnd, start)
	return b.String(), nil
}

// scriptHelpers are the shell functions the install script uses. stat
// reads a path's own owner and mode, never a link's target, on both
// systems.
func scriptHelpers(goos string) string {
	uid, mode := "stat -c %u", "stat -c %a"
	if goos == goosDarwin {
		uid, mode = "stat -f %u", "stat -f %Lp"
	}
	return `set -eu
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
# make_dir DIR MODE OWNER GROUP: make DIR when it is missing; one that
# exists must pass the walk. mkdir never follows a link at DIR, and chown -h
# changes only what mkdir made.
make_dir() {
	trusted "$1" "$engine_uid"
	[ ! -L "$1" ] || fail "$1 is a symlink"
	[ -d "$1" ] && return 0
	mkdir -m "$2" "$1"
	chown -h "$3:$4" "$1"
}
# put_file PATH: write stdin to PATH, mode 0644, in a directory only root
# can change, replacing the file whole.
put_file() {
	trusted "${1%/*}" ""
	[ ! -L "$1" ] || fail "$1 is a symlink"
	t=$1.basalt-new
	rm -f "$t"
	(umask 077 && cat >"$t")
	chmod 0644 "$t"
	mv -f "$t" "$1"
}
`
}

// linuxScript creates the engine's user and its config directory; systemd
// makes the runtime and state directories from the unit.
func linuxScript(s Spec) string {
	u := s.User
	return fmt.Sprintf(`if ! id -u %[1]s >/dev/null 2>&1; then
	useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin %[1]s
fi
engine_uid=$(id -u %[1]s)
make_dir %[2]s %04[3]o %[1]s %[1]s
`, u, scriptWord(filepath.Dir(s.ConfigPath)), configDirMode)
}

// darwinScript creates the engine's hidden system account with the lowest
// free id from 300 to 499, picked as root when the script runs, then its
// directories and its log.
func darwinScript(s Spec) string {
	u := s.User
	configDir := filepath.Dir(s.ConfigPath)
	return fmt.Sprintf(`if ! id -u %[1]s >/dev/null 2>&1; then
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
fi
engine_uid=$(id -u %[1]s)
make_dir %[4]s %04[5]o %[1]s %[1]s
make_dir %[6]s %04[7]o %[1]s %[1]s
make_dir %[8]s %04[9]o %[1]s %[1]s
make_dir %[10]s %04[11]o 0 0
log=%[12]s
[ ! -L "$log" ] || fail "$log is a symlink"
[ -e "$log" ] || (umask 077 && : >"$log")
[ -f "$log" ] || fail "$log is not a file"
chown -h %[1]s:%[1]s "$log"
chmod %04[13]o "$log"
`, u, darwinIDMin, darwinIDMax,
		scriptWord(configDir), openDirMode,
		scriptWord(config.DefaultSocketDir(goosDarwin)), runtimeDirMode,
		scriptWord(config.DefaultStateDir(goosDarwin)), darwinStateDirMode,
		scriptWord(darwinLogDir), openDirMode,
		scriptWord(darwinLogFile), engineLogMode)
}

// scriptWord is a constant path as one shell word: single-quoted when it
// has a space. The constants hold no quote.
func scriptWord(s string) string {
	if strings.ContainsAny(s, " \t") {
		return "'" + s + "'"
	}
	return s
}
