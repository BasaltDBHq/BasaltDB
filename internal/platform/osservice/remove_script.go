package osservice

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// RemoveScript is the script the administrator dialog runs after the setup
// page removed BasaltDB (CONTRACT.md, The administrator dialog), built from
// constants only: no agent, flag, config, environment or working directory
// reaches it. It refuses while engine.json exists, so an engine that still
// serves an agent is never removed. It stops the engine service and every
// plugin unit, removes their units, the plugins' newsyslog rules, the
// system directories (config, state, sockets, logs and the plugin base),
// and the plugins' and the engine's OS users and groups.
//
// The plugin entries were in the engine.json the removal deleted, so the
// script finds them by their fixed name prefixes; a plugin OS user is
// deleted only when it cannot log in, and the engine's only when the
// install would have taken it over (a system account that cannot log in).
func RemoveScript(goos string) (string, error) {
	var b strings.Builder
	b.WriteString(scriptHelpers(goos))
	b.WriteString(removeHelpers(goos))
	b.WriteString(ScriptHelpersEnd)
	switch goos {
	case goosLinux:
		b.WriteString(linuxRemovePreflight())
		b.WriteString(ScriptPreflightEnd)
		b.WriteString(linuxRemove())
	case goosDarwin:
		b.WriteString(darwinRemovePreflight())
		b.WriteString(ScriptPreflightEnd)
		b.WriteString(darwinRemove())
	default:
		return "", fmt.Errorf("the engine service installs on linux and darwin, not %s", goos)
	}
	return b.String(), nil
}

// removeHelpers: no_login says whether a login shell refuses a login;
// remove_dir removes a directory tree the preflight walked (rm never
// follows a link inside it). delete_account deletes an OS user and then its
// group, the group only once the user is really gone: an install takes over
// a user whose group is missing only by making the group again, and it
// refuses a group without its user. A user it cannot delete is kept with
// its group (kept); a group left without its user is an error (orphaned).
func removeHelpers(goos string) string {
	deleteUser, userGone, deleteGroup, groupGone := `userdel "$1"`, `! getent passwd "$1" >/dev/null 2>&1`,
		`groupdel "$1"`, `! getent group "$1" >/dev/null 2>&1`
	if goos == goosDarwin {
		deleteUser, userGone, deleteGroup, groupGone = `dscl . -delete "/Users/$1"`, `! dscl . -read "/Users/$1" >/dev/null 2>&1`,
			`dscl . -delete "/Groups/$1"`, `! dscl . -read "/Groups/$1" >/dev/null 2>&1`
	}
	return `no_login() {
	case $1 in
	/usr/sbin/nologin | /sbin/nologin | /usr/bin/false | /bin/false) return 0 ;;
	esac
	return 1
}
remove_dir() {
	no_link "$1"
	rm -rf "$1"
}
kept=
orphaned=
# delete_account NAME: wait up to 10 seconds for NAME's processes to end
# (its service is stopped above), delete the user, and its group only once
# the user is gone.
delete_account() {
	n=0
	while [ "$n" -lt 10 ] && pgrep -U "$1" >/dev/null 2>&1; do
		sleep 1
		n=$((n + 1))
	done
	` + deleteUser + ` || true
	if ` + userGone + `; then
		` + groupGone + ` || ` + deleteGroup + ` >/dev/null 2>&1 || true
		` + groupGone + ` || orphaned="$orphaned $1"
	else
		kept="$kept $1"
	fi
}
`
}

func configGone(goos string) string {
	p := scriptWord(config.DefaultPath(goos))
	return fmt.Sprintf(`[ ! -e %[1]s ] && [ ! -L %[1]s ] ||
	fail "%[2]s still exists: this engine still serves an agent, so its service stays. Nothing was removed"
`, p, config.DefaultPath(goos))
}

// linuxRemovePreflight checks, before anything is removed, that the config
// is gone, whether the engine's account is one the install would take
// over, and every directory it removes in or under.
// linuxEngineUID sets engine_uid to the engine's OS user when it is the
// system account the install made, else to empty.
func linuxEngineUID() string {
	return fmt.Sprintf(`engine_uid=
if id -u %[1]s >/dev/null 2>&1; then
	uid=$(id -u %[1]s)
	sys_max=$(awk '$1 == "SYS_UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null || true)
	case $sys_max in '' | *[!0-9]*) sys_max=%[2]d ;; esac
	if [ "$uid" -ge 1 ] && [ "$uid" -le "$sys_max" ] && no_login "$(getent passwd %[1]s | cut -d: -f7)"; then
		engine_uid=$uid
	fi
fi
`, DefaultUser(goosLinux), linuxSysUIDMax)
}

func linuxRemovePreflight() string {
	return configGone(goosLinux) + linuxEngineUID() + fmt.Sprintf(`check_dir %[1]s "$engine_uid"
check_dir %[2]s "$engine_uid"
check_dir %[3]s "$engine_uid"
check_dir %[4]s ""
trusted %[5]s ""
`,
		scriptWord(filepath.Dir(config.DefaultPath(goosLinux))), scriptWord(config.DefaultStateDir(goosLinux)),
		scriptWord(config.DefaultSocketDir(goosLinux)), scriptWord(linuxPluginBase), scriptWord(strings.TrimSuffix(systemdUnitDir, "/")))
}

// linuxRemove stops and removes the units, the directories and the users.
func linuxRemove() string {
	u := DefaultUser(goosLinux)
	return fmt.Sprintf(`systemctl disable --now %[1]s >/dev/null 2>&1 || true
for unit in %[2]s%[3]s*.service; do
	[ -e "$unit" ] || [ -L "$unit" ] || continue
	systemctl disable --now "${unit##*/}" >/dev/null 2>&1 || true
	rm -f "$unit"
done
rm -f %[4]s
systemctl daemon-reload >/dev/null 2>&1 || true
remove_dir %[5]s
remove_dir %[6]s
remove_dir %[7]s
remove_dir %[8]s
for p in $(getent passwd | cut -d: -f1 | grep '^%[3]s' || true); do
	if no_login "$(getent passwd "$p" | cut -d: -f7)"; then
		delete_account "$p"
	else
		echo "basalt: the OS user $p can log in, so it was left in place" >&2
	fi
done
if [ -n "$engine_uid" ]; then
	delete_account %[9]s
elif id -u %[9]s >/dev/null 2>&1; then
	echo "basalt: the OS user %[9]s is not the system account the install made, so it was left in place" >&2
fi
[ -z "$kept" ] ||
	echo "basalt: the engine service is removed, but the OS user${kept} could not be deleted, so it stays with its group: the next install uses it again. To delete it: userdel NAME" >&2
[ -z "$orphaned" ] ||
	fail "the engine service is removed, but the group${orphaned} stays without its user, and an install refuses that group: delete it with groupdel NAME"
`, servicespec.SystemdUnitName, systemdUnitDir, pluginUnitPrefix, SystemdUnitPath,
		scriptWord(filepath.Dir(config.DefaultPath(goosLinux))), scriptWord(config.DefaultStateDir(goosLinux)),
		scriptWord(config.DefaultSocketDir(goosLinux)), scriptWord(linuxPluginBase), u)
}

// darwinRemovePreflight is linuxRemovePreflight on macOS.
// darwinEngineUID sets engine_uid to the engine's OS user when it is the
// hidden system account the install made, else to empty.
func darwinEngineUID() string {
	return fmt.Sprintf(`engine_uid=
if id -u %[1]s >/dev/null 2>&1; then
	uid=$(id -u %[1]s)
	if [ "$uid" -ge %[2]d ] && [ "$uid" -le %[3]d ] && no_login "$(dscl . -read /Users/%[1]s UserShell | awk '{ print $2 }')"; then
		engine_uid=$uid
	fi
fi
`, DefaultUser(goosDarwin), darwinIDMin, darwinIDMax)
}

func darwinRemovePreflight() string {
	return configGone(goosDarwin) + darwinEngineUID() + fmt.Sprintf(`check_dir %[1]s "$engine_uid"
check_dir %[2]s "$engine_uid"
check_dir %[3]s "$engine_uid"
check_dir %[4]s "$engine_uid"
check_dir %[5]s ""
trusted %[6]s ""
trusted %[7]s ""
`,
		scriptWord(filepath.Dir(config.DefaultPath(goosDarwin))), scriptWord(config.DefaultSocketDir(goosDarwin)),
		scriptWord(config.DefaultStateDir(goosDarwin)), scriptWord(darwinLogDir), scriptWord(darwinPluginBase),
		scriptWord(strings.TrimSuffix(launchDaemonsDir, "/")), scriptWord(strings.TrimSuffix(newsyslogDir, "/")))
}

// darwinRemove stops and removes the launch daemons, the plugins' log
// rules, the directories (the socket and state directories are inside the
// config directory) and the users with their groups.
func darwinRemove() string {
	u := DefaultUser(goosDarwin)
	return fmt.Sprintf(`launchctl bootout system/%[1]s >/dev/null 2>&1 || true
for unit in %[2]s%[3]s*.plist; do
	[ -e "$unit" ] || [ -L "$unit" ] || continue
	label=${unit##*/}
	launchctl bootout "system/${label%%.plist}" >/dev/null 2>&1 || true
	rm -f "$unit"
done
rm -f %[4]s
rm -f %[5]s%[6]s*.conf
remove_dir %[7]s
remove_dir %[8]s
for old in %[8]s.old-*; do
	[ -e "$old" ] || continue
	remove_dir "$old"
done
remove_dir %[9]s
for p in $(dscl . -list /Users | grep '^%[10]s' || true); do
	if no_login "$(dscl . -read "/Users/$p" UserShell | awk '{ print $2 }')"; then
		delete_account "$p"
	else
		echo "basalt: the OS user $p can log in, so it was left in place" >&2
	fi
done
if [ -n "$engine_uid" ]; then
	delete_account %[11]s
elif id -u %[11]s >/dev/null 2>&1; then
	echo "basalt: the OS user %[11]s is not the system account the install made, so it was left in place" >&2
fi
[ -z "$kept" ] ||
	echo "basalt: the engine service is removed, but macOS refused to delete the OS user${kept} (it does, for example, when the app that ran basalt init has no Full Disk Access), so it stays with its group: the next install uses it again. To delete it, in a terminal with Full Disk Access: sudo dscl . -delete /Users/NAME, then sudo dscl . -delete /Groups/NAME"
[ -z "$orphaned" ] ||
	fail "the engine service is removed, but the group${orphaned} stays without its user, and an install refuses that group: delete it with sudo dscl . -delete /Groups/NAME"
`, servicespec.LaunchdLabel, launchDaemonsDir, pluginLabelPrefix, LaunchdPlist, newsyslogDir, pluginUnitPrefix,
		scriptWord(filepath.Dir(config.DefaultPath(goosDarwin))), scriptWord(darwinLogDir), scriptWord(darwinPluginBase),
		darwinPluginUserPrefix, u)
}
