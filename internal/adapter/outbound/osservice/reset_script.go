package service

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// ResetScript is the administrator dialog's script for a reset (CONTRACT.md,
// Not your database): the person answered that the database the engine
// serves is not theirs. As root it stops the plugin services the engine
// started, deletes engine.json, the agents' credential files and the
// certificate pins in trust.d, and restarts the engine service, which then
// waits for a first install. It touches no database. It is built from
// constants only: no value from the agent, the engine or the environment
// reaches it.
func ResetScript(goos string) (string, error) {
	var b strings.Builder
	b.WriteString(scriptHelpers(goos))
	b.WriteString(removeHelpers)
	b.WriteString(ScriptHelpersEnd)
	switch goos {
	case goosLinux:
		b.WriteString(linuxEngineUID())
		b.WriteString(resetPreflight(goosLinux))
		b.WriteString(ScriptPreflightEnd)
		fmt.Fprintf(&b, `for unit in %[1]s%[2]s*.service; do
	[ -e "$unit" ] || [ -L "$unit" ] || continue
	systemctl disable --now "${unit##*/}" >/dev/null 2>&1 || true
	rm -f "$unit"
done
systemctl daemon-reload >/dev/null 2>&1 || true
`, systemdUnitDir, pluginUnitPrefix)
		b.WriteString(resetFiles(goosLinux))
		fmt.Fprintf(&b, "systemctl restart %s\n", SystemdUnitName)
	case goosDarwin:
		b.WriteString(darwinEngineUID())
		b.WriteString(resetPreflight(goosDarwin))
		b.WriteString(ScriptPreflightEnd)
		fmt.Fprintf(&b, `for unit in %[1]s%[2]s*.plist; do
	[ -e "$unit" ] || [ -L "$unit" ] || continue
	label=${unit##*/}
	launchctl bootout "system/${label%%.plist}" >/dev/null 2>&1 || true
	rm -f "$unit"
done
`, launchDaemonsDir, pluginLabelPrefix)
		b.WriteString(resetFiles(goosDarwin))
		fmt.Fprintf(&b, "launchctl kickstart -k system/%s\n", LaunchdLabel)
	default:
		return "", fmt.Errorf("the engine service installs on linux and darwin, not %s", goos)
	}
	return b.String(), nil
}

// resetPreflight checks, changing nothing, that there is a setup to reset
// in the engine's own folders, which only root and the engine's system
// account can change.
func resetPreflight(goos string) string {
	path := config.DefaultPath(goos)
	dir := filepath.Dir(path)
	return fmt.Sprintf(`[ -n "$engine_uid" ] || fail "the OS user %[1]s is not the system account the install made, so nothing was reset"
check_dir %[2]s "$engine_uid"
no_link %[3]s
[ -f %[3]s ] || fail "%[4]s does not exist: this engine has no setup to reset. Nothing was changed"
for d in %[5]s %[6]s; do
	[ ! -e "$d" ] && [ ! -L "$d" ] || check_dir "$d" "$engine_uid"
done
`, DefaultUser(goos), scriptWord(dir), scriptWord(path), path,
		scriptWord(filepath.Join(dir, "agents")), scriptWord(filepath.Join(dir, "trust.d")))
}

// resetFiles deletes the setup's files: engine.json, the agents'
// credentials and the certificate pins. rm never follows a link.
func resetFiles(goos string) string {
	dir := filepath.Dir(config.DefaultPath(goos))
	return fmt.Sprintf(`rm -f %[1]s
rm -f %[2]s/*.url %[2]s/*.url.pending
rm -f %[3]s/pin-*.json %[3]s/pin-*.pem
`, scriptWord(config.DefaultPath(goos)), scriptWord(filepath.Join(dir, "agents")), scriptWord(filepath.Join(dir, "trust.d")))
}
