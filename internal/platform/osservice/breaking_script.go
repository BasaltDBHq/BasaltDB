package osservice

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// The reset of a setup from before the last breaking release (CONTRACT.md,
// The administrator dialog, A setup from before the last breaking
// release): the install and restart scripts read, as root, the breaking
// epoch of the engine.json at the system path (config.EpochOf). Below
// config.BreakingEpoch, they stop and remove the engine service and its
// plugin services, move the config folder aside to the first free
// <folder>.old, <folder>.old.2, ... (never deleted, overwritten or nested),
// say so in one line, and install the service again as a first install
// does: the engine then waits for its first install. An epoch the script
// cannot read resets nothing.

// breakingHelpers is config_epoch, the shell side of config.EpochOf: the
// same rule on the same keys, so one set of test configs pins both. It
// prints nothing for a "breaking" that is not a plain number.
const breakingHelpers = `# config_epoch FILE: the breaking epoch of an engine.json, as
# config.EpochOf reads it: its "breaking" number; else 0 for a config with
# "directAddr", or with "credentialFile" and no "store" (the shape of
# releases before the first breaking one); else 1.
config_epoch() {
	if grep -q '"breaking"' "$1"; then
		sed -n 's/.*"breaking"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*[,}]*[[:space:]]*$/\1/p' "$1" | head -n 1
	elif grep -q '"directAddr"' "$1"; then
		echo 0
	elif grep -q '"credentialFile"' "$1" && ! grep -q '"store"' "$1"; then
		echo 0
	else
		echo 1
	fi
}
`

// BreakingResetLine starts the line the scripts print after a reset.
const BreakingResetLine = "basalt: this computer's BasaltDB was set up by a release before the last breaking one: its engine service is removed and its config folder moved to "

// breakingReset is the reset step: it sets breaking_reset when it ran.
func breakingReset(goos string) string {
	path := config.DefaultPath(goos)
	dir := filepath.Dir(path)
	var stop string
	switch goos {
	case goosLinux:
		stop = fmt.Sprintf(`	systemctl disable --now %[1]s >/dev/null 2>&1 || true
	for unit in %[2]s%[3]s*.service; do
		[ -e "$unit" ] || [ -L "$unit" ] || continue
		systemctl disable --now "${unit##*/}" >/dev/null 2>&1 || true
		rm -f "$unit"
	done
	rm -f %[4]s
	systemctl daemon-reload >/dev/null 2>&1 || true
`, servicespec.SystemdUnitName, systemdUnitDir, pluginUnitPrefix, SystemdUnitPath)
	case goosDarwin:
		stop = fmt.Sprintf(`	launchctl bootout system/%[1]s >/dev/null 2>&1 || true
	for unit in %[2]s%[3]s*.plist; do
		[ -e "$unit" ] || [ -L "$unit" ] || continue
		label=${unit##*/}
		launchctl bootout "system/${label%%.plist}" >/dev/null 2>&1 || true
		rm -f "$unit"
	done
	rm -f %[4]s
`, servicespec.LaunchdLabel, launchDaemonsDir, pluginLabelPrefix, LaunchdPlist)
	}
	return fmt.Sprintf(`breaking_reset=
if [ -f %[1]s ] && [ ! -L %[1]s ]; then
	epoch=$(config_epoch %[1]s)
	case $epoch in '' | *[!0-9]*) epoch=%[3]d ;; esac
	if [ "$epoch" -lt %[3]d ]; then
		no_link %[2]s
%[4]s		old=%[2]s.old
		n=1
		while [ -e "$old" ] || [ -L "$old" ]; do
			n=$((n + 1))
			old=%[2]s.old.$n
		done
		mv %[2]s "$old"
		breaking_reset=1
		echo "%[5]s$old. Delete that folder once the new setup works."
	fi
fi
`, scriptWord(path), scriptWord(dir), config.BreakingEpoch, indent(stop), BreakingResetLine)
}

// indent puts one more tab before every line of s.
func indent(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.SplitAfter(s, "\n")
	var b strings.Builder
	for _, l := range lines {
		if l != "" {
			b.WriteString("\t" + l)
		}
	}
	return b.String()
}
