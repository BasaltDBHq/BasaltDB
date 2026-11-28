package osservice

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// The removal job (CONTRACT.md, The administrator dialog, The removal
// job): the install also writes a small root job that removes the engine
// service when the engine asks for it, so removing BasaltDB on the setup
// page needs no second password and no terminal. The engine asks by
// creating one marker file in its state folder after the page's removal
// committed and engine.json is gone. The job reads nothing from the
// marker: its existence is the whole request. It runs fixed paths with a
// fixed argv (/bin/sh and its own root-owned script), and removes itself
// last. Someone with the engine's own account can ask too; that removes
// BasaltDB from this computer, which that account can already make useless
// by stopping the engine.
const (
	// RemovalMarkerName is the marker's name in the engine's state folder.
	RemovalMarkerName = servicespec.RemovalMarkerName

	darwinRemovalLabel  = "dev.basaltdb.remove"
	darwinRemovalPlist  = launchDaemonsDir + darwinRemovalLabel + ".plist"
	darwinRemovalScript = "/usr/local/libexec/basalt-remove"

	linuxRemovalPathUnit    = "basalt-remove.path"
	linuxRemovalServiceUnit = "basalt-remove.service"
	linuxRemovalScript      = "/usr/libexec/basalt-remove"

	// removalJobEnd and removalUnitEnd end the here-documents that carry
	// the job's script and units in the install script.
	removalJobEnd  = "END_OF_REMOVAL_JOB"
	removalUnitEnd = "END_OF_REMOVAL_UNIT"
)

// RemovalMarker is the marker's path on goos: in the engine's state
// folder, which only root and the engine's account can write.
func RemovalMarker(goos string) string {
	return filepath.Join(config.DefaultStateDir(goos), RemovalMarkerName)
}

// removalScriptPath is the job's own script on goos, next to the service's
// copy of basalt, in a folder only root can change.
func removalScriptPath(goos string) string {
	if goos == goosDarwin {
		return darwinRemovalScript
	}
	return linuxRemovalScript
}

// RemovalJobScript is the job's script: the gate, then RemoveScript. The
// gate unlinks the marker before anything else, on every path (a systemd
// PathExists unit fires again while the marker exists, and launchd may
// start a WatchPaths job when nothing changed): with no marker it exits 0;
// a marker that is not a plain file owned by the engine's account is
// refused, and nothing is removed. RemoveScript then refuses while
// engine.json exists. The marker's content is never read.
func RemovalJobScript(goos string) (string, error) {
	body, err := RemoveScript(goos)
	if err != nil {
		return "", err
	}
	return removalGate(goos) + removalGrace + body, nil
}

// removalGrace lets the engine finish answering the page's removal, which
// created the marker just before it answered, before the job stops it.
const removalGrace = "# The engine answers the page's removal before it is stopped.\nsleep 2\n"

func removalGate(goos string) string {
	owner := "stat -c %u"
	if goos == goosDarwin {
		owner = "stat -f %u"
	}
	return fmt.Sprintf(`#!/bin/sh
# BasaltDB's removal job: it runs when the engine created its marker, and
# reads nothing from it.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
cd /
marker=%[1]s
[ -e "$marker" ] || [ -L "$marker" ] || exit 0
asked=
if [ -f "$marker" ] && [ ! -L "$marker" ] && [ "$(%[2]s "$marker")" = "$(id -u %[3]s 2>/dev/null)" ]; then
	asked=1
fi
rm -f "$marker"
[ -n "$asked" ] || { echo "basalt: $marker is not a plain file of %[3]s, so nothing was removed" >&2; exit 1; }
`, scriptWord(RemovalMarker(goos)), owner, DefaultUser(goos))
}

// darwinRemovalDaemon is the job's LaunchDaemon: /bin/sh on its script,
// when the marker's path changes.
func darwinRemovalDaemon() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%[1]s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%[2]s</string>
		<string>%[3]s</string>
	</array>
	<key>WatchPaths</key>
	<array>
		<string>%[4]s</string>
	</array>
</dict>
</plist>
`, darwinRemovalLabel, shPath, darwinRemovalScript, xmlEscape(RemovalMarker(goosDarwin)))
}

// linuxRemovalUnits are the job's systemd units: a .path unit that starts
// the oneshot .service while the marker exists.
func linuxRemovalUnits() (pathUnit, serviceUnit string) {
	pathUnit = fmt.Sprintf(`[Unit]
Description=BasaltDB removal: runs when the engine asks to be removed

[Path]
PathExists=%[1]s
Unit=%[2]s

[Install]
WantedBy=paths.target
`, RemovalMarker(goosLinux), linuxRemovalServiceUnit)
	serviceUnit = fmt.Sprintf(`[Unit]
Description=BasaltDB removal

[Service]
Type=oneshot
ExecStart=%[1]s %[2]s
`, shPath, linuxRemovalScript)
	return pathUnit, serviceUnit
}

// removalJobSteps write the job's script and units, root's, mode 0644, and
// load them: the install script's last steps, and the restart script's, so
// an engine installed before the job gets it on its next restart.
func removalJobSteps(goos string) (string, error) {
	script, err := RemovalJobScript(goos)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	put := func(path, end, body string) error {
		if strings.Contains(body, "\n"+end+"\n") || strings.HasPrefix(body, end+"\n") {
			return errors.New("the removal job holds the install script's own end marker")
		}
		fmt.Fprintf(&b, "put_file %s <<'%s'\n%s%s\n", scriptWord(path), end, body, end)
		return nil
	}
	if err := put(removalScriptPath(goos), removalJobEnd, script); err != nil {
		return "", err
	}
	if goos == goosDarwin {
		if err := put(darwinRemovalPlist, removalUnitEnd, darwinRemovalDaemon()); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "launchctl bootout system/%[1]s >/dev/null 2>&1 || true\nlaunchctl bootstrap system %[2]s\n", darwinRemovalLabel, darwinRemovalPlist)
		return b.String(), nil
	}
	pathUnit, serviceUnit := linuxRemovalUnits()
	if err := put(systemdUnitDir+linuxRemovalServiceUnit, removalUnitEnd, serviceUnit); err != nil {
		return "", err
	}
	if err := put(systemdUnitDir+linuxRemovalPathUnit, removalUnitEnd, pathUnit); err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "systemctl daemon-reload\nsystemctl enable --now %s\n", linuxRemovalPathUnit)
	return b.String(), nil
}

// linuxRemoveJob removes the job's units and script, the .path unit
// stopped first. It is safe inside the job itself: stopping the .path unit
// does not stop the running .service.
func linuxRemoveJob() string {
	return fmt.Sprintf(`systemctl disable --now %[1]s >/dev/null 2>&1 || true
rm -f %[2]s%[1]s %[2]s%[3]s %[4]s
`, linuxRemovalPathUnit, systemdUnitDir, linuxRemovalServiceUnit, linuxRemovalScript)
}

// darwinRemoveJob removes the job's plist and script, then unloads the
// job: the last command, because inside the job launchctl bootout of its
// own label ends it.
func darwinRemoveJob() string {
	return fmt.Sprintf(`rm -f %[1]s %[2]s
launchctl bootout system/%[3]s >/dev/null 2>&1 || true
`, darwinRemovalPlist, darwinRemovalScript, darwinRemovalLabel)
}
