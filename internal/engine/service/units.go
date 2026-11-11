// Package service installs the engine as a system service under its own OS
// user: a systemd unit on Linux, a launchd daemon on macOS (foundation,
// "Credentials": one sudo prompt at basalt init). Install and uninstall are
// plans of steps, printed before they run, so a person sees every command
// that needs root.
package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// Service names and unit locations.
const (
	goosLinux  = "linux"
	goosDarwin = "darwin"

	SystemdUnitName = "basalt-engine.service"
	SystemdUnitPath = "/etc/systemd/system/" + SystemdUnitName
	LaunchdLabel    = "dev.basaltdb.engine"
	LaunchdPlist    = "/Library/LaunchDaemons/" + LaunchdLabel + ".plist"

	linuxUser      = "basalt"
	darwinUser     = "_basalt" // macOS system accounts start with '_'
	darwinLogDir   = "/Library/Logs/Basalt"
	darwinLogFile  = darwinLogDir + "/engine.log"
	launchdUmask   = 0o077
	systemdRunMode = "0755"
)

// Spec is what the unit runs.
type Spec struct {
	// GOOS is linux or darwin.
	GOOS string
	// Binary is the absolute path of the basalt binary.
	Binary string
	// ConfigPath is the engine config file.
	ConfigPath string
	// User is the OS user the engine runs as.
	User string
	// Files are written mode 0600, owned by User, before the service
	// starts: the engine config and an agent's credential from basalt init.
	Files []File
}

// File is one file the install writes for the engine.
type File struct {
	Path    string
	Content []byte
}

// DefaultUser is the engine's OS user on goos.
func DefaultUser(goos string) string {
	if goos == goosDarwin {
		return darwinUser
	}
	return linuxUser
}

// StartCommand is the command that starts the installed engine on goos,
// whether or not its service is loaded yet. On macOS an unloaded job needs
// bootstrap first; when it is already loaded, bootstrap fails harmlessly
// and kickstart starts (or restarts) it.
func StartCommand(goos string) string {
	if goos == goosDarwin {
		return "sudo launchctl bootstrap system " + LaunchdPlist + "; sudo launchctl kickstart -k system/" + LaunchdLabel
	}
	return "sudo systemctl start " + SystemdUnitName
}

// RestartArgs is the command that restarts the installed engine on goos,
// so it picks up a changed config.
func RestartArgs(goos string) []string {
	if goos == goosDarwin {
		return []string{"launchctl", "kickstart", "-k", "system/" + LaunchdLabel}
	}
	return []string{"systemctl", "restart", SystemdUnitName}
}

func (s Spec) args() []string {
	return []string{s.Binary, "engine", "--config", s.ConfigPath}
}

// SystemdUnit renders the Linux unit. The engine gets /run/basalt for its
// sockets and lock, and a read-only view of everything else.
func SystemdUnit(s Spec) string {
	quoted := make([]string, 0, len(s.args()))
	for _, a := range s.args() {
		quoted = append(quoted, systemdQuote(a))
	}
	return fmt.Sprintf(`[Unit]
Description=BasaltDB engine
Documentation=https://github.com/BasaltDBHq/BasaltDB
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[1]s
Group=%[1]s
ExecStart=%[2]s
Restart=on-failure
RestartSec=2s
RuntimeDirectory=basalt
RuntimeDirectoryMode=%[3]s
StateDirectory=basalt
StateDirectoryMode=0700
StateDirectory=basalt
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
`, s.User, strings.Join(quoted, " "), systemdRunMode)
}

// systemdQuote quotes an ExecStart word when it has spaces, quotes or
// backslashes.
func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// LaunchdDaemon renders the macOS launch daemon.
func LaunchdDaemon(s Spec) string {
	var args strings.Builder
	for _, a := range s.args() {
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
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Umask</key>
	<integer>%[4]d</integer>
	<key>StandardErrorPath</key>
	<string>%[5]s</string>
</dict>
</plist>
`, LaunchdLabel, args.String(), xmlEscape(s.User), launchdUmask, darwinLogFile)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	// EscapeText only fails when the writer fails; a bytes.Buffer does not.
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
