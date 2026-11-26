// Package service installs the engine as a system service under its own OS
// user: a systemd unit on Linux, a launchd daemon on macOS, set up with
// one sudo prompt at basalt init. Install and uninstall are
// plans of steps, printed before they run, so a person sees every command
// that needs root.
package osservice

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Service names and unit locations.
const (
	goosLinux  = "linux"
	goosDarwin = "darwin"

	SystemdUnitPath = "/etc/systemd/system/" + servicespec.SystemdUnitName
	LaunchdPlist    = "/Library/LaunchDaemons/" + servicespec.LaunchdLabel + ".plist"

	linuxUser     = "basalt"
	darwinUser    = "_basalt" // macOS system accounts start with '_'
	darwinLogDir  = "/Library/Logs/Basalt"
	darwinLogFile = darwinLogDir + "/engine.log"
	launchdUmask  = 0o077

	// runtimeDirMode is the socket directory's mode: open, so an agent's
	// OS user reaches its socket (the socket itself is 0666 and checks the
	// peer's uid). stateDirMode is the Linux state directory's, the
	// engine's alone; darwinStateDirMode is the macOS install's.
	runtimeDirMode     = 0o755
	stateDirMode       = 0o700
	darwinStateDirMode = configDirMode
)

// pluginHostOf is what s's plugin units hide and who reaches their
// sockets. It is plugin.HostFor's, from the fields plugin.ServiceUnits copied out
// of it.
func pluginHostOf(s servicespec.Spec) servicespec.PluginHost {
	h := servicespec.PluginHost{
		GOOS: s.GOOS, EngineUser: s.User, ConfigDir: filepath.Dir(s.ConfigPath),
		StateDir: s.StateDir, SocketDir: s.SocketDir, CredentialFiles: s.CredentialFiles,
	}
	if h.StateDir == "" {
		h.StateDir = config.DefaultStateDir(s.GOOS)
	}
	if h.SocketDir == "" {
		h.SocketDir = config.DefaultSocketDir(s.GOOS)
	}
	return h
}

// The unit's memory limits, as multiples of pii.maxMemoryMB: the Go heap
// is soft-limited to twice the budget (GOMEMLIMIT, a dictionary build and
// the rest of the engine), and the mapped dictionary file takes up to the
// budget again. MemoryHigh throttles past that; MemoryMax stops the engine.
// The limits are written at install time: after raising pii.maxMemoryMB,
// basalt service install must run again to rewrite them. On macOS the
// plist's ResidentSetSize limits are written for the record only: current
// macOS does not enforce them, so GOMEMLIMIT is the only limit there.
const (
	memoryHighFactor = 3
	memoryMaxFactor  = 4
)

// bytesPerMB converts the units' MiB limits, which pii.maxMemoryMB sets
// for the engine, as pii converts its budget.
const bytesPerMB = pii.BytesPerMB

// memoryLimitsMB are the soft and hard limits for s, in MiB.
func memoryLimitsMB(s servicespec.Spec) (high, hard int) {
	mb := s.MemoryMB
	if mb <= 0 {
		mb = config.DefaultPIIMaxMemoryMB
	}
	return mb * memoryHighFactor, mb * memoryMaxFactor
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
		return "sudo launchctl bootstrap system " + LaunchdPlist + "; sudo launchctl kickstart -k system/" + servicespec.LaunchdLabel
	}
	return "sudo systemctl start " + servicespec.SystemdUnitName
}

// RestartArgs is the command that restarts the installed engine on goos,
// so it picks up a changed config.
func RestartArgs(goos string) []string {
	if goos == goosDarwin {
		return []string{"launchctl", "kickstart", "-k", "system/" + servicespec.LaunchdLabel}
	}
	return []string{"systemctl", "restart", servicespec.SystemdUnitName}
}

// RestartScript is the fixed script that restarts the installed engine
// service on goos onto src, the basalt that runs it: built from constants
// and src only. When src is the service's own copy it is one command;
// otherwise it first copies src over that copy, root's, as the install does
// (InstallScript), so an upgraded basalt (brew upgrade) reaches the service
// in the same administrator dialog.
func RestartScript(goos string, src Source) (string, error) {
	if goos != goosDarwin && goos != goosLinux {
		return "", fmt.Errorf("no engine service to restart on %s", goos)
	}
	restart := strings.Join(RestartArgs(goos), " ") + "\n"
	if !src.copies(goos) {
		return restart, nil
	}
	if err := src.validate(); err != nil {
		return "", err
	}
	return scriptHelpers(goos) + ScriptHelpersEnd + sourceCheck(goos, src) + ScriptPreflightEnd + copyBinary(goos, src) + restart, nil
}

// specArgs is the command line s's unit runs.
func specArgs(s servicespec.Spec) []string {
	return []string{s.Binary, "engine", "--config", s.ConfigPath, "--supervise"}
}

// SystemdUnit renders the Linux unit. The engine gets /run/basalt for its
// sockets and lock, its state directory, its config directory (where it
// takes an agent's lock, promotes a .pending credential and clears a
// finished setup from engine.json), and a read-only view of everything
// else.
func SystemdUnit(s servicespec.Spec) string {
	quoted := make([]string, 0, len(specArgs(s)))
	for _, a := range specArgs(s) {
		quoted = append(quoted, systemdQuote(a))
	}
	high, hard := memoryLimitsMB(s)
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
RuntimeDirectoryMode=%04[3]o
StateDirectory=basalt
StateDirectoryMode=%04[6]o
UMask=0077
MemoryHigh=%[4]dM
MemoryMax=%[5]dM
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%[7]s
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
`, s.User, strings.Join(quoted, " "), runtimeDirMode, high, hard, stateDirMode, systemdPath("", filepath.Dir(s.ConfigPath)))
}

// systemdQuote writes an ExecStart word: as it is when it has nothing special,
// else in double quotes with '\' and '"' escaped and '%' and '$' doubled: the
// service manager expands specifiers and variables in ExecStart.
func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\%$") {
		return s
	}
	return systemdExecWord(s)
}

// LaunchdDaemon renders the macOS launch daemon.
func LaunchdDaemon(s servicespec.Spec) string {
	high, hard := memoryLimitsMB(s)
	var args strings.Builder
	for _, a := range specArgs(s) {
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
	<key>SoftResourceLimits</key>
	<dict>
		<key>ResidentSetSize</key>
		<integer>%[6]d</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>ResidentSetSize</key>
		<integer>%[7]d</integer>
	</dict>
</dict>
</plist>
`, servicespec.LaunchdLabel, args.String(), xmlEscape(s.User), launchdUmask, darwinLogFile, int64(high)*bytesPerMB, int64(hard)*bytesPerMB)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	// EscapeText only fails when the writer fails; a bytes.Buffer does not.
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// InstallScriptFor is InstallScript for the binary at path, read with
// ReadSource.
func InstallScriptFor(goos, path string) (string, error) {
	src, err := ReadSource(path)
	if err != nil {
		return "", err
	}
	return InstallScript(goos, src)
}

// RestartScriptFor is RestartScript for the binary at path, read with
// ReadSource.
func RestartScriptFor(goos, path string) (string, error) {
	src, err := ReadSource(path)
	if err != nil {
		return "", err
	}
	return RestartScript(goos, src)
}
