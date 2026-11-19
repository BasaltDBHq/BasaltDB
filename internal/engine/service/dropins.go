package service

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// systemdUnitDirs are the directories systemd reads system units and their
// drop-ins from, highest priority first (systemd.unit(5), "Unit File Load
// Path"). A plugin's unit is written to /etc/systemd/system.
var systemdUnitDirs = []string{
	"/etc/systemd/system.control",
	"/run/systemd/system.control",
	"/run/systemd/transient",
	"/run/systemd/generator.early",
	"/etc/systemd/system",
	"/etc/systemd/system.attached",
	"/run/systemd/system",
	"/run/systemd/system.attached",
	"/run/systemd/generator",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/run/systemd/generator.late",
}

// systemdAbovePluginUnit are the directories whose unit file of the same
// name systemd would load instead of the one in /etc/systemd/system.
var systemdAbovePluginUnit = systemdUnitDirs[:4]

// dropInDirNames are the drop-in directory names systemd applies to unit:
// <unit>.d, then one for each prefix of the name up to a dash
// (basalt-.service.d, basalt-plugin-.service.d, ...), then the one for every
// service (service.d).
func dropInDirNames(unit string) []string {
	name, suffix, _ := strings.Cut(unit, ".")
	names := []string{unit + ".d"}
	for i := range len(name) {
		if name[i] == '-' {
			names = append(names, name[:i+1]+"."+suffix+".d")
		}
	}
	return append(names, suffix+".d")
}

// harmlessDropInKeys are the only settings a drop-in may hold and still
// leave a plugin's unit as the engine compared it: how long systemd waits
// to start or stop it, and what it does when that runs out. None of them
// touches who the plugin runs as, what it can reach or what it runs.
// Fedora's systemd ships service.d/10-timeout-abort.conf with one of them.
var harmlessDropInKeys = map[string]bool{
	"TimeoutSec": true, "TimeoutStartSec": true, "TimeoutStopSec": true, "TimeoutAbortSec": true,
	"TimeoutStartFailureMode": true, "TimeoutStopFailureMode": true,
}

// SystemdFS is how SystemdOverrides reads the machine: os.ReadDir,
// os.Lstat, os.Readlink and os.ReadFile there.
type SystemdFS struct {
	ReadDir  func(string) ([]fs.DirEntry, error)
	Lstat    func(string) (fs.FileInfo, error)
	Readlink func(string) (string, error)
	ReadFile func(string) ([]byte, error)
}

// SystemdOverrides are the files that would change what systemd runs for
// unit beyond its unit file in /etc/systemd/system:
//   - a unit file of the same name in a directory systemd reads first;
//   - a drop-in (*.conf) systemd applies to it that sets anything but the
//     harmless timeout settings.
//
// Drop-ins are resolved as systemd does: by file name across every drop-in
// directory that applies, the one in the highest-priority directory wins,
// and a winner that is a link to /dev/null or empty masks that name. A file
// or directory that cannot be read for any reason other than not existing
// is an error, so the caller fails closed.
func SystemdOverrides(unit string, m SystemdFS) ([]string, error) {
	var found []string
	for _, dir := range systemdAbovePluginUnit {
		p := filepath.Join(dir, unit)
		_, err := m.Lstat(p)
		switch {
		case err == nil:
			found = append(found, p)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, dir := range systemdUnitDirs {
		for _, d := range dropInDirNames(unit) {
			entries, err := m.ReadDir(filepath.Join(dir, d))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				name := e.Name()
				if !strings.HasSuffix(name, ".conf") || seen[name] {
					continue
				}
				seen[name] = true
				p := filepath.Join(dir, d, name)
				changes, err := dropInChanges(p, m)
				if err != nil {
					return nil, err
				}
				if changes {
					found = append(found, p)
				}
			}
		}
	}
	return found, nil
}

// dropInChanges reports whether drop-in p changes the unit: false when it
// masks its name (a link to /dev/null, or empty) or sets only harmless
// timeout settings.
func dropInChanges(p string, m SystemdFS) (bool, error) {
	fi, err := m.Lstat(p)
	if err != nil {
		return false, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := m.Readlink(p)
		if err == nil && target == os.DevNull {
			return false, nil
		}
		// Any other link: what it points at can change; refuse.
		return true, nil
	}
	data, err := m.ReadFile(p)
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			return true, nil // a continued line: refuse rather than parse
		}
		if line == "[Service]" || line == "[Unit]" {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok || !harmlessDropInKeys[strings.TrimSpace(key)] {
			return true, nil
		}
	}
	return false, sc.Err()
}

// SystemdOverridesOnMachine is SystemdOverrides on this machine.
func SystemdOverridesOnMachine(unit string) ([]string, error) {
	return SystemdOverrides(unit, SystemdFS{ReadDir: os.ReadDir, Lstat: os.Lstat, Readlink: os.Readlink, ReadFile: os.ReadFile})
}
