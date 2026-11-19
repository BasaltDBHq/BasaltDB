package service

import (
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

// SystemdOverrides are the files that would change what systemd runs for
// unit beyond its unit file in /etc/systemd/system: every drop-in (*.conf)
// in a drop-in directory systemd applies to it, and a unit file of the same
// name in a directory systemd reads first. readDir and lstat are
// os.ReadDir and os.Lstat on the machine; a directory that cannot be read
// for any reason other than not existing is an error, so the caller fails
// closed.
func SystemdOverrides(unit string, readDir func(string) ([]fs.DirEntry, error), lstat func(string) (fs.FileInfo, error)) ([]string, error) {
	var found []string
	for _, dir := range systemdAbovePluginUnit {
		p := filepath.Join(dir, unit)
		_, err := lstat(p)
		switch {
		case err == nil:
			found = append(found, p)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, err
		}
	}
	for _, dir := range systemdUnitDirs {
		for _, d := range dropInDirNames(unit) {
			entries, err := readDir(filepath.Join(dir, d))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".conf") {
					found = append(found, filepath.Join(dir, d, e.Name()))
				}
			}
		}
	}
	return found, nil
}

// SystemdOverridesOnMachine is SystemdOverrides on this machine.
func SystemdOverridesOnMachine(unit string) ([]string, error) {
	return SystemdOverrides(unit, os.ReadDir, os.Lstat)
}
