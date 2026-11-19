package service_test

import (
	"context"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// machineFS answers SystemdOverrides' reads from files, paths without the
// leading slash.
func machineFS(files fstest.MapFS) (func(string) ([]fs.DirEntry, error), func(string) (fs.FileInfo, error)) {
	rel := func(p string) string { return p[1:] }
	return func(p string) ([]fs.DirEntry, error) { return fs.ReadDir(files, rel(p)) },
		func(p string) (fs.FileInfo, error) { return fs.Stat(files, rel(p)) }
}

const pluginUnit = "basalt-plugin-acme-ner-default.service"

func TestSystemdOverridesFindsEveryDropIn(t *testing.T) {
	t.Parallel()
	conf := &fstest.MapFile{Data: []byte("[Service]\nUser=root\n")}
	for _, path := range []string{
		"etc/systemd/system/basalt-plugin-acme-ner-default.service.d/override.conf",
		"run/systemd/system/basalt-plugin-acme-ner-default.service.d/x.conf",
		"usr/lib/systemd/system/basalt-plugin-acme-ner-default.service.d/x.conf",
		"etc/systemd/system/basalt-.service.d/x.conf",
		"etc/systemd/system/basalt-plugin-.service.d/x.conf",
		"etc/systemd/system/basalt-plugin-acme-.service.d/x.conf",
		"etc/systemd/system/basalt-plugin-acme-ner-.service.d/x.conf",
		"etc/systemd/system/service.d/x.conf",
		"etc/systemd/system.control/basalt-plugin-acme-ner-default.service.d/50-MemoryMax.conf",
		"run/systemd/transient/basalt-plugin-acme-ner-default.service",
		"etc/systemd/system.control/basalt-plugin-acme-ner-default.service",
	} {
		files := fstest.MapFS{
			"etc/systemd/system/" + pluginUnit: {Data: []byte("[Unit]\n")},
			path:                               conf,
		}
		readDir, lstat := machineFS(files)
		found, err := service.SystemdOverrides(pluginUnit, readDir, lstat)
		require.NoError(t, err, path)
		require.Equal(t, []string{"/" + path}, found, path)
	}
}

func TestSystemdOverridesIgnoresWhatSystemdIgnores(t *testing.T) {
	t.Parallel()
	files := fstest.MapFS{
		"etc/systemd/system/" + pluginUnit: {Data: []byte("[Unit]\n")},
		// Not a .conf file, another unit's drop-in, an empty directory.
		"etc/systemd/system/" + pluginUnit + ".d/README":                    {},
		"etc/systemd/system/basalt-engine.service.d/x.conf":                 {},
		"etc/systemd/system/basalt-plugin-acme-ner-other.service.d/x.conf":  {},
		"run/systemd/system/" + pluginUnit + ".d":                           {Mode: fs.ModeDir | 0o755},
		"usr/lib/systemd/system/basalt-plugin-acme-ner-default.service":     {},
		"etc/systemd/system/basalt-plugin-acme-ner-default.service.wants/x": {},
	}
	readDir, lstat := machineFS(files)
	found, err := service.SystemdOverrides(pluginUnit, readDir, lstat)
	require.NoError(t, err)
	require.Empty(t, found)
}

func TestSystemdOverridesFailsClosed(t *testing.T) {
	t.Parallel()
	readDir := func(p string) ([]fs.DirEntry, error) {
		if p == "/run/systemd/system/service.d" {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}
	lstat := func(string) (fs.FileInfo, error) { return nil, os.ErrNotExist }
	_, err := service.SystemdOverrides(pluginUnit, readDir, lstat)
	require.ErrorIs(t, err, os.ErrPermission)
}

// A plugin's OS user that already exists and is in the engine's group is
// refused at install, naming the user and the command that fixes it.
func TestPluginInstallRefusesAUserInTheEnginesGroup(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		h, user, fix := linuxHost(), "basalt-plugin-acme-ner-default", "sudo gpasswd -d basalt-plugin-acme-ner-default basalt"
		if goos == "darwin" {
			h, user, fix = darwinHost(), "_basalt-plugin-acme-ner-default", "sudo dseditgroup -o edit -d _basalt-plugin-acme-ner-default -t user _basalt"
		}
		sys := newFake()
		sys.users[user] = true
		sys.inGroup = map[string]bool{user + " " + h.EngineUser: true}
		_, err := service.PluginInstallPlan(context.Background(), sys, h, []service.PluginEntry{entry(goos, "default")})
		require.ErrorContains(t, err, "its OS user "+user+" is in the engine's group "+h.EngineUser, goos)
		require.ErrorContains(t, err, fix, goos)

		sys.inGroup = nil
		_, err = service.PluginInstallPlan(context.Background(), sys, h, []service.PluginEntry{entry(goos, "default")})
		require.NoError(t, err, goos)
	}
}
