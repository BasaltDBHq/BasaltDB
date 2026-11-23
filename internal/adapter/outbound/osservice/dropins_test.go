package osservice_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
)

const pluginUnit = "basalt-plugin-acme-ner-default.service"

// machine is a directory standing in for /, with the plugin's unit file.
type machine string

func newMachine(t *testing.T) machine {
	t.Helper()
	m := machine(t.TempDir())
	m.write(t, "etc/systemd/system/"+pluginUnit, "[Unit]\n")
	return m
}

func (m machine) write(t *testing.T, path, data string) {
	t.Helper()
	p := filepath.Join(string(m), path)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
}

func (m machine) link(t *testing.T, path, target string) {
	t.Helper()
	p := filepath.Join(string(m), path)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.Symlink(target, p))
}

func (m machine) fs() osservice.SystemdFS {
	at := func(p string) string { return filepath.Join(string(m), p) }
	return osservice.SystemdFS{
		ReadDir:  func(p string) ([]fs.DirEntry, error) { return os.ReadDir(at(p)) },
		Lstat:    func(p string) (fs.FileInfo, error) { return os.Lstat(at(p)) },
		Readlink: func(p string) (string, error) { return os.Readlink(at(p)) },
		ReadFile: func(p string) ([]byte, error) { return os.ReadFile(at(p)) },
	}
}

func (m machine) overrides(t *testing.T) []string {
	t.Helper()
	found, err := osservice.SystemdOverrides(pluginUnit, m.fs())
	require.NoError(t, err)
	return found
}

func TestSystemdOverridesFindsEveryDropIn(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"etc/systemd/system/basalt-plugin-acme-ner-default.service.d/override.conf",
		"run/systemd/system/basalt-plugin-acme-ner-default.service.d/x.conf",
		"usr/lib/systemd/system/basalt-plugin-acme-ner-default.service.d/x.conf",
		"etc/systemd/system/basalt-.service.d/x.conf",
		"etc/systemd/system/basalt-plugin-.service.d/x.conf",
		"etc/systemd/system/basalt-plugin-acme-.service.d/x.conf",
		"etc/systemd/system/basalt-plugin-acme-ner-.service.d/x.conf",
		"etc/systemd/system/service.d/x.conf",
		"usr/lib/systemd/system/service.d/x.conf",
		"etc/systemd/system.control/basalt-plugin-acme-ner-default.service.d/50-MemoryMax.conf",
		"run/systemd/transient/basalt-plugin-acme-ner-default.service",
		"etc/systemd/system.control/basalt-plugin-acme-ner-default.service",
	} {
		m := newMachine(t)
		m.write(t, path, "[Service]\nUser=root\n")
		require.Equal(t, []string{"/" + path}, m.overrides(t), path)
	}
}

// Fedora's systemd ships a drop-in for every service that only changes what
// a stop timeout does: it changes no isolation, so it passes.
func TestSystemdOverridesAllowsTheStockFedoraDropIn(t *testing.T) {
	t.Parallel()
	m := newMachine(t)
	m.write(t, "usr/lib/systemd/system/service.d/10-timeout-abort.conf",
		"# This file is part of the systemd package.\n\n[Service]\nTimeoutStopFailureMode=abort\n")
	require.Empty(t, m.overrides(t))

	// A timeout setting next to anything else is an override.
	m.write(t, "etc/systemd/system/service.d/20-more.conf", "[Service]\nTimeoutStopSec=5\nUser=root\n")
	require.Equal(t, []string{"/etc/systemd/system/service.d/20-more.conf"}, m.overrides(t))
}

// A drop-in is resolved by file name as systemd does: a higher-priority file
// of the same name replaces it, and a link to /dev/null or an empty file
// masks it.
func TestSystemdOverridesFollowsMasking(t *testing.T) {
	t.Parallel()
	vendor := "usr/lib/systemd/system/service.d/50-x.conf"
	for name, mask := range map[string]func(m machine){
		"dev/null link": func(m machine) { m.link(t, "etc/systemd/system/service.d/50-x.conf", os.DevNull) },
		"empty file":    func(m machine) { m.write(t, "etc/systemd/system/service.d/50-x.conf", "") },
		"harmless file": func(m machine) { m.write(t, "run/systemd/system/service.d/50-x.conf", "[Service]\nTimeoutSec=9\n") },
	} {
		m := newMachine(t)
		m.write(t, vendor, "[Service]\nUser=root\n")
		require.Equal(t, []string{"/" + vendor}, m.overrides(t), name)
		mask(m)
		require.Empty(t, m.overrides(t), name)
	}

	// A lower-priority file does not mask a higher one.
	m := newMachine(t)
	m.write(t, "etc/systemd/system/service.d/50-x.conf", "[Service]\nUser=root\n")
	m.link(t, "usr/lib/systemd/system/service.d/50-x.conf", os.DevNull)
	require.Equal(t, []string{"/etc/systemd/system/service.d/50-x.conf"}, m.overrides(t))

	// A file masks only the same name in the same drop-in directory name:
	// a harmless shorter dash prefix does not hide a longer one (which
	// systemd applies over it), and service.d does not hide a name-specific
	// drop-in in a lower-priority directory.
	m = newMachine(t)
	m.write(t, "etc/systemd/system/basalt-.service.d/override.conf", "[Service]\nTimeoutSec=5\n")
	m.write(t, "etc/systemd/system/basalt-plugin-.service.d/override.conf", "[Service]\nUser=root\n")
	require.Equal(t, []string{"/etc/systemd/system/basalt-plugin-.service.d/override.conf"}, m.overrides(t))
	for name, mask := range map[string]func(m machine){
		"dev/null link": func(m machine) { m.link(t, "etc/systemd/system/service.d/override.conf", os.DevNull) },
		"empty file":    func(m machine) { m.write(t, "etc/systemd/system/service.d/override.conf", "") },
		"harmless file": func(m machine) { m.write(t, "etc/systemd/system/service.d/override.conf", "[Service]\nTimeoutSec=9\n") },
	} {
		m := newMachine(t)
		mask(m)
		m.write(t, "run/systemd/system/"+pluginUnit+".d/override.conf", "[Service]\nReadWritePaths=/\n")
		require.Equal(t, []string{"/run/systemd/system/" + pluginUnit + ".d/override.conf"}, m.overrides(t), name)
	}

	// A link anywhere else is refused: its target can change.
	m = newMachine(t)
	m.write(t, "srv/x.conf", "[Service]\nTimeoutSec=1\n")
	m.link(t, "etc/systemd/system/service.d/60-y.conf", "/srv/x.conf")
	require.Equal(t, []string{"/etc/systemd/system/service.d/60-y.conf"}, m.overrides(t))
}

func TestSystemdOverridesIgnoresWhatSystemdIgnores(t *testing.T) {
	t.Parallel()
	m := newMachine(t)
	m.write(t, "etc/systemd/system/"+pluginUnit+".d/README", "User=root\n")
	m.write(t, "etc/systemd/system/basalt-engine.service.d/x.conf", "User=root\n")
	m.write(t, "etc/systemd/system/basalt-plugin-acme-ner-other.service.d/x.conf", "User=root\n")
	m.write(t, "usr/lib/systemd/system/"+pluginUnit, "[Unit]\n")
	m.write(t, "etc/systemd/system/"+pluginUnit+".wants/x", "")
	require.NoError(t, os.MkdirAll(filepath.Join(string(m), "run", "systemd", "system", pluginUnit+".d"), 0o755))
	require.Empty(t, m.overrides(t))
}

func TestSystemdOverridesFailsClosed(t *testing.T) {
	t.Parallel()
	m := newMachine(t).fs()
	readDir := m.ReadDir
	m.ReadDir = func(p string) ([]fs.DirEntry, error) {
		if p == "/run/systemd/system/service.d" {
			return nil, os.ErrPermission
		}
		return readDir(p)
	}
	_, err := osservice.SystemdOverrides(pluginUnit, m)
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
		_, err := osservice.PluginInstallPlan(context.Background(), sys, h, []osservice.PluginEntry{entry(goos, "default")})
		require.ErrorContains(t, err, "its OS user "+user+" is in the engine's group "+h.EngineUser, goos)
		require.ErrorContains(t, err, fix, goos)

		sys.inGroup = nil
		_, err = osservice.PluginInstallPlan(context.Background(), sys, h, []osservice.PluginEntry{entry(goos, "default")})
		require.NoError(t, err, goos)
	}
}

// TestSystemdOverridesOnThisMachine: a stock distribution's own drop-ins
// leave a plugin's unit alone. Run inside a distribution image with
// BASALT_TEST_SYSTEMD_HOST=1.
func TestSystemdOverridesOnThisMachine(t *testing.T) {
	if os.Getenv("BASALT_TEST_SYSTEMD_HOST") != "1" {
		t.Skip("reads this machine's systemd directories: run in a distribution image")
	}
	found, err := osservice.SystemdOverridesOnMachine(pluginUnit)
	require.NoError(t, err)
	require.Empty(t, found)
}
