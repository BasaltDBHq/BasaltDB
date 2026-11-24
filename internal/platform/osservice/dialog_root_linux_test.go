//go:build linux

package osservice_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// The install script runs as root only in a throwaway Linux container
// (make test-root-container): it makes real OS users and folders and replaces
// systemctl with a stub.
const rootScriptEnv = "BASALT_TEST_PLUGIN_ISOLATION"

const rootBinary = "/usr/local/bin/basalt"

// serviceBinary is the service's own copy the script makes.
var serviceBinary = osservice.ServiceBinary("linux")

// runInstall runs the Linux install script for binary as root.
func runInstall(t *testing.T, binary string) (string, error) {
	t.Helper()
	src, err := osservice.ReadSource(binary)
	require.NoError(t, err)
	return runInstallOf(t, src)
}

// runInstallOf runs the Linux install script for src as root.
func runInstallOf(t *testing.T, src osservice.Source) (string, error) {
	t.Helper()
	script, err := osservice.InstallScript("linux", src)
	require.NoError(t, err)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	return string(out), err
}

// requireServiceCopy: the service's copy is a plain file, root:root 0755,
// with want's content.
func requireServiceCopy(t *testing.T, want string) {
	t.Helper()
	require.True(t, exists(`[ ! -L `+serviceBinary+` ] && [ "$(stat -c '%U:%G %a %F' `+serviceBinary+`)" = "root:root 755 regular file" ]`), "the copy is root's, 0755")
	require.True(t, exists("cmp -s "+want+" "+serviceBinary), "the copy is the basalt that ran")
	require.NoFileExists(t, serviceBinary+".basalt-new")
}

func sh(t *testing.T, cmd string) {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	require.NoError(t, err, "%s: %s", cmd, out)
}

func exists(cmd string) bool { return exec.Command("/bin/sh", "-c", cmd).Run() == nil }

// requireRefused: the script stopped with want, and left no basalt user,
// no /etc/basalt and no unit behind.
func requireRefused(t *testing.T, binary, want string) {
	t.Helper()
	out, err := runInstall(t, binary)
	require.Error(t, err, out)
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitCode(), out)
	require.Contains(t, out, want)
	require.False(t, exists("getent passwd basalt"), "no OS user is left behind: %s", out)
	require.NoFileExists(t, osservice.SystemdUnitPath)
}

func TestInstallScriptAsRoot(t *testing.T) {
	if os.Getenv(rootScriptEnv) != "1" || os.Geteuid() != 0 {
		t.Skip("runs as root in a throwaway container: make test-root-container")
	}
	// A stub systemctl records its calls; the binary is root's, 0755.
	sh(t, `printf '#!/bin/sh\necho "$*" >>/tmp/systemctl.log\n' >/usr/bin/systemctl && chmod 0755 /usr/bin/systemctl`)
	sh(t, "mkdir -p /etc/systemd/system /usr/local/bin && install -o root -g root -m 0755 /bin/true "+rootBinary)
	clean := func() {
		sh(t, "userdel basalt 2>/dev/null; groupdel basalt 2>/dev/null; rm -rf /etc/basalt /opt/basalt "+osservice.SystemdUnitPath+
			" "+serviceBinary+" "+serviceBinary+".basalt-new /tmp/evil-basalt"+
			"; mkdir -p /usr/libexec; chmod 0755 /etc/systemd/system /usr/local/bin /usr/libexec; chown root:root "+rootBinary+"; chmod 0755 "+rootBinary+"; true")
	}
	clean()
	t.Cleanup(clean)

	t.Run("a unit folder others can write: nothing is created", func(t *testing.T) {
		defer clean()
		sh(t, "chmod 0777 /etc/systemd/system")
		requireRefused(t, rootBinary, "/etc/systemd/system is writable by group or others")
		require.NoDirExists(t, "/etc/basalt")
	})
	t.Run("a basalt the person's account can change is copied, root's", func(t *testing.T) {
		defer clean()
		// A Homebrew-like prefix: a folder others can write, a binary
		// nobody (not root) owns, writable by others.
		dir := t.TempDir()
		bin := filepath.Join(dir, "basalt")
		sh(t, "chmod 0777 "+dir+" && install -o nobody -m 0777 /bin/true "+bin)
		out, err := runInstall(t, bin)
		require.NoError(t, err, out)
		requireServiceCopy(t, bin)
		unit, err := os.ReadFile(osservice.SystemdUnitPath)
		require.NoError(t, err)
		require.Contains(t, string(unit), "ExecStart="+serviceBinary+" engine --config /etc/basalt/engine.json --supervise\n")
		require.NotContains(t, string(unit), bin)
	})
	t.Run("an older copy is replaced whole", func(t *testing.T) {
		defer clean()
		sh(t, "install -o root -g root -m 0755 /bin/false "+serviceBinary)
		before, err := os.Stat(serviceBinary)
		require.NoError(t, err)
		out, err := runInstall(t, rootBinary)
		require.NoError(t, err, out)
		requireServiceCopy(t, rootBinary)
		after, err := os.Stat(serviceBinary)
		require.NoError(t, err)
		require.False(t, os.SameFile(before, after), "a new file renamed into place, not a write into the one the service runs")
	})
	t.Run("a symlinked copy: nothing is created", func(t *testing.T) {
		defer clean()
		sh(t, "printf keep >/tmp/evil-basalt && ln -s /tmp/evil-basalt "+serviceBinary)
		requireRefused(t, rootBinary, serviceBinary+" is a symlink")
		b, err := os.ReadFile("/tmp/evil-basalt")
		require.NoError(t, err)
		require.Equal(t, "keep", string(b), "the link's target is untouched")
		require.NoDirExists(t, "/etc/basalt")
	})
	t.Run("a copy folder others can write: nothing is created", func(t *testing.T) {
		defer clean()
		sh(t, "chmod 0777 /usr/libexec")
		requireRefused(t, rootBinary, "/usr/libexec is writable by group or others")
		require.NoFileExists(t, serviceBinary)
	})
	t.Run("a basalt changed after init read it: nothing is created", func(t *testing.T) {
		defer clean()
		src, err := osservice.ReadSource("/bin/false")
		require.NoError(t, err)
		src.Path = rootBinary // /bin/true is there now, not what was read
		out, err := runInstallOf(t, src)
		require.Error(t, err, out)
		require.Contains(t, out, rootBinary+" changed after basalt init read it")
		require.NoFileExists(t, serviceBinary)
		require.NoFileExists(t, serviceBinary+".basalt-new")
		require.False(t, exists("getent passwd basalt"), "no OS user is left behind: %s", out)
		require.NoFileExists(t, osservice.SystemdUnitPath)
	})
	t.Run("a config folder that is a symlink another user owns", func(t *testing.T) {
		defer clean()
		sh(t, "mkdir -p /srv/evil && ln -s /srv/evil /etc/basalt && chown -h nobody /etc/basalt")
		requireRefused(t, rootBinary, "/etc/basalt is a symlink root does not own")
		sh(t, "rm /etc/basalt")
	})
	t.Run("an existing account with a person's uid", func(t *testing.T) {
		defer clean()
		sh(t, "useradd --uid 1500 --shell /usr/sbin/nologin basalt")
		out, err := runInstall(t, rootBinary)
		require.Error(t, err)
		require.Contains(t, out, "the OS user basalt exists with uid 1500, not a system account")
		require.NoFileExists(t, osservice.SystemdUnitPath)
	})
	t.Run("an existing system account with a login shell", func(t *testing.T) {
		defer clean()
		sh(t, "useradd --system --shell /bin/bash basalt")
		out, err := runInstall(t, rootBinary)
		require.Error(t, err)
		require.Contains(t, out, "the OS user basalt exists with the login shell /bin/bash")
		require.NoFileExists(t, osservice.SystemdUnitPath)
	})
	t.Run("a group without the user", func(t *testing.T) {
		defer clean()
		sh(t, "groupadd --system basalt")
		requireRefused(t, rootBinary, "the group basalt exists without the OS user basalt")
	})
	t.Run("installs, and again", func(t *testing.T) {
		defer clean()
		sh(t, "rm -f /tmp/systemctl.log")
		for range 2 {
			out, err := runInstall(t, rootBinary)
			require.NoError(t, err, out)
		}
		require.True(t, exists("getent passwd basalt | grep -q ':/usr/sbin/nologin$'"), "a system user that cannot log in")
		require.True(t, exists(`[ "$(stat -c '%U:%G %a' /etc/basalt)" = "basalt:basalt 750" ]`))
		require.True(t, exists(`[ "$(stat -c '%U:%G %a' /opt/basalt /opt/basalt/run | sort -u)" = "root:root 755" ]`), "the plugin base, root's")
		require.True(t, exists(`[ "$(stat -c '%U:%G %a' `+osservice.SystemdUnitPath+`)" = "root:root 644" ]`))
		unit, err := os.ReadFile(osservice.SystemdUnitPath)
		require.NoError(t, err)
		require.Contains(t, string(unit), "ExecStart="+serviceBinary+" engine --config /etc/basalt/engine.json --supervise\n")
		requireServiceCopy(t, rootBinary)
		log, err := os.ReadFile("/tmp/systemctl.log")
		require.NoError(t, err)
		require.Equal(t, strings.Repeat("daemon-reload\nenable --now basalt-engine.service\n", 2), string(log))
	})
}

// runRemove runs the Linux removal script as root.
func runRemove(t *testing.T) (string, error) {
	t.Helper()
	script, err := osservice.RemoveScript("linux")
	require.NoError(t, err)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	return string(out), err
}

func TestRemoveScriptAsRoot(t *testing.T) {
	if os.Getenv(rootScriptEnv) != "1" || os.Geteuid() != 0 {
		t.Skip("runs as root in a throwaway container: make test-root-container")
	}
	sh(t, `printf '#!/bin/sh\necho "$*" >>/tmp/systemctl.log\n' >/usr/bin/systemctl && chmod 0755 /usr/bin/systemctl`)
	sh(t, "mkdir -p /etc/systemd/system /usr/local/bin && install -o root -g root -m 0755 /bin/true "+rootBinary)
	clean := func() {
		sh(t, "for u in basalt basalt-plugin-ner-default basalt-plugin-shell-default; do userdel $u 2>/dev/null; done; groupdel basalt 2>/dev/null; "+
			"rm -rf /etc/basalt /var/lib/basalt /run/basalt /opt/basalt /etc/systemd/system/basalt-*.service /tmp/systemctl.log "+serviceBinary+"; true")
	}
	clean()
	t.Cleanup(clean)
	// installed is an engine the install script made, with one plugin
	// entry's unit, user and socket directory as service install makes
	// them, and a state directory.
	installed := func(t *testing.T) {
		t.Helper()
		out, err := runInstall(t, rootBinary)
		require.NoError(t, err, out)
		sh(t, "mkdir -m 0700 /var/lib/basalt && chown basalt:basalt /var/lib/basalt")
		sh(t, "useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin basalt-plugin-ner-default")
		sh(t, "mkdir /opt/basalt/run/basalt-plugin-ner-default && touch /etc/systemd/system/basalt-plugin-ner-default.service")
		sh(t, "rm -f /tmp/systemctl.log")
	}

	t.Run("an engine.json left: nothing is removed", func(t *testing.T) {
		defer clean()
		installed(t)
		sh(t, "touch /etc/basalt/engine.json")
		out, err := runRemove(t)
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, out)
		require.Equal(t, 1, exitErr.ExitCode(), out)
		require.Contains(t, out, "/etc/basalt/engine.json still exists")
		require.FileExists(t, osservice.SystemdUnitPath)
		require.FileExists(t, "/etc/systemd/system/basalt-plugin-ner-default.service")
		require.True(t, exists("getent passwd basalt"))
		require.NoFileExists(t, "/tmp/systemctl.log", "nothing was stopped")
	})
	t.Run("removes the engine and its plugins", func(t *testing.T) {
		defer clean()
		installed(t)
		// A plugin-prefixed account that can log in is not the install's.
		sh(t, "useradd --system --shell /bin/sh basalt-plugin-shell-default")
		out, err := runRemove(t)
		require.NoError(t, err, out)
		require.NoFileExists(t, osservice.SystemdUnitPath)
		require.NoFileExists(t, "/etc/systemd/system/basalt-plugin-ner-default.service")
		for _, d := range []string{"/etc/basalt", "/var/lib/basalt", "/opt/basalt"} {
			require.NoDirExists(t, d)
		}
		require.NoFileExists(t, serviceBinary, "the service's copy of basalt is deleted")
		require.False(t, exists("getent passwd basalt"), out)
		require.False(t, exists("getent group basalt"), out)
		require.False(t, exists("getent passwd basalt-plugin-ner-default"), out)
		require.True(t, exists("getent passwd basalt-plugin-shell-default"), "an account that can log in stays")
		require.Contains(t, out, "basalt-plugin-shell-default can log in, so it was left in place")
		log, err := os.ReadFile("/tmp/systemctl.log")
		require.NoError(t, err)
		require.Contains(t, string(log), "disable --now basalt-engine.service\n")
		require.Contains(t, string(log), "disable --now basalt-plugin-ner-default.service\n")
		require.Contains(t, string(log), "daemon-reload\n")

		// Run again: nothing is left, and it still succeeds.
		out, err = runRemove(t)
		require.NoError(t, err, out)
	})
	t.Run("an engine account that is not the install's stays", func(t *testing.T) {
		defer clean()
		sh(t, "useradd --uid 1500 --shell /usr/sbin/nologin basalt")
		out, err := runRemove(t)
		require.NoError(t, err, out)
		require.True(t, exists("getent passwd basalt"))
		require.Contains(t, out, "not the system account the install made")
	})
}
