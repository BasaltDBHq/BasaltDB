//go:build linux

package service_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// The install script runs as root only in a throwaway Linux container
// (make test-privdrop): it makes real OS users and folders and replaces
// systemctl with a stub.
const rootScriptEnv = "BASALT_TEST_PLUGIN_ISOLATION"

const rootBinary = "/usr/local/bin/basalt"

// runInstall runs the Linux install script for binary as root.
func runInstall(t *testing.T, binary string) (string, error) {
	t.Helper()
	script, err := service.InstallScript("linux", binary)
	require.NoError(t, err)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	return string(out), err
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
	require.NoFileExists(t, service.SystemdUnitPath)
}

func TestInstallScriptAsRoot(t *testing.T) {
	if os.Getenv(rootScriptEnv) != "1" || os.Geteuid() != 0 {
		t.Skip("runs as root in a throwaway container: make test-privdrop")
	}
	// A stub systemctl records its calls; the binary is root's, 0755.
	sh(t, `printf '#!/bin/sh\necho "$*" >>/tmp/systemctl.log\n' >/usr/bin/systemctl && chmod 0755 /usr/bin/systemctl`)
	sh(t, "mkdir -p /etc/systemd/system /usr/local/bin && install -o root -g root -m 0755 /bin/true "+rootBinary)
	clean := func() {
		sh(t, "userdel basalt 2>/dev/null; groupdel basalt 2>/dev/null; rm -rf /etc/basalt "+service.SystemdUnitPath+
			"; chmod 0755 /etc/systemd/system /usr/local/bin; chown root:root "+rootBinary+"; chmod 0755 "+rootBinary+"; true")
	}
	clean()
	t.Cleanup(clean)

	t.Run("a unit folder others can write: nothing is created", func(t *testing.T) {
		defer clean()
		sh(t, "chmod 0777 /etc/systemd/system")
		requireRefused(t, rootBinary, "/etc/systemd/system is writable by group or others")
		require.NoDirExists(t, "/etc/basalt")
	})
	t.Run("a binary others can write", func(t *testing.T) {
		defer clean()
		sh(t, "chmod 0777 "+rootBinary)
		requireRefused(t, rootBinary, rootBinary+" is writable by group or others")
	})
	t.Run("a binary below a folder others can write", func(t *testing.T) {
		defer clean()
		dir := t.TempDir()
		sh(t, "chmod 0777 "+dir+" && install -o root -m 0755 /bin/true "+dir+"/basalt")
		requireRefused(t, filepath.Join(dir, "basalt"), "is writable by group or others")
	})
	t.Run("a binary root does not own", func(t *testing.T) {
		defer clean()
		sh(t, "chown nobody "+rootBinary)
		requireRefused(t, rootBinary, rootBinary+" is not owned by root")
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
		require.NoFileExists(t, service.SystemdUnitPath)
	})
	t.Run("an existing system account with a login shell", func(t *testing.T) {
		defer clean()
		sh(t, "useradd --system --shell /bin/bash basalt")
		out, err := runInstall(t, rootBinary)
		require.Error(t, err)
		require.Contains(t, out, "the OS user basalt exists with the login shell /bin/bash")
		require.NoFileExists(t, service.SystemdUnitPath)
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
		require.True(t, exists(`[ "$(stat -c '%U:%G %a' `+service.SystemdUnitPath+`)" = "root:root 644" ]`))
		unit, err := os.ReadFile(service.SystemdUnitPath)
		require.NoError(t, err)
		require.Contains(t, string(unit), "ExecStart="+rootBinary+" engine --config /etc/basalt/engine.json --supervise\n")
		log, err := os.ReadFile("/tmp/systemctl.log")
		require.NoError(t, err)
		require.Equal(t, strings.Repeat("daemon-reload\nenable --now basalt-engine.service\n", 2), string(log))
	})
}
