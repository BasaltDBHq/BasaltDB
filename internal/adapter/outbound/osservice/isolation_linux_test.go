//go:build linux

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/dial"
)

// The plugin isolation check runs as root in a throwaway Linux container
// (make test-root-container): it makes real OS users and directories. It never
// runs anywhere else.
const isolationEnv = "BASALT_TEST_PLUGIN_ISOLATION"

// isolationChildEnv makes this test binary a child of the isolation check:
// "plugin" reads the files in isolationFilesEnv (exit 10 if any can be
// read), then listens on BASALT_PLUGIN_SOCKET under umask 0007; "connect"
// connects to that socket (exit 0 when it can, 20 when it is refused for
// permissions, 21 otherwise).
const (
	isolationChildEnv = "BASALT_ISOLATION_CHILD"
	isolationFilesEnv = "BASALT_ISOLATION_FILES"
)

func init() {
	if mode := os.Getenv(isolationChildEnv); mode != "" {
		os.Exit(isolationChild(mode))
	}
}

func isolationChild(mode string) int {
	sock := os.Getenv(SocketEnv)
	switch mode {
	case "plugin":
		for _, f := range strings.Split(os.Getenv(isolationFilesEnv), ",") {
			if _, err := os.ReadFile(f); err == nil || !errors.Is(err, os.ErrPermission) {
				return 10
			}
		}
		syscall.Umask(pluginUmask)
		l, err := net.Listen("unix", sock)
		if err != nil {
			return 11
		}
		for {
			c, err := l.Accept()
			if err != nil {
				return 0
			}
			_, _ = io.WriteString(c, "hi\n")
			_ = c.Close()
		}
	case "connect":
		c, err := net.Dial("unix", sock)
		if errors.Is(err, os.ErrPermission) {
			return 20
		}
		if err != nil {
			return 21
		}
		_ = c.Close()
		return 0
	}
	return 2
}

func runCmd(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	require.NoError(t, err, "%v: %s", args, out)
}

func ids(t *testing.T, name string) (uid, gid uint32) {
	t.Helper()
	u, err := user.Lookup(name)
	require.NoError(t, err)
	a, err := strconv.Atoi(u.Uid)
	require.NoError(t, err)
	b, err := strconv.Atoi(u.Gid)
	require.NoError(t, err)
	return uint32(a), uint32(b)
}

// asUser starts this binary as OS user name (its own group only) in mode.
func asUser(t *testing.T, exe, name, mode string, env ...string) *exec.Cmd {
	t.Helper()
	uid, gid := ids(t, name)
	cmd := exec.Command(exe)
	cmd.Env = append([]string{isolationChildEnv + "=" + mode}, env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	return cmd
}

func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	require.NoError(t, err)
	return 0
}

// apply runs the steps that need no service manager: users, directories,
// removals. systemd does not run in the container.
func apply(t *testing.T, steps []Step) {
	t.Helper()
	sys := OSSystem{Stdout: io.Discard, Stderr: io.Discard}
	for _, st := range steps {
		if (st.Kind == StepRun && (st.Args[0] == "systemctl")) || st.Kind == StepWrite {
			continue
		}
		if st.Kind == StepRemove && strings.HasPrefix(st.Path, systemdUnitDir) {
			continue
		}
		require.NoError(t, applyStep(context.Background(), sys, st, io.Discard), st.String())
	}
}

// A plugin run as its entry's OS user cannot read pii.key, the config or an
// agent's credential; the engine's group reaches its socket and the
// listening process is the plugin's user; an agent's OS user and another
// instance's user cannot connect. Network isolation (PrivateNetwork) needs
// systemd and is checked by the golden units only.
func TestPluginIsolationAsRoot(t *testing.T) {
	if os.Getenv(isolationEnv) != "1" || os.Geteuid() != 0 {
		t.Skip("makes OS users: runs as root in a throwaway container only (make test-root-container)")
	}
	// The test binary may sit in a directory only root can enter: copy it
	// where the plugin's user can run it.
	exeDir, err := os.MkdirTemp("/", "bpi")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(exeDir) })
	require.NoError(t, os.Chmod(exeDir, 0o755))
	self, err := os.Executable()
	require.NoError(t, err)
	raw, err := os.ReadFile(self)
	require.NoError(t, err)
	exe := filepath.Join(exeDir, "t")
	require.NoError(t, os.WriteFile(exe, raw, 0o755))

	sys := OSSystem{Stdout: io.Discard, Stderr: io.Discard}
	// A group-writable directory above the base: the base is refused, as any
	// path under it would be. The mode is put back even when an assert fails.
	opt, err := os.Stat("/opt")
	require.NoError(t, err, "/opt holds the plugin base")
	optMode := opt.Mode().Perm() | opt.Mode()&os.ModeSetgid
	t.Cleanup(func() { _ = os.Chmod("/opt", optMode) })
	runCmd(t, "chmod", "2775", "/opt")
	err = sys.Mkdir("/opt/basalt", openDirMode, "", "")
	require.ErrorContains(t, err, "writable by group or others")
	_, err = os.Lstat("/opt/basalt")
	require.ErrorIs(t, err, os.ErrNotExist, "nothing is made under a group-writable directory")
	require.NoError(t, os.Chmod("/opt", optMode))

	for _, u := range []string{"basalt", "agent-one"} {
		if !sys.UserExists(u) {
			runCmd(t, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", u)
		}
	}
	t.Cleanup(func() { _ = exec.Command("userdel", "agent-one").Run() })

	// The engine's files, as the engine's install leaves them.
	engineUID, engineGID := ids(t, "basalt")
	state, cfgDir := "/var/lib/basalt-it", "/etc/basalt-it"
	t.Cleanup(func() { _ = os.RemoveAll(state); _ = os.RemoveAll(cfgDir) })
	require.NoError(t, sys.Mkdir(state, stateDirMode, "basalt", ""))
	require.NoError(t, sys.Mkdir(cfgDir, configDirMode, "basalt", ""))
	require.NoError(t, sys.Mkdir(filepath.Join(cfgDir, "agents"), privateDirMode, "basalt", ""))
	secrets := []string{filepath.Join(state, "pii.key"), filepath.Join(cfgDir, "engine.json"), filepath.Join(cfgDir, "agents", "agent_one.url")}
	for _, f := range secrets {
		require.NoError(t, sys.WriteFile(f, []byte("secret"), 0o600, "basalt"))
	}

	h := PluginHost{GOOS: goosLinux, EngineUser: "basalt", ConfigDir: cfgDir, StateDir: state, SocketDir: "/run/basalt"}
	a := PluginEntry{Name: "acme-ner", Instance: "default", Dir: "/opt/basalt/plugins/acme-ner/default/x", Command: "bin/p", Enabled: true}
	b := a
	b.Instance, b.Dir = "client_x", "/opt/basalt/plugins/acme-ner/client_x/x"
	steps, err := PluginInstallPlan(context.Background(), sys, h, []PluginEntry{a, b})
	require.NoError(t, err)
	apply(t, steps)
	na, err := NamesFor(goosLinux, a.Name, a.Instance)
	require.NoError(t, err)
	nb, err := NamesFor(goosLinux, b.Name, b.Instance)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, k := range []PluginEntry{a, b} {
			if rm, err := PluginRemoveSteps(sys, goosLinux, k.Name, k.Instance); err == nil {
				apply(t, rm)
			}
		}
	})
	ua, _ := ids(t, na.User)
	ub, _ := ids(t, nb.User)
	require.NotEqual(t, ua, ub, "two instances, two users")
	require.NotEqual(t, ua, engineUID)

	fi, err := os.Stat(na.SocketDir)
	require.NoError(t, err)
	st := fi.Sys().(*syscall.Stat_t)
	require.Equal(t, ua, st.Uid)
	require.Equal(t, engineGID, st.Gid)
	require.Equal(t, os.FileMode(0o750), fi.Mode().Perm())
	require.NotZero(t, fi.Mode()&os.ModeSetgid)

	plug := asUser(t, exe, na.User, "plugin", SocketEnv+"="+na.Socket, isolationFilesEnv+"="+strings.Join(secrets, ","))
	exited := make(chan int, 1)
	require.NoError(t, plug.Start())
	go func() {
		err := plug.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exited <- ee.ExitCode()
			return
		}
		exited <- 0
	}()
	t.Cleanup(func() { _ = plug.Process.Kill() })
	require.Eventually(t, func() bool {
		select {
		case code := <-exited:
			t.Fatalf("the plugin exited %d (10: it could read a secret)", code)
		default:
		}
		fi, err := os.Lstat(na.Socket)
		return err == nil && fi.Mode().Type() == os.ModeSocket
	}, 10*time.Second, 20*time.Millisecond, "the plugin listens, after failing to read every secret")

	sfi, err := os.Stat(na.Socket)
	require.NoError(t, err)
	require.Equal(t, engineGID, sfi.Sys().(*syscall.Stat_t).Gid, "the socket is in the engine's group")
	require.Zero(t, sfi.Mode().Perm()&0o007, "others have no access")

	env := SocketEnv + "=" + na.Socket
	require.Equal(t, 0, exitCode(t, asUser(t, exe, "basalt", "connect", env)), "the engine's user connects through its group")
	require.Equal(t, 20, exitCode(t, asUser(t, exe, "agent-one", "connect", env)), "an agent's OS user cannot connect")
	require.Equal(t, 20, exitCode(t, asUser(t, exe, nb.User, "connect", env)), "another instance's user cannot connect")

	// The engine's own check: the listening process is the entry's user.
	c, err := net.Dial("unix", na.Socket)
	require.NoError(t, err)
	require.NoError(t, dial.PeerIs(ua)(c))
	require.ErrorIs(t, dial.PeerIs(ub)(c), dial.ErrWrongPeer)
	_ = c.Close()
	// The engine's per-connection check of the socket directory passes on
	// the one the install made, and the plugin's user is not in its group.
	require.True(t, dial.SocketDirIs(na.SocketDir, ua, engineGID))
	require.False(t, dial.SocketDirIs(na.SocketDir, ua, engineGID+1))
	in, err := sys.InGroup(na.User, "basalt")
	require.NoError(t, err)
	require.False(t, in, "a plugin's user is not in the engine's group")
	in, err = sys.InGroup("basalt", "basalt")
	require.NoError(t, err)
	require.True(t, in, "a primary group counts")

	// Remove deletes the directory and the user.
	_ = plug.Process.Kill()
	<-exited
	rm, err := PluginRemoveSteps(sys, goosLinux, a.Name, a.Instance)
	require.NoError(t, err)
	apply(t, rm)
	_, err = os.Lstat(na.SocketDir)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.False(t, sys.UserExists(na.User))
	require.True(t, sys.UserExists(nb.User), "the other instance is untouched")
}
