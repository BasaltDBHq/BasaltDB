package osservice_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// fakeSystem records what install would do; it never touches the machine.
type fakeSystem struct {
	users   map[string]bool
	outputs map[string]string
	ran     []string
	written map[string]string
	removed []string
	failOn  string
	exists  map[string]bool
	modes   map[string]os.FileMode
	owners  map[string]string
	// binaryErr is what CheckBinary returns.
	binaryErr error
	// removeErr is what Remove returns for a directory under the plugin
	// base (one that is not empty).
	removeErr error
	// inGroup are the "user group" pairs InGroup reports as members.
	inGroup map[string]bool
}

func newFake() *fakeSystem {
	return &fakeSystem{
		users: map[string]bool{}, outputs: map[string]string{}, written: map[string]string{},
		exists: map[string]bool{}, modes: map[string]os.FileMode{}, owners: map[string]string{},
	}
}

func (f *fakeSystem) UserExists(name string) bool { return f.users[name] }

func (f *fakeSystem) InGroup(name, group string) (bool, error) { return f.inGroup[name+" "+group], nil }

func (f *fakeSystem) Exists(path string) bool { return f.exists[path] }

func (f *fakeSystem) Output(_ context.Context, args ...string) (string, error) {
	return f.outputs[strings.Join(args, " ")], nil
}

func (f *fakeSystem) Run(_ context.Context, args ...string) error {
	cmd := strings.Join(args, " ")
	if f.failOn != "" && strings.HasPrefix(cmd, f.failOn) {
		return errors.New("exit status 1")
	}
	f.ran = append(f.ran, cmd)
	return nil
}

func (f *fakeSystem) Mkdir(path string, mode os.FileMode, owner, group string) error {
	if f.failOn == "mkdir" || f.failOn == "mkdir "+path {
		return errors.New("exit status 1")
	}
	f.ran = append(f.ran, fakeMkdir(path, mode, owner, group))
	return nil
}

func (f *fakeSystem) RemoveTree(path string) error {
	f.ran = append(f.ran, "rm -rf "+path)
	return nil
}

func (f *fakeSystem) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	f.owners[path] = owner
	f.written[path] = string(data)
	f.modes[path] = mode
	return nil
}

func (f *fakeSystem) CreateFile(path string, mode os.FileMode, owner string) error {
	f.ran = append(f.ran, fakeCreate(path, mode, owner))
	return nil
}

// MoveAside records the step; a path in f.exists owned (in f.owners) by
// owner is reported moved.
func (f *fakeSystem) MoveAside(path, owner string) (string, error) {
	f.ran = append(f.ran, "move-aside "+path+" "+owner)
	if f.exists[path] && f.owners[path] == owner {
		return path + ".old-20261119T000000Z", nil
	}
	return "", nil
}

// fakeCreate is how the fake records a create step.
func fakeCreate(path string, mode os.FileMode, owner string) string {
	return fmt.Sprintf("create -m %04o -o %s %s", mode.Perm(), owner, path)
}

func (f *fakeSystem) CheckBinary(string) error { return f.binaryErr }

func (f *fakeSystem) Remove(path string) error {
	f.removed = append(f.removed, path)
	if f.removeErr != nil && strings.HasPrefix(path, "/opt/basalt") {
		return f.removeErr
	}
	return os.ErrNotExist
}

func linuxSpec() servicespec.Spec {
	return servicespec.Spec{GOOS: "linux", Binary: "/usr/local/bin/basalt", ConfigPath: "/etc/basalt/engine.json", User: "basalt"}
}

func darwinSpec() servicespec.Spec {
	return servicespec.Spec{
		GOOS: "darwin", Binary: "/usr/local/bin/basalt",
		ConfigPath: "/Library/Application Support/Basalt/engine.json", User: "_basalt",
	}
}

func TestSystemdUnit(t *testing.T) {
	t.Parallel()
	unit := osservice.SystemdUnit(linuxSpec())
	// Every directive is set once: a repeated one is at best noise.
	seen := map[string]bool{}
	for _, line := range strings.Split(unit, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		require.False(t, seen[key], "directive %s set twice", key)
		seen[key] = true
	}
	for _, want := range []string{
		"User=basalt\n",
		"Group=basalt\n",
		"ExecStart=/usr/local/bin/basalt engine --config /etc/basalt/engine.json --supervise\n",
		"RuntimeDirectory=basalt\n",
		"RuntimeDirectoryMode=0755\n",
		"StateDirectory=basalt\n",
		"StateDirectoryMode=0700\n",
		"UMask=0077\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n",
		"ReadWritePaths=/etc/basalt\n",
		"ProtectHome=yes\n",
		"WantedBy=multi-user.target\n",
	} {
		require.Contains(t, unit, want)
	}

	spaced := linuxSpec()
	spaced.ConfigPath = `/etc/my basalt/engine "x".json`
	require.Contains(t, osservice.SystemdUnit(spaced), `ExecStart=/usr/local/bin/basalt engine --config "/etc/my basalt/engine \"x\".json" --supervise`)
	require.Contains(t, osservice.SystemdUnit(spaced), "ReadWritePaths=\"/etc/my basalt\"\n")
}

func TestSystemdUnitEscapesSpecifiersAndVariables(t *testing.T) {
	t.Parallel()
	s := linuxSpec()
	s.Binary = "/opt/100%/basalt"
	s.ConfigPath = "/etc/%h/$HOME/engine.json"
	unit := osservice.SystemdUnit(s)
	require.Contains(t, unit, `ExecStart="/opt/100%%/basalt" engine --config "/etc/%%h/$$HOME/engine.json" --supervise`)
	require.Contains(t, unit, "ReadWritePaths=\"/etc/%%h/$HOME\"\n", "path lists expand specifiers, not variables")
}

func TestLaunchdDaemon(t *testing.T) {
	t.Parallel()
	plist := osservice.LaunchdDaemon(darwinSpec())
	for _, want := range []string{
		"<string>dev.basaltdb.engine</string>",
		"<string>/usr/local/bin/basalt</string>\n\t\t<string>engine</string>\n\t\t<string>--config</string>\n\t\t<string>/Library/Application Support/Basalt/engine.json</string>\n\t\t<string>--supervise</string>",
		"<key>UserName</key>\n\t<string>_basalt</string>",
		"<key>GroupName</key>\n\t<string>_basalt</string>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>Umask</key>\n\t<integer>63</integer>",
	} {
		require.Contains(t, plist, want)
	}
	odd := darwinSpec()
	odd.ConfigPath = "/a&b/<c>.json"
	require.Contains(t, osservice.LaunchdDaemon(odd), "<string>/a&amp;b/&lt;c&gt;.json</string>")
}

func TestUnitsLimitTheEngineMemoryFromThePIIBudget(t *testing.T) {
	t.Parallel()
	unit := osservice.SystemdUnit(linuxSpec())
	require.Contains(t, unit, "MemoryHigh=1536M\n", "three times the default 512 MiB budget")
	require.Contains(t, unit, "MemoryMax=2048M\n")
	plist := osservice.LaunchdDaemon(darwinSpec())
	require.Contains(t, plist, "<key>SoftResourceLimits</key>\n\t<dict>\n\t\t<key>ResidentSetSize</key>\n\t\t<integer>1610612736</integer>")
	require.Contains(t, plist, "<key>HardResourceLimits</key>\n\t<dict>\n\t\t<key>ResidentSetSize</key>\n\t\t<integer>2147483648</integer>")

	small := linuxSpec()
	small.MemoryMB = 64
	unit = osservice.SystemdUnit(small)
	require.Contains(t, unit, "MemoryHigh=192M\n")
	require.Contains(t, unit, "MemoryMax=256M\n")
}

func TestLinuxInstallPlan(t *testing.T) {
	t.Parallel()
	sys := newFake()
	steps, err := osservice.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, osservice.Apply(context.Background(), sys, steps, false, &out))
	require.Equal(t, []string{
		"useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin basalt",
		"mkdir -m 0750 -o basalt /etc/basalt",
		"systemctl daemon-reload",
		"systemctl enable --now basalt-engine.service",
		"mkdir -m 0755 -o root /opt/basalt",
		"mkdir -m 0755 -o root /opt/basalt/run",
	}, sys.ran)
	require.Equal(t, osservice.SystemdUnit(linuxSpec()), sys.written[osservice.SystemdUnitPath])
	require.Contains(t, out.String(), "write /etc/systemd/system/basalt-engine.service")

	sys = newFake()
	sys.users["basalt"] = true
	steps, err = osservice.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	require.NotContains(t, steps[0].String(), "useradd", "an existing user is reused")
}

func TestDarwinInstallPlan(t *testing.T) {
	t.Parallel()
	sys := newFake()
	sys.outputs["dscl . -list /Users UniqueID"] = "_www 70\nroot 0\n_other 300\n"
	sys.outputs["dscl . -list /Groups PrimaryGroupID"] = "_grp 301\n"
	steps, err := osservice.InstallPlan(context.Background(), sys, darwinSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, osservice.Apply(context.Background(), sys, steps, false, &out))
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt UniqueID 302")
	require.Contains(t, sys.ran, "dscl . -create /Groups/_basalt PrimaryGroupID 302")
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt UserShell /usr/bin/false")
	require.Contains(t, sys.ran, "mkdir -m 0755 -o _basalt /Library/Application Support/Basalt/run")
	require.Contains(t, sys.ran, "mkdir -m 0750 -o _basalt /Library/Application Support/Basalt/state")
	// The log directory is root's, so the engine's user cannot swap the
	// plugins' log directory below it; the engine's own log is made, as its
	// user's, before the daemon loads.
	ran := strings.Join(sys.ran, "\n")
	require.Contains(t, ran, "move-aside /Library/Logs/Basalt _basalt\nmkdir -m 0755 -o root /Library/Logs/Basalt\ncreate -m 0600 -o _basalt /Library/Logs/Basalt/engine.log\n")
	require.NotContains(t, out.String(), "moved the old", "nothing to move on a new Mac")
	require.Contains(t, ran, "mkdir -m 0755 -o root /Library/Logs/Basalt/plugins\n")
	require.NotContains(t, ran, "mkdir -m 0750 -o _basalt /Library/Logs")
	require.Contains(t, out.String(), "create -m 0600 -o _basalt /Library/Logs/Basalt/engine.log (kept when it exists)")
	require.Equal(t, []string{
		"launchctl bootstrap system /Library/LaunchDaemons/dev.basaltdb.engine.plist",
		"launchctl enable system/dev.basaltdb.engine",
	}, sys.ran[len(sys.ran)-2:])
	require.Equal(t, osservice.LaunchdDaemon(darwinSpec()), sys.written[osservice.LaunchdPlist])
	require.Contains(t, out.String(), `mkdir -m 0755 -o _basalt "/Library/Application Support/Basalt/run"`)

	// Over an earlier install whose log directory is the engine user's, the
	// install moves it aside itself, says where, and carries on.
	sys = newFake()
	sys.users["_basalt"] = true
	sys.exists[osservice.LaunchdPlist] = true
	sys.exists["/Library/Logs/Basalt"] = true
	sys.owners["/Library/Logs/Basalt"] = "_basalt"
	steps, err = osservice.InstallPlan(context.Background(), sys, darwinSpec())
	require.NoError(t, err)
	out.Reset()
	require.NoError(t, osservice.Apply(context.Background(), sys, steps, false, &out))
	require.Contains(t, out.String(), "  mv /Library/Logs/Basalt /Library/Logs/Basalt.old-<time> (only when _basalt owns it)\n")
	require.Contains(t, out.String(), "  moved the old /Library/Logs/Basalt, which _basalt owned, to /Library/Logs/Basalt.old-20261119T000000Z\n")
	require.Equal(t, "launchctl kickstart -k system/dev.basaltdb.engine", sys.ran[len(sys.ran)-1], "the engine restarts onto the new log")
}

func TestDryRunRunsNothing(t *testing.T) {
	t.Parallel()
	sys := newFake()
	steps, err := osservice.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, osservice.Apply(context.Background(), sys, steps, true, &out))
	require.Empty(t, sys.ran)
	require.Empty(t, sys.written)
	require.Contains(t, out.String(), "systemctl enable --now basalt-engine.service")
}

func TestApplyStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	sys := newFake()
	sys.users["basalt"] = true
	sys.failOn = "mkdir"
	steps, err := osservice.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	err = osservice.Apply(context.Background(), sys, steps, false, &strings.Builder{})
	require.ErrorContains(t, err, "mkdir -m 0750")
	require.Empty(t, sys.written, "no unit written after a failed step")
}

// Whether the service manager runs decides whether a skipped step is
// expected: launchd always runs; systemd only when it booted the system.
func TestManagerRunning(t *testing.T) {
	t.Parallel()
	sys := newFake()
	require.True(t, osservice.ManagerRunning(sys, "darwin"))
	require.False(t, osservice.ManagerRunning(sys, "linux"), "a container without systemd")
	sys.exists["/run/systemd/system"] = true
	require.True(t, osservice.ManagerRunning(sys, "linux"))
}

// A skipped step fails uninstall only where the service manager runs.
func TestSettleSkippedSteps(t *testing.T) {
	t.Parallel()
	skipped := fmt.Errorf("%w: systemctl daemon-reload", osservice.ErrStepsSkipped)
	other := errors.New("rm failed")
	sys := newFake()
	require.NoError(t, osservice.Settle(skipped, sys, "linux"), "no systemd: expected")
	require.ErrorIs(t, osservice.Settle(skipped, sys, "darwin"), osservice.ErrStepsSkipped, "launchd runs")
	require.ErrorIs(t, osservice.Settle(other, sys, "linux"), other)
	require.NoError(t, osservice.Settle(nil, sys, "darwin"))
	sys.exists["/run/systemd/system"] = true
	require.ErrorIs(t, osservice.Settle(skipped, sys, "linux"), osservice.ErrStepsSkipped)
}

func TestSpecValidate(t *testing.T) {
	t.Parallel()
	bad := []servicespec.Spec{
		{GOOS: "windows", Binary: "/b", ConfigPath: "/c", User: "u"},
		{GOOS: "linux", Binary: "basalt", ConfigPath: "/c", User: "u"},
		{GOOS: "linux", Binary: "/b", ConfigPath: "engine.json", User: "u"},
		{GOOS: "linux", Binary: "/b", ConfigPath: "/c", User: "root"},
		{GOOS: "linux", Binary: "/b", ConfigPath: "/c"},
	}
	for _, s := range bad {
		_, err := osservice.InstallPlan(context.Background(), newFake(), s)
		require.Error(t, err, "%+v", s)
	}
}

func TestDefaultUser(t *testing.T) {
	t.Parallel()
	require.Equal(t, "basalt", osservice.DefaultUser("linux"))
	require.Equal(t, "_basalt", osservice.DefaultUser("darwin"))
}

func TestInstallWritesOwnedFilesAndRestartsAnInstalledService(t *testing.T) {
	t.Parallel()
	spec := linuxSpec()
	spec.Files = []servicespec.File{
		{Path: "/etc/basalt/engine.json", Content: []byte(`{"socketDir":"/run/basalt"}`)},
		{Path: "/etc/basalt/agents/bot.url", Content: []byte("postgres://secret")},
	}
	sys := newFake()
	sys.users["basalt"] = true
	sys.exists[osservice.SystemdUnitPath] = true
	steps, err := osservice.InstallPlan(context.Background(), sys, spec)
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, osservice.Apply(context.Background(), sys, steps, false, &out))
	require.Equal(t, []string{
		"mkdir -m 0750 -o basalt /etc/basalt",
		"mkdir -m 0700 -o basalt /etc/basalt/agents",
		"systemctl daemon-reload",
		"systemctl enable basalt-engine.service",
		"systemctl reset-failed basalt-engine.service",
		"systemctl restart basalt-engine.service",
		"mkdir -m 0755 -o root /opt/basalt",
		"mkdir -m 0755 -o root /opt/basalt/run",
	}, sys.ran)
	require.Equal(t, "postgres://secret", sys.written["/etc/basalt/agents/bot.url"])
	require.Equal(t, os.FileMode(0o600), sys.modes["/etc/basalt/agents/bot.url"])
	require.Equal(t, os.FileMode(0o600), sys.modes["/etc/basalt/engine.json"])
	require.Equal(t, os.FileMode(0o644), sys.modes[osservice.SystemdUnitPath])
	require.NotContains(t, out.String(), "secret", "file contents are never printed")

	dspec := darwinSpec()
	dspec.Files = []servicespec.File{{Path: "/Library/Application Support/Basalt/agents/bot.url", Content: []byte("x")}}
	sys = newFake()
	sys.users["_basalt"] = true
	sys.exists[osservice.LaunchdPlist] = true
	steps, err = osservice.InstallPlan(context.Background(), sys, dspec)
	require.NoError(t, err)
	require.NoError(t, osservice.Apply(context.Background(), sys, steps, false, &strings.Builder{}))
	require.Contains(t, sys.ran, "mkdir -m 0700 -o _basalt /Library/Application Support/Basalt/agents")
	require.Equal(t, "_basalt", sys.owners["/Library/Application Support/Basalt/agents/bot.url"])
	require.Equal(t, "launchctl kickstart -k system/dev.basaltdb.engine", sys.ran[len(sys.ran)-1])
	require.NotContains(t, sys.ran, "launchctl bootstrap system "+osservice.LaunchdPlist)
}

// fakeMkdir is how the fakes record a mkdir step: the path as it is.
func fakeMkdir(path string, mode os.FileMode, owner, group string) string {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if owner == "" {
		owner = "root"
	}
	if group != "" {
		owner += " -g " + group
	}
	return fmt.Sprintf("mkdir -m %04o -o %s %s", bits, owner, path)
}

// The install makes the directories with the modes the unit gives them: the
// socket directory 0755 and the state directory 0700 on Linux (0750 on
// macOS).
func TestEngineDirsMatchTheUnit(t *testing.T) {
	unit := osservice.SystemdUnit(servicespec.Spec{GOOS: "linux", Binary: "/usr/local/libexec/basalt", ConfigPath: "/etc/basalt/engine.json", User: "basalt"})
	require.Contains(t, unit, "RuntimeDirectory=basalt\nRuntimeDirectoryMode=0755\n")
	require.Contains(t, unit, "StateDirectory=basalt\nStateDirectoryMode=0700\n")

	sys := newFake()
	sys.users["_basalt"] = true
	steps, err := osservice.InstallPlan(context.Background(), sys, darwinSpec())
	require.NoError(t, err)
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/Library/Application Support/Basalt/run", 0o755},
		{"/Library/Application Support/Basalt/state", 0o750},
	} {
		require.Contains(t, steps, osservice.Step{Kind: osservice.StepMkdir, Path: d.path, Mode: d.mode, Owner: "_basalt"}, d.path)
	}
}
