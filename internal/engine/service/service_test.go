package service_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
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
}

func newFake() *fakeSystem {
	return &fakeSystem{
		users: map[string]bool{}, outputs: map[string]string{}, written: map[string]string{},
		exists: map[string]bool{}, modes: map[string]os.FileMode{}, owners: map[string]string{},
	}
}

func (f *fakeSystem) UserExists(name string) bool { return f.users[name] }

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

func (f *fakeSystem) Mkdir(path string, mode os.FileMode, owner string) error {
	if f.failOn == "mkdir" {
		return errors.New("exit status 1")
	}
	f.ran = append(f.ran, fmt.Sprintf("mkdir -m %04o -o %s %s", mode, owner, path))
	return nil
}

func (f *fakeSystem) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	f.owners[path] = owner
	f.written[path] = string(data)
	f.modes[path] = mode
	return nil
}

func (f *fakeSystem) CheckBinary(string) error { return f.binaryErr }

func (f *fakeSystem) Remove(path string) error {
	f.removed = append(f.removed, path)
	return os.ErrNotExist
}

func linuxSpec() service.Spec {
	return service.Spec{GOOS: "linux", Binary: "/usr/local/bin/basalt", ConfigPath: "/etc/basalt/engine.json", User: "basalt"}
}

func darwinSpec() service.Spec {
	return service.Spec{
		GOOS: "darwin", Binary: "/usr/local/bin/basalt",
		ConfigPath: "/Library/Application Support/Basalt/engine.json", User: "_basalt",
	}
}

func TestSystemdUnit(t *testing.T) {
	t.Parallel()
	unit := service.SystemdUnit(linuxSpec())
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
		"ExecStart=/usr/local/bin/basalt engine --config /etc/basalt/engine.json\n",
		"RuntimeDirectory=basalt\n",
		"RuntimeDirectoryMode=0755\n",
		"StateDirectory=basalt\n",
		"StateDirectoryMode=0700\n",
		"UMask=0077\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n",
		"ProtectHome=yes\n",
		"WantedBy=multi-user.target\n",
	} {
		require.Contains(t, unit, want)
	}

	spaced := linuxSpec()
	spaced.ConfigPath = `/etc/my basalt/engine "x".json`
	require.Contains(t, service.SystemdUnit(spaced), `ExecStart=/usr/local/bin/basalt engine --config "/etc/my basalt/engine \"x\".json"`)
}

func TestLaunchdDaemon(t *testing.T) {
	t.Parallel()
	plist := service.LaunchdDaemon(darwinSpec())
	for _, want := range []string{
		"<string>dev.basaltdb.engine</string>",
		"<string>/usr/local/bin/basalt</string>\n\t\t<string>engine</string>\n\t\t<string>--config</string>\n\t\t<string>/Library/Application Support/Basalt/engine.json</string>",
		"<key>UserName</key>\n\t<string>_basalt</string>",
		"<key>GroupName</key>\n\t<string>_basalt</string>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>Umask</key>\n\t<integer>63</integer>",
	} {
		require.Contains(t, plist, want)
	}
	odd := darwinSpec()
	odd.ConfigPath = "/a&b/<c>.json"
	require.Contains(t, service.LaunchdDaemon(odd), "<string>/a&amp;b/&lt;c&gt;.json</string>")
}

func TestUnitsLimitTheEngineMemoryFromThePIIBudget(t *testing.T) {
	t.Parallel()
	unit := service.SystemdUnit(linuxSpec())
	require.Contains(t, unit, "MemoryHigh=1536M\n", "three times the default 512 MiB budget")
	require.Contains(t, unit, "MemoryMax=2048M\n")
	plist := service.LaunchdDaemon(darwinSpec())
	require.Contains(t, plist, "<key>SoftResourceLimits</key>\n\t<dict>\n\t\t<key>ResidentSetSize</key>\n\t\t<integer>1610612736</integer>")
	require.Contains(t, plist, "<key>HardResourceLimits</key>\n\t<dict>\n\t\t<key>ResidentSetSize</key>\n\t\t<integer>2147483648</integer>")

	small := linuxSpec()
	small.MemoryMB = 64
	unit = service.SystemdUnit(small)
	require.Contains(t, unit, "MemoryHigh=192M\n")
	require.Contains(t, unit, "MemoryMax=256M\n")
}

func TestLinuxInstallPlan(t *testing.T) {
	t.Parallel()
	sys := newFake()
	steps, err := service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Equal(t, []string{
		"useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin basalt",
		"mkdir -m 0750 -o basalt /etc/basalt",
		"systemctl daemon-reload",
		"systemctl enable --now basalt-engine.service",
	}, sys.ran)
	require.Equal(t, service.SystemdUnit(linuxSpec()), sys.written[service.SystemdUnitPath])
	require.Contains(t, out.String(), "write /etc/systemd/system/basalt-engine.service")

	sys = newFake()
	sys.users["basalt"] = true
	steps, err = service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	require.NotContains(t, steps[0].String(), "useradd", "an existing user is reused")
}

func TestDarwinInstallPlan(t *testing.T) {
	t.Parallel()
	sys := newFake()
	sys.outputs["dscl . -list /Users UniqueID"] = "_www 70\nroot 0\n_other 300\n"
	sys.outputs["dscl . -list /Groups PrimaryGroupID"] = "_grp 301\n"
	steps, err := service.InstallPlan(context.Background(), sys, darwinSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt UniqueID 302")
	require.Contains(t, sys.ran, "dscl . -create /Groups/_basalt PrimaryGroupID 302")
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt UserShell /usr/bin/false")
	require.Contains(t, sys.ran, "mkdir -m 0755 -o _basalt /Library/Application Support/Basalt/run")
	require.Contains(t, sys.ran, "mkdir -m 0750 -o _basalt /Library/Application Support/Basalt/state")
	require.Equal(t, []string{
		"launchctl bootstrap system /Library/LaunchDaemons/dev.basaltdb.engine.plist",
		"launchctl enable system/dev.basaltdb.engine",
	}, sys.ran[len(sys.ran)-2:])
	require.Equal(t, service.LaunchdDaemon(darwinSpec()), sys.written[service.LaunchdPlist])
	require.Contains(t, out.String(), `mkdir -m 0755 -o _basalt "/Library/Application Support/Basalt/run"`)
}

func TestDryRunRunsNothing(t *testing.T) {
	t.Parallel()
	sys := newFake()
	steps, err := service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, true, &out))
	require.Empty(t, sys.ran)
	require.Empty(t, sys.written)
	require.Contains(t, out.String(), "systemctl enable --now basalt-engine.service")
}

func TestApplyStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	sys := newFake()
	sys.users["basalt"] = true
	sys.failOn = "mkdir"
	steps, err := service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	err = service.Apply(context.Background(), sys, steps, false, &strings.Builder{})
	require.ErrorContains(t, err, "mkdir -m 0750")
	require.Empty(t, sys.written, "no unit written after a failed step")
}

func TestUninstallPlan(t *testing.T) {
	t.Parallel()
	sys := newFake()
	steps, err := service.UninstallPlan(linuxSpec())
	require.NoError(t, err)
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &strings.Builder{}))
	require.Equal(t, []string{"systemctl disable --now basalt-engine.service", "systemctl daemon-reload"}, sys.ran)
	require.Equal(t, []string{service.SystemdUnitPath}, sys.removed, "a missing unit file is not an error")

	sys = newFake()
	steps, err = service.UninstallPlan(darwinSpec())
	require.NoError(t, err)
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &strings.Builder{}))
	require.Equal(t, []string{"launchctl bootout system/dev.basaltdb.engine"}, sys.ran)
	require.Equal(t, []string{service.LaunchdPlist}, sys.removed)
}

// Without a running service manager (a container without systemd) the
// unit is still removed; the steps that failed are named as skipped.
func TestUninstallWithoutAServiceManager(t *testing.T) {
	t.Parallel()
	for name, spec := range map[string]service.Spec{"linux": linuxSpec(), "darwin": darwinSpec()} {
		sys := newFake()
		sys.failOn = map[string]string{"linux": "systemctl", "darwin": "launchctl"}[name]
		steps, err := service.UninstallPlan(spec)
		require.NoError(t, err)
		var out strings.Builder
		require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out), name)
		require.Empty(t, sys.ran, name)
		require.Len(t, sys.removed, 1, "the unit file is removed: %s", name)
		require.Contains(t, out.String(), "skipped "+sys.failOn, name)
		require.Contains(t, out.String(), "exit status 1", name)
	}

	// An install step that fails still stops the install.
	sys := newFake()
	sys.failOn = "systemctl"
	steps, err := service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	require.Error(t, service.Apply(context.Background(), sys, steps, false, &strings.Builder{}))
}

func TestSpecValidate(t *testing.T) {
	t.Parallel()
	bad := []service.Spec{
		{GOOS: "windows", Binary: "/b", ConfigPath: "/c", User: "u"},
		{GOOS: "linux", Binary: "basalt", ConfigPath: "/c", User: "u"},
		{GOOS: "linux", Binary: "/b", ConfigPath: "engine.json", User: "u"},
		{GOOS: "linux", Binary: "/b", ConfigPath: "/c", User: "root"},
		{GOOS: "linux", Binary: "/b", ConfigPath: "/c"},
	}
	for _, s := range bad {
		_, err := service.InstallPlan(context.Background(), newFake(), s)
		require.Error(t, err, "%+v", s)
	}
	_, err := service.UninstallPlan(service.Spec{GOOS: "windows"})
	require.Error(t, err)
}

func TestPickFreeID(t *testing.T) {
	t.Parallel()
	id, err := service.PickFreeID("")
	require.NoError(t, err)
	require.Equal(t, 300, id)
	id, err = service.PickFreeID("a 300\nb 301\n\nmalformed\nc x\n")
	require.NoError(t, err)
	require.Equal(t, 302, id)

	var all strings.Builder
	for i := 300; i <= 499; i++ {
		all.WriteString("u " + strconv.Itoa(i) + "\n")
	}
	_, err = service.PickFreeID(all.String())
	require.Error(t, err)
}

func TestDefaultUser(t *testing.T) {
	t.Parallel()
	require.Equal(t, "basalt", service.DefaultUser("linux"))
	require.Equal(t, "_basalt", service.DefaultUser("darwin"))
}

func TestInstallWritesOwnedFilesAndRestartsAnInstalledService(t *testing.T) {
	t.Parallel()
	spec := linuxSpec()
	spec.Files = []service.File{
		{Path: "/etc/basalt/engine.json", Content: []byte(`{"socketDir":"/run/basalt"}`)},
		{Path: "/etc/basalt/agents/bot.url", Content: []byte("postgres://secret")},
	}
	sys := newFake()
	sys.users["basalt"] = true
	sys.exists[service.SystemdUnitPath] = true
	steps, err := service.InstallPlan(context.Background(), sys, spec)
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Equal(t, []string{
		"mkdir -m 0750 -o basalt /etc/basalt",
		"mkdir -m 0700 -o basalt /etc/basalt/agents",
		"systemctl daemon-reload",
		"systemctl enable basalt-engine.service",
		"systemctl restart basalt-engine.service",
	}, sys.ran)
	require.Equal(t, "postgres://secret", sys.written["/etc/basalt/agents/bot.url"])
	require.Equal(t, os.FileMode(0o600), sys.modes["/etc/basalt/agents/bot.url"])
	require.Equal(t, os.FileMode(0o600), sys.modes["/etc/basalt/engine.json"])
	require.Equal(t, os.FileMode(0o644), sys.modes[service.SystemdUnitPath])
	require.NotContains(t, out.String(), "secret", "file contents are never printed")

	dspec := darwinSpec()
	dspec.Files = []service.File{{Path: "/Library/Application Support/Basalt/agents/bot.url", Content: []byte("x")}}
	sys = newFake()
	sys.users["_basalt"] = true
	sys.exists[service.LaunchdPlist] = true
	steps, err = service.InstallPlan(context.Background(), sys, dspec)
	require.NoError(t, err)
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &strings.Builder{}))
	require.Contains(t, sys.ran, "mkdir -m 0700 -o _basalt /Library/Application Support/Basalt/agents")
	require.Equal(t, "_basalt", sys.owners["/Library/Application Support/Basalt/agents/bot.url"])
	require.Equal(t, "launchctl kickstart -k system/dev.basaltdb.engine", sys.ran[len(sys.ran)-1])
	require.NotContains(t, sys.ran, "launchctl bootstrap system "+service.LaunchdPlist)
}
