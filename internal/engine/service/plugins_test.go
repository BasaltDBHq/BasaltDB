package service_test

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

var updateGolden = flag.Bool("update", false, "rewrite the plugin unit golden files under testdata/")

const copySHA = "4f1c2b0e9a8d7c6b5a49382716f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3"

func linuxHost() service.PluginHost {
	return service.PluginHost{
		GOOS: "linux", EngineUser: "basalt", ConfigDir: "/etc/basalt", StateDir: "/var/lib/basalt", SocketDir: "/run/basalt",
		CredentialFiles: []string{"/etc/basalt/agents/product_a.url", "/srv/creds/client_x.url", "/srv/acme.token"},
	}
}

func darwinHost() service.PluginHost {
	return service.PluginHost{
		GOOS: "darwin", EngineUser: "_basalt", ConfigDir: "/Library/Application Support/Basalt",
		StateDir: "/Library/Application Support/Basalt/state", SocketDir: "/Library/Application Support/Basalt/run",
		CredentialFiles: []string{"/Library/Application Support/Basalt/agents/product_a.url"},
	}
}

func entry(goos, instance string, egress ...string) service.PluginEntry {
	root, err := plugin.Root(plugin.ModeService, goos, "")
	if err != nil {
		panic(err)
	}
	return service.PluginEntry{
		Name: "acme-ner", Instance: instance, Dir: filepath.Join(root, "acme-ner", instance, copySHA),
		Command: "bin/acme-ner", Args: []string{"--serve", "--lang=en id"}, Egress: egress, Enabled: true,
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run go test ./internal/engine/service/ -run TestPluginUnitsGolden -update")
	require.Equal(t, string(want), got)
}

func TestPluginUnitsGolden(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file   string
		goos   string
		egress []string
	}{
		{"plugin-linux-no-egress.service", "linux", nil},
		{"plugin-linux-egress.service", "linux", []string{"hooks.slack.com:443"}},
		{"plugin-darwin-no-egress.plist", "darwin", nil},
		{"plugin-darwin-egress.plist", "darwin", []string{"hooks.slack.com:443"}},
	} {
		h := linuxHost()
		render := service.SystemdPluginUnit
		if tc.goos == "darwin" {
			h, render = darwinHost(), service.LaunchdPluginDaemon
		}
		got, err := render(h, entry(tc.goos, "default", tc.egress...))
		require.NoError(t, err)
		golden(t, tc.file, got)
	}
}

func TestPluginNetwork(t *testing.T) {
	t.Parallel()
	require.Equal(t, "ENFORCED", service.PluginNetwork("linux", nil))
	require.Equal(t, "DECLARED", service.PluginNetwork("linux", []string{"hooks.slack.com:443"}))
	require.Equal(t, "NOT_ENFORCED", service.PluginNetwork("darwin", nil))

	none, err := service.SystemdPluginUnit(linuxHost(), entry("linux", "default"))
	require.NoError(t, err)
	require.Contains(t, none, "\nPrivateNetwork=yes\n", "an empty egress runs without network")
	some, err := service.SystemdPluginUnit(linuxHost(), entry("linux", "default", "hooks.slack.com:443"))
	require.NoError(t, err)
	require.NotContains(t, some, "PrivateNetwork")
}

func TestInaccessiblePathsHideTheEngine(t *testing.T) {
	t.Parallel()
	unit, err := service.SystemdPluginUnit(linuxHost(), entry("linux", "default"))
	require.NoError(t, err)
	for _, want := range []string{
		`InaccessiblePaths=/etc/basalt`,
		`InaccessiblePaths=/var/lib/basalt`,
		`InaccessiblePaths=/run/basalt`,
		`InaccessiblePaths=-/srv/creds/client_x.url`,
		`InaccessiblePaths=-/srv/acme.token`,
	} {
		require.Contains(t, unit, want+"\n")
	}
	// A credential file in the config directory is hidden with it, so an
	// agent added there leaves the unit as it is.
	require.NotContains(t, unit, "product_a.url")
	// Each path once, whatever the host lists twice.
	h := linuxHost()
	h.CredentialFiles = append(h.CredentialFiles, "/etc/basalt", "/srv/creds/client_x.url")
	unit, err = service.SystemdPluginUnit(h, entry("linux", "default"))
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(unit, "=/etc/basalt\n"))
	require.Equal(t, 1, strings.Count(unit, "/srv/creds/client_x.url"))

	// A path with a space or a '%' is quoted, its specifier escaped.
	h = linuxHost()
	h.ConfigDir = "/etc/my basalt"
	h.CredentialFiles = []string{`/srv/my creds/a%h"b.url`}
	unit, err = service.SystemdPluginUnit(h, entry("linux", "default"))
	require.NoError(t, err)
	require.Contains(t, unit, "InaccessiblePaths=\"/etc/my basalt\"\n")
	require.Contains(t, unit, "InaccessiblePaths=\"-/srv/my creds/a%%h\\\"b.url\"\n")
}

func TestRemoteEntryHasNoUnit(t *testing.T) {
	t.Parallel()
	// Only local entries become PluginEntry values: a remote one has no
	// copy to run. The install plan for a spec without local entries makes
	// the base and nothing for any plugin.
	sys := newFake()
	sys.users["basalt"] = true
	steps, err := service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	for _, st := range steps {
		require.NotContains(t, st.String(), "basalt-plugin-")
	}
	plan, err := service.PluginInstallPlan(context.Background(), sys, linuxHost(), nil)
	require.NoError(t, err)
	require.Empty(t, plan)
	// A PluginEntry with no copy or command is refused, never rendered.
	_, err = service.SystemdPluginUnit(linuxHost(), service.PluginEntry{Name: "acme-ner", Instance: "default"})
	require.Error(t, err)
}

func TestInstancesAreSeparate(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		a, err := service.NamesFor(goos, "acme-ner", "default")
		require.NoError(t, err)
		b, err := service.NamesFor(goos, "acme-ner", "client_x")
		require.NoError(t, err)
		require.NotEqual(t, a.Unit, b.Unit)
		require.NotEqual(t, a.UnitPath, b.UnitPath)
		require.NotEqual(t, a.User, b.User)
		require.NotEqual(t, a.SocketDir, b.SocketDir)
		require.NotEqual(t, a.Socket, b.Socket)
		require.NotEqual(t, filepath.Dir(a.Socket), filepath.Dir(b.Socket), "no shared directory")
	}

	// One plan for both entries: two users with different ids, two
	// directories, two units.
	sys := newFake()
	sys.outputs["dscl . -list /Users UniqueID"] = "root 0\n_basalt 300\n"
	sys.outputs["dscl . -list /Groups PrimaryGroupID"] = "_basalt 300\n"
	h := darwinHost()
	steps, err := service.PluginInstallPlan(context.Background(), sys, h,
		[]service.PluginEntry{entry("darwin", "default"), entry("darwin", "client_x")})
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt-plugin-acme-ner-default UniqueID 301")
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt-plugin-acme-ner-client_x UniqueID 302")
	require.Contains(t, sys.ran, "mkdir -m 2750 -o _basalt-plugin-acme-ner-default -g _basalt /Library/Basalt/run/_basalt-plugin-acme-ner-default")
	require.Contains(t, sys.ran, "mkdir -m 2750 -o _basalt-plugin-acme-ner-client_x -g _basalt /Library/Basalt/run/_basalt-plugin-acme-ner-client_x")
	require.Contains(t, sys.written, "/Library/LaunchDaemons/dev.basaltdb.plugin-acme-ner-default.plist")
	require.Contains(t, sys.written, "/Library/LaunchDaemons/dev.basaltdb.plugin-acme-ner-client_x.plist")

	lsys := newFake()
	steps, err = service.PluginInstallPlan(context.Background(), lsys, linuxHost(),
		[]service.PluginEntry{entry("linux", "default"), entry("linux", "client_x")})
	require.NoError(t, err)
	require.NoError(t, service.Apply(context.Background(), lsys, steps, false, &out))
	require.Contains(t, lsys.ran, "useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment BasaltDB plugin acme-ner default basalt-plugin-acme-ner-default")
	require.Contains(t, lsys.ran, "useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment BasaltDB plugin acme-ner client_x basalt-plugin-acme-ner-client_x")
	ua := lsys.written["/etc/systemd/system/basalt-plugin-acme-ner-default.service"]
	ub := lsys.written["/etc/systemd/system/basalt-plugin-acme-ner-client_x.service"]
	require.Contains(t, ua, "User=basalt-plugin-acme-ner-default\n")
	require.Contains(t, ub, "User=basalt-plugin-acme-ner-client_x\n")
	require.Contains(t, ua, "WorkingDirectory=/usr/local/lib/basalt/plugins/acme-ner/default/")
	require.Contains(t, ub, "WorkingDirectory=/usr/local/lib/basalt/plugins/acme-ner/client_x/")
	require.Contains(t, ua, "ReadWritePaths=/usr/local/lib/basalt/run/basalt-plugin-acme-ner-default\n")
	require.Contains(t, ub, "ReadWritePaths=/usr/local/lib/basalt/run/basalt-plugin-acme-ner-client_x\n")
	require.Contains(t, ua, "Environment=BASALT_PLUGIN_SOCKET=/usr/local/lib/basalt/run/basalt-plugin-acme-ner-default/p.sock\n")
}

func TestPluginUserShortening(t *testing.T) {
	t.Parallel()
	require.Equal(t, "basalt-plugin-acme-ner-default", service.PluginUser("linux", "acme-ner", "default"))
	require.Equal(t, "_basalt-plugin-acme-ner-default", service.PluginUser("darwin", "acme-ner", "default"))

	long := strings.Repeat("n", 40)
	inst := strings.Repeat("i", 32)
	seen := map[string]bool{}
	for _, goos := range []string{"linux", "darwin"} {
		for _, k := range [][2]string{{long, inst}, {long, "default"}, {"acme-ner", "client_x_with_a_long_name"}, {long[:39] + "m", inst}} {
			u := service.PluginUser(goos, k[0], k[1])
			require.LessOrEqual(t, len(u), 32, u)
			require.Equal(t, u, service.PluginUser(goos, k[0], k[1]), "deterministic")
			require.False(t, seen[u], "two entries share user %s", u)
			seen[u] = true
			// A shortened name ends in '-', '0' and hex digits, which no
			// instance does (an instance starts with a letter).
			last := u[strings.LastIndex(u, "-")+1:]
			require.Regexp(t, `^0[0-9a-f]{8}$`, last)
			n, err := service.NamesFor(goos, k[0], k[1])
			require.NoError(t, err)
			require.Equal(t, u, n.User)
			require.Contains(t, n.Unit, k[0]+"-"+k[1], "the unit keeps the real name")
			require.LessOrEqual(t, len(n.Socket), 103, "fits a Unix socket path on both OSes")
		}
	}
}

func TestPluginNamesRefuseBadKeys(t *testing.T) {
	t.Parallel()
	for _, k := range [][2]string{{"Acme", "default"}, {"acme", "a-b"}, {"acme;rm", "default"}, {"acme", "x\ny"}, {"../x", "default"}, {"acme", ""}} {
		_, err := service.NamesFor("linux", k[0], k[1])
		require.Error(t, err, k)
	}
}

// unquoteSystemd reads back the words of an ExecStart line the way systemd
// does for what systemdWord writes: double-quoted words, '\' escapes, and
// doubled '%' and '$'.
func unquoteSystemd(t *testing.T, line string) []string {
	t.Helper()
	var words []string
	for line != "" {
		line = strings.TrimLeft(line, " ")
		require.True(t, strings.HasPrefix(line, `"`), "every word is quoted: %q", line)
		var w strings.Builder
		i := 1
		for ; line[i] != '"'; i++ {
			switch c := line[i]; c {
			case '\\':
				i++
				w.WriteByte(line[i])
			case '%', '$':
				require.Equal(t, c, line[i+1], "a lone %c would expand", c)
				i++
				w.WriteByte(c)
			default:
				w.WriteByte(c)
			}
		}
		words = append(words, w.String())
		line = line[i+1:]
	}
	return words
}

func TestPluginArgsCannotInjectIntoUnits(t *testing.T) {
	t.Parallel()
	odd := []string{`a "quoted" \ word`, "%h $HOME ${X} %%", "it's; fine", "--x=<y>&z", "ünïcode"}
	e := entry("linux", "default")
	e.Args = odd
	unit, err := service.SystemdPluginUnit(linuxHost(), e)
	require.NoError(t, err)
	var execLine string
	for _, l := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
			execLine = v
		}
	}
	require.Equal(t, append([]string{filepath.Join(e.Dir, "bin", "acme-ner")}, odd...), unquoteSystemd(t, execLine))

	d := entry("darwin", "default")
	d.Args = odd
	plist, err := service.LaunchdPluginDaemon(darwinHost(), d)
	require.NoError(t, err)
	require.Contains(t, plist, "<string>--x=&lt;y&gt;&amp;z</string>")
	require.Contains(t, plist, "<string>a &#34;quoted&#34; \\ word</string>")

	for _, bad := range []string{"a\nExecStartPre=/bin/sh", "a\rb", "nul\x00", "\x1b[31m", ";", "line sep", string([]byte{0xff})} {
		e.Args = []string{bad}
		_, err := service.SystemdPluginUnit(linuxHost(), e)
		require.Error(t, err, "%q", bad)
		d.Args = []string{bad}
		_, err = service.LaunchdPluginDaemon(darwinHost(), d)
		require.Error(t, err, "%q", bad)
	}
	for _, cmd := range []string{"../bin/x", "/bin/sh", "bin/../../x", "bin/a b", "bin/x\n"} {
		e = entry("linux", "default")
		e.Command = cmd
		_, err := service.SystemdPluginUnit(linuxHost(), e)
		require.Error(t, err, cmd)
	}
	e = entry("linux", "default")
	e.Dir = "/usr/local/lib/basalt/plugins/x y"
	_, err = service.SystemdPluginUnit(linuxHost(), e)
	require.Error(t, err)
	h := linuxHost()
	h.CredentialFiles = []string{"/etc/a\nExecStartPre=/bin/sh"}
	_, err = service.SystemdPluginUnit(h, entry("linux", "default"))
	require.Error(t, err)
	h = linuxHost()
	h.EngineUser = "root"
	_, err = service.SystemdPluginUnit(h, entry("linux", "default"))
	require.Error(t, err, "the socket's group is never root's")
}

func TestPluginInstallPlanCreatesTheUser(t *testing.T) {
	t.Parallel()
	sys := newFake()
	disabled := entry("linux", "default")
	disabled.Enabled = false
	steps, err := service.PluginInstallPlan(context.Background(), sys, linuxHost(), []service.PluginEntry{disabled})
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Equal(t, []string{
		"mkdir -m 0755 -o root /usr/local/lib/basalt",
		"mkdir -m 0755 -o root /usr/local/lib/basalt/run",
		"useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment BasaltDB plugin acme-ner default basalt-plugin-acme-ner-default",
		"mkdir -m 2750 -o basalt-plugin-acme-ner-default -g basalt /usr/local/lib/basalt/run/basalt-plugin-acme-ner-default",
		"systemctl daemon-reload",
		"systemctl disable --now basalt-plugin-acme-ner-default.service",
	}, sys.ran, "a disabled entry's unit is written and stays stopped")
	require.Contains(t, sys.written, "/etc/systemd/system/basalt-plugin-acme-ner-default.service")
	require.Contains(t, out.String(), "write /etc/systemd/system/basalt-plugin-acme-ner-default.service")

	sys = newFake()
	sys.users["basalt-plugin-acme-ner-default"] = true
	steps, err = service.PluginInstallPlan(context.Background(), sys, linuxHost(), []service.PluginEntry{entry("linux", "default")})
	require.NoError(t, err)
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.NotContains(t, strings.Join(sys.ran, "\n"), "useradd", "an existing user is reused")
	require.Equal(t, []string{"systemctl enable basalt-plugin-acme-ner-default.service", "systemctl restart basalt-plugin-acme-ner-default.service"},
		sys.ran[len(sys.ran)-2:])

	// The service install makes every local entry's user and unit before
	// it starts the engine.
	sys = newFake()
	sys.users["basalt"] = true
	spec := linuxSpec()
	spec.Plugins = []service.PluginEntry{entry("linux", "default")}
	steps, err = service.InstallPlan(context.Background(), sys, spec)
	require.NoError(t, err)
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	ran := strings.Join(sys.ran, "\n")
	require.Contains(t, ran, "basalt-plugin-acme-ner-default\n")
	require.Less(t, strings.Index(ran, "systemctl restart basalt-plugin-acme-ner-default.service"), strings.Index(ran, "systemctl enable --now basalt-engine.service"))
	unit := sys.written["/etc/systemd/system/basalt-plugin-acme-ner-default.service"]
	require.Contains(t, unit, "InaccessiblePaths=/etc/basalt\n")
	require.Contains(t, unit, "InaccessiblePaths=/var/lib/basalt\n")
}

func TestDarwinDisabledPluginStaysUnloaded(t *testing.T) {
	t.Parallel()
	sys := newFake()
	sys.outputs["dscl . -list /Users UniqueID"] = "root 0\n"
	disabled := entry("darwin", "default")
	disabled.Enabled = false
	steps, err := service.PluginInstallPlan(context.Background(), sys, darwinHost(), []service.PluginEntry{disabled})
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Equal(t, []string{
		"launchctl bootout system/dev.basaltdb.plugin-acme-ner-default",
		"launchctl disable system/dev.basaltdb.plugin-acme-ner-default",
	}, sys.ran[len(sys.ran)-2:], "a plist in LaunchDaemons would load at boot unless disabled")
	require.Contains(t, sys.ran, "dscl . -create /Users/_basalt-plugin-acme-ner-default RealName BasaltDB plugin acme-ner default")
}

func TestPluginRemoveDeletesWhatInstallMade(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		goos string
		want []string
	}{
		{"linux", []string{
			"systemctl disable --now basalt-plugin-acme-ner-default.service",
			"systemctl daemon-reload",
			"rm -rf /usr/local/lib/basalt/run/basalt-plugin-acme-ner-default",
			"userdel basalt-plugin-acme-ner-default",
		}},
		{"darwin", []string{
			"launchctl bootout system/dev.basaltdb.plugin-acme-ner-default",
			"rm -rf /Library/Basalt/run/_basalt-plugin-acme-ner-default",
			"dscl . -delete /Users/_basalt-plugin-acme-ner-default",
			"dscl . -delete /Groups/_basalt-plugin-acme-ner-default",
		}},
	} {
		sys := newFake()
		n, err := service.NamesFor(tc.goos, "acme-ner", "default")
		require.NoError(t, err)
		sys.users[n.User] = true
		sys.exists[n.UnitPath] = true
		steps, err := service.PluginRemoveSteps(sys, tc.goos, "acme-ner", "default")
		require.NoError(t, err)
		var out strings.Builder
		require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
		require.Equal(t, tc.want, sys.ran, tc.goos)
		require.Equal(t, []string{n.UnitPath}, sys.removed)

		// Another instance's user, unit and directory are not touched.
		other, err := service.NamesFor(tc.goos, "acme-ner", "client_x")
		require.NoError(t, err)
		for _, r := range append(sys.ran, sys.removed...) {
			require.NotContains(t, r, other.User)
			require.NotContains(t, r, other.Unit)
		}

		// Run again with nothing left: nothing fails, no user is deleted.
		sys = newFake()
		steps, err = service.PluginRemoveSteps(sys, tc.goos, "acme-ner", "default")
		require.NoError(t, err)
		require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
		require.NotContains(t, strings.Join(sys.ran, "\n"), "userdel")
		require.NotContains(t, strings.Join(sys.ran, "\n"), "-delete")
	}
}

func TestUninstallRemovesPluginsAndAnEmptyBase(t *testing.T) {
	t.Parallel()
	sys := newFake()
	sys.users["basalt-plugin-acme-ner-default"] = true
	sys.exists["/usr/local/lib/basalt"] = true
	spec := linuxSpec()
	spec.Plugins = []service.PluginEntry{entry("linux", "default")}
	steps, err := service.UninstallPlan(sys, spec)
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Contains(t, sys.ran, "userdel basalt-plugin-acme-ner-default")
	require.Contains(t, sys.ran, "rm -rf /usr/local/lib/basalt/run/basalt-plugin-acme-ner-default")
	require.Equal(t, []string{
		service.SystemdUnitPath,
		"/etc/systemd/system/basalt-plugin-acme-ner-default.service",
		"/usr/local/lib/basalt/run",
		"/usr/local/lib/basalt",
	}, sys.removed)

	// A base that still holds installed copies or keys stays, and the
	// uninstall still succeeds.
	sys = newFake()
	sys.exists["/usr/local/lib/basalt"] = true
	sys.removeErr = errors.New("directory not empty")
	steps, err = service.UninstallPlan(sys, linuxSpec())
	require.NoError(t, err)
	out.Reset()
	require.NoError(t, service.Settle(service.Apply(context.Background(), sys, steps, false, &out), sys, "linux"))
	require.Contains(t, out.String(), "skipped rm -f /usr/local/lib/basalt: left in place")
}

func TestPluginBaseOnAGroupWritableUsrLocal(t *testing.T) {
	t.Parallel()
	// Debian-family systems ship /usr/local group-writable: the base cannot
	// be made safely. The engine still installs, and the step names the fix.
	sys := newFake()
	sys.failOn = "mkdir /usr/local/lib/basalt"
	sys.users["basalt"] = true
	steps, err := service.InstallPlan(context.Background(), sys, linuxSpec())
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, service.Apply(context.Background(), sys, steps, false, &out))
	require.Contains(t, out.String(), "skipped mkdir -m 0755 -o root /usr/local/lib/basalt: plugins cannot be installed until every directory above /usr/local/lib/basalt is writable by root only; on Debian-family systems /usr/local is group-writable: sudo chmod g-w /usr/local")
	require.Contains(t, sys.ran, "systemctl enable --now basalt-engine.service")
}
