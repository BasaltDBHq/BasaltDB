//go:build unix

package engine

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

const svcCopy = "/opt/basalt/plugins/acme-ner/default/4f1c2b0e9a8d7c6b5a49382716f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3"

func svcConfig() config.Config {
	return config.Config{
		Mode: config.ModeService, SocketDir: "/run/basalt",
		Agents: []config.Agent{
			{Name: "product_a", OSUser: "alice", Store: config.PostgresStore("/etc/basalt/agents/product_a.url")},
			{Name: "client_x", OSUser: "bob", Store: config.PostgresStore("/srv/client_x.url")},
		},
		Plugins: []config.Plugin{{Name: "acme-ner", Instance: "default", Enabled: true, Agents: []string{"product_a"}}},
	}
}

func svcVerified() pluginmodel.Verified {
	return pluginmodel.Verified{Dir: svcCopy, Manifest: pluginmodel.Manifest{
		Endpoint: pluginmodel.Endpoint{Local: &pluginmodel.LocalEndpoint{Transport: dial.TransportUnix, Command: "bin/acme-ner"}},
	}}
}

// fakeUnits is a machine with the units in units and the users in uids.
type fakeUnits struct {
	units   map[string]string
	uids    map[string]int
	inGroup error
	// pluginInGroup are the plugin users in the engine's group.
	pluginInGroup map[string]bool
	// gid is the engine group's id; overrides are drop-ins found.
	gid          int
	overrides    []string
	overridesErr error
}

func (f *fakeUnits) source() *UnitSource {
	return &UnitSource{
		ReadUnit: func(path string) ([]byte, error) {
			u, ok := f.units[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(u), nil
		},
		LookupUID: func(name string) (int, error) {
			uid, ok := f.uids[name]
			if !ok {
				return 0, errors.New("unknown user")
			}
			return uid, nil
		},
		EngineUser:  func() (string, error) { return "basalt", nil },
		CheckAgents: func(string, map[string]string) error { return f.inGroup },
		InGroup:     func(name, _ string) (bool, error) { return f.pluginInGroup[name], nil },
		LookupGID: func(string) (int, error) {
			if f.gid == 0 {
				return 0, errors.New("unknown group")
			}
			return f.gid, nil
		},
		Overrides: func(string) ([]string, error) { return f.overrides, f.overridesErr },
	}
}

// installed is a fake machine where the entry's unit is the one install
// writes, run by uid.
func installed(t *testing.T, cfg config.Config, v pluginmodel.Verified, uid int) *fakeUnits {
	t.Helper()
	h := osservice.HostFor(cfg, "linux", "/etc/basalt/engine.json", "basalt")
	e, ok := osservice.EntryFor(cfg.Plugins[0], v)
	require.True(t, ok)
	unit, err := osservice.PluginUnit(h, e)
	require.NoError(t, err)
	n, err := osservice.NamesFor("linux", "acme-ner", "default")
	require.NoError(t, err)
	return &fakeUnits{units: map[string]string{n.UnitPath: unit}, uids: map[string]int{n.User: uid}, gid: 980}
}

func serviceEngine(cfg config.Config, f *fakeUnits, euid int) *Plugins {
	ep := &Plugins{
		host: plugin.NewHost(), log: slog.New(slog.DiscardHandler), mode: pluginmodel.ModeService,
		o:     Options{Ports: testPorts, Dialer: dial.Dialer{}, goos: "linux", euid: euid, units: f.source()},
		first: map[pluginmodel.EntryKey]pluginmodel.Verified{}, notTrusted: map[pluginmodel.EntryKey]error{}, refused: map[pluginmodel.EntryKey]string{},
		configured: cfg.Plugins,
	}
	ep.initServiceUnits(cfg, "/etc/basalt/engine.json")
	return ep
}

func TestServiceEngineReachesOnlyAMatchingUnit(t *testing.T) {
	t.Parallel()
	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	k := p.Key()

	ep := serviceEngine(cfg, installed(t, cfg, v, 990), 995)
	require.Empty(t, ep.localRefusal(p, v))
	require.Equal(t, serviceTarget{socket: "/opt/basalt/run/basalt-plugin-acme-ner-default/p.sock", uid: 990, gid: 980}, ep.targets[k])

	// No unit: refused, fail closed.
	ep = serviceEngine(cfg, &fakeUnits{uids: map[string]int{"basalt-plugin-acme-ner-default": 990}}, 995)
	require.Equal(t, whyNoUnit, ep.localRefusal(p, v))
	require.NotContains(t, ep.targets, k)

	// A unit for another copy, or one that lost a setting, is refused.
	other := svcVerified()
	other.Dir = filepath.Join(filepath.Dir(svcCopy), "0000000000000000000000000000000000000000000000000000000000000000")
	ep = serviceEngine(cfg, installed(t, cfg, other, 990), 995)
	require.Equal(t, whyNoUnit, ep.localRefusal(p, v))
	f := installed(t, cfg, v, 990)
	for path, u := range f.units {
		f.units[path] = u[:len(u)-len("PrivateNetwork=yes\n\n[Install]\nWantedBy=multi-user.target\n")] + "\n[Install]\nWantedBy=multi-user.target\n"
	}
	ep = serviceEngine(cfg, f, 995)
	require.Equal(t, whyNoUnit, ep.localRefusal(p, v))

	// An agent whose credential file is outside the config directory was
	// added since the unit was written: it would not be hidden, so refused.
	wider := svcConfig()
	wider.Agents = append(wider.Agents, config.Agent{Name: "new_one", OSUser: "carol", Store: config.PostgresStore("/srv/new_one.url")})
	ep = serviceEngine(wider, installed(t, cfg, v, 990), 995)
	require.Equal(t, whyNoUnit, ep.localRefusal(p, v))

	// The unit's user must exist and be neither root nor the engine.
	for _, uid := range []int{0, 995} {
		ep = serviceEngine(cfg, installed(t, cfg, v, uid), 995)
		require.Equal(t, whyUnitUser, ep.localRefusal(p, v), "uid %d", uid)
	}
	f = installed(t, cfg, v, 990)
	f.uids = nil
	ep = serviceEngine(cfg, f, 995)
	require.Equal(t, whyUnitUser, ep.localRefusal(p, v))

	// Root never runs a local plugin, in any mode.
	ep = serviceEngine(cfg, installed(t, cfg, v, 990), 0)
	require.Equal(t, whyLocalAsRoot, ep.localRefusal(p, v))

	// A remote entry has no unit and is not refused here.
	remote := pluginmodel.Verified{Manifest: pluginmodel.Manifest{Endpoint: pluginmodel.Endpoint{Remote: &pluginmodel.RemoteEndpoint{Transport: dial.TransportConnect, URL: "https://x.example"}}}}
	ep = serviceEngine(cfg, &fakeUnits{}, 995)
	require.Empty(t, ep.localRefusal(p, remote))
	require.Empty(t, ep.targets)
}

// An agent's OS user in the engine's group could reach every plugin socket:
// the engine starts no local plugin, and the agent's status says why.
func TestServiceEngineRefusesWhenAnAgentIsInItsGroup(t *testing.T) {
	t.Parallel()
	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	f := installed(t, cfg, v, 990)
	f.inGroup = &plugin.AgentInGroupError{Agent: "product_a"}
	ep := serviceEngine(cfg, f, 995)
	e, err := p.Entry(v.Manifest)
	require.NoError(t, err)
	require.Empty(t, ep.localRefusal(p, v))
	ep.entries, ep.first[p.Key()] = []pluginmodel.Entry{e}, v
	ep.checkServiceAgents(cfg)
	require.Empty(t, ep.entries, "no local plugin starts")
	require.Empty(t, ep.targets)
	probs := ep.PluginProblems("product_a")
	require.Len(t, probs, 1)
	require.Equal(t, agent.ProblemPluginNotTrusted, probs[0].Code)
	require.Contains(t, probs[0].Message, "this agent's OS user is in the engine's group")
}

// In service mode the engine connects to the unit's socket; it starts no
// process, and talks only to the unit's OS user.
func TestServiceEngineConnectsToTheUnitSocket(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	cfg := svcConfig()
	v := svcVerified()
	k := cfg.Plugins[0].Key()
	e, err := cfg.Plugins[0].Entry(v.Manifest)
	require.NoError(t, err)
	me := uint32(os.Getuid())
	f := installed(t, cfg, v, int(me))
	f.gid = int(dirGID(t, dir))
	ep := serviceEngine(cfg, f, 995)
	ep.first[k] = v
	ep.targets[k] = serviceTarget{socket: sock, uid: me, gid: uint32(f.gid)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr, err := ep.dial(ctx, e)
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("the engine did not connect to the unit's socket")
	}
	_, isProcess := tr.(plugin.Exiter)
	require.False(t, isProcess, "no process is started in service mode")

	// A unit whose OS user is now another one is refused before any
	// connection.
	ep.first[k] = v
	ep.targets[k] = serviceTarget{socket: sock, uid: me + 1, gid: uint32(f.gid)}
	_, err = ep.dial(ctx, e)
	require.ErrorContains(t, err, whyUnitUserMoved)
}

// A drop-in, or a unit file systemd reads before the engine's, changes what
// the unit runs though its file is unchanged: refused, and when the lookup
// itself fails too.
func TestServiceEngineRefusesAnOverriddenUnit(t *testing.T) {
	t.Parallel()
	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	f := installed(t, cfg, v, 990)
	f.overrides = []string{"/etc/systemd/system/basalt-plugin-acme-ner-default.service.d/override.conf"}
	ep := serviceEngine(cfg, f, 995)
	require.Equal(t, whyUnitOverridden, ep.localRefusal(p, v))
	require.NotContains(t, ep.targets, p.Key())

	f = installed(t, cfg, v, 990)
	f.overridesErr = os.ErrPermission
	ep = serviceEngine(cfg, f, 995)
	require.Equal(t, whyUnitOverridden, ep.localRefusal(p, v), "fail closed")
}

// A plugin's OS user in the engine's group could reach every plugin socket
// and the engine's config: its entry is not started, and status names the
// user and the fix.
func TestServiceEngineRefusesAPluginUserInItsGroup(t *testing.T) {
	t.Parallel()
	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	f := installed(t, cfg, v, 990)
	f.pluginInGroup = map[string]bool{"basalt-plugin-acme-ner-default": true}
	ep := serviceEngine(cfg, f, 995)
	why := ep.localRefusal(p, v)
	require.Equal(t, "its OS user basalt-plugin-acme-ner-default is in the engine's group basalt, which reaches every plugin socket "+
		"and the engine's config; take it out of that group: sudo gpasswd -d basalt-plugin-acme-ner-default basalt", why)
	require.NotContains(t, ep.targets, p.Key())
	ep.refused[p.Key()] = why
	probs := ep.PluginProblems("product_a")
	require.Len(t, probs, 1)
	require.Equal(t, agent.ProblemPluginUnavailable, probs[0].Code)
	require.Equal(t, "plugin acme-ner/default was not started: "+why, probs[0].Message)
}

// The unit is checked again before every connection: one changed after the
// engine started (its file, a drop-in, its user's groups) is refused there,
// status says why, and the entry is reached again once it is put back.
func TestServiceEngineChecksTheUnitAtEachConnection(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	k := p.Key()
	e, err := p.Entry(v.Manifest)
	require.NoError(t, err)
	me := os.Getuid()
	f := installed(t, cfg, v, me)
	f.gid = int(dirGID(t, dir))
	ep := serviceEngine(cfg, f, 995)
	ep.sup = plugin.NewSupervisor(ep.host, ep.dial, plugin.RealClock())
	require.Empty(t, ep.localRefusal(p, v))
	ep.targets[k] = serviceTarget{socket: sock, uid: uint32(me), gid: uint32(f.gid)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reach := func() error {
		tr, err := ep.dial(ctx, e)
		if err == nil {
			_ = tr.Close()
		}
		return err
	}
	status := func() string {
		probs := ep.PluginProblems("product_a")
		if len(probs) == 0 {
			return ""
		}
		return probs[0].Message
	}
	ep.first[k] = v
	require.NoError(t, reach())

	good := map[string]string{}
	for path, u := range f.units {
		good[path] = u
		f.units[path] = u + "Environment=X=1\n"
	}
	ep.first[k] = v
	require.ErrorContains(t, reach(), whyNoUnit)
	require.Contains(t, status(), whyNoUnit)

	f.units = good
	f.overrides = []string{"/run/systemd/system/basalt-plugin-.service.d/x.conf"}
	ep.first[k] = v
	require.ErrorContains(t, reach(), whyUnitOverridden)
	require.Contains(t, status(), whyUnitOverridden)

	f.overrides = nil
	f.pluginInGroup = map[string]bool{"basalt-plugin-acme-ner-default": true}
	ep.first[k] = v
	require.ErrorContains(t, reach(), "is in the engine's group basalt")

	f.pluginInGroup = nil
	ep.first[k] = v
	require.NoError(t, reach(), "put back: reached again")
	require.NotContains(t, status(), "was not started")
}

// A service entry whose unit never made its socket (a plugin that only
// reads stdin) is not ready, and status says the plugin must listen on
// BASALT_PLUGIN_SOCKET.
func TestServiceEngineNamesTheSocketVariable(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	k := p.Key()
	e, err := p.Entry(v.Manifest)
	require.NoError(t, err)
	me := os.Getuid()
	f := installed(t, cfg, v, me)
	f.gid = int(dirGID(t, dir))
	ep := serviceEngine(cfg, f, 995)
	ep.sup = plugin.NewSupervisor(ep.host, ep.dial, plugin.RealClock())
	ep.first[k] = v
	ep.targets[k] = serviceTarget{socket: filepath.Join(dir, "p.sock"), uid: uint32(me), gid: uint32(f.gid)}
	_, err = ep.dial(context.Background(), e)
	require.ErrorIs(t, err, dial.ErrNoSocket)
	probs := ep.PluginProblems("product_a")
	require.Len(t, probs, 1)
	require.Equal(t, agent.ProblemPluginUnavailable, probs[0].Code)
	require.Contains(t, probs[0].Message, "must listen on the socket BASALT_PLUGIN_SOCKET names")

	// A socket directory opened to others: status names that instead.
	require.NoError(t, os.Chmod(dir, 0o755))
	ep.first[k] = v
	_, err = ep.dial(context.Background(), e)
	require.ErrorIs(t, err, dial.ErrSocketDir)
	probs = ep.PluginProblems("product_a")
	require.Len(t, probs, 1)
	require.Contains(t, probs[0].Message, whySocketDir)
}

// dirGID is dir's group: on macOS a new directory takes its parent's.
func dirGID(t *testing.T, dir string) uint32 {
	t.Helper()
	fi, err := os.Stat(dir)
	require.NoError(t, err)
	return fi.Sys().(*syscall.Stat_t).Gid
}
