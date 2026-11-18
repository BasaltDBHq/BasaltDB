//go:build unix

package engine

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
)

const svcCopy = "/usr/local/lib/basalt/plugins/acme-ner/default/4f1c2b0e9a8d7c6b5a49382716f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3"

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

func svcVerified() plugin.Verified {
	return plugin.Verified{Dir: svcCopy, Manifest: plugin.Manifest{
		Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: dial.TransportUnix, Command: "bin/acme-ner"}},
	}}
}

// fakeUnits is a machine with the units in units and the users in uids.
type fakeUnits struct {
	units   map[string]string
	uids    map[string]int
	inGroup error
}

func (f *fakeUnits) source() *unitSource {
	return &unitSource{
		readUnit: func(path string) ([]byte, error) {
			u, ok := f.units[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(u), nil
		},
		lookupUID: func(name string) (int, error) {
			uid, ok := f.uids[name]
			if !ok {
				return 0, errors.New("unknown user")
			}
			return uid, nil
		},
		engineUser:  func() (string, error) { return "basalt", nil },
		checkAgents: func(string, map[string]string) error { return f.inGroup },
	}
}

// installed is a fake machine where the entry's unit is the one install
// writes, run by uid.
func installed(t *testing.T, cfg config.Config, v plugin.Verified, uid int) *fakeUnits {
	t.Helper()
	h := service.HostFor(cfg, "linux", "/etc/basalt/engine.json", "basalt")
	e, ok := service.EntryFor(cfg.Plugins[0], v)
	require.True(t, ok)
	unit, err := service.PluginUnit(h, e)
	require.NoError(t, err)
	n, err := service.NamesFor("linux", "acme-ner", "default")
	require.NoError(t, err)
	return &fakeUnits{units: map[string]string{n.UnitPath: unit}, uids: map[string]int{n.User: uid}}
}

func serviceEngine(cfg config.Config, f *fakeUnits, euid int) *enginePlugins {
	ep := &enginePlugins{
		host: plugin.NewHost(), log: slog.New(slog.DiscardHandler), mode: plugin.ModeService,
		o:     pluginOptions{goos: "linux", euid: euid, units: f.source()},
		first: map[plugin.EntryKey]plugin.Verified{}, notTrusted: map[plugin.EntryKey]error{}, refused: map[plugin.EntryKey]string{},
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
	require.Equal(t, serviceTarget{socket: "/usr/local/lib/basalt/run/basalt-plugin-acme-ner-default/p.sock", uid: 990}, ep.targets[k])

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
	remote := plugin.Verified{Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: dial.TransportConnect, URL: "https://x.example"}}}}
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
	ep.entries, ep.first[p.Key()] = []plugin.Entry{e}, v
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
	ep := serviceEngine(cfg, &fakeUnits{}, 995)
	ep.first[k] = v
	ep.targets[k] = serviceTarget{socket: sock, uid: me}
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

	// Another OS user listening there is refused.
	ep.first[k] = v
	ep.targets[k] = serviceTarget{socket: sock, uid: me + 1}
	_, err = ep.dial(ctx, e)
	require.ErrorIs(t, err, dial.ErrWrongPeer)
}
