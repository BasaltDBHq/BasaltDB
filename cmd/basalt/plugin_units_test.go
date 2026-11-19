package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os/user"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

func TestAgentOSUserInTheEngineGroupIsRefused(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{"alice": {"20", "1001"}, "bob": {"20"}}
	lookupGroups := func(name string) ([]string, error) {
		g, ok := groups[name]
		if !ok {
			return nil, user.UnknownUserError(name)
		}
		return g, nil
	}
	engineGroup := func(name string) (*user.Group, error) {
		if name == "basalt" {
			return &user.Group{Gid: "1001", Name: "basalt"}, nil
		}
		return nil, user.UnknownGroupError(name)
	}

	err := checkAgentOSUserWith("alice", "basalt", engineGroup, lookupGroups)
	require.ErrorIs(t, err, errUsage)
	require.ErrorContains(t, err, "--os-user alice is in the engine's group basalt")
	require.NoError(t, checkAgentOSUserWith("bob", "basalt", engineGroup, lookupGroups))
	require.ErrorContains(t, checkAgentOSUserWith("basalt", "basalt", engineGroup, lookupGroups), "the engine's own OS user")
	for _, reserved := range []string{"basalt-plugin-acme-ner-default", "_basalt-plugin-x"} {
		require.ErrorContains(t, checkAgentOSUserWith(reserved, "basalt", engineGroup, lookupGroups), "keeps those names for plugins")
	}

	// A first install: the engine's group does not exist yet, so no one is in it.
	require.NoError(t, checkAgentOSUserWith("alice", "_basalt", engineGroup, lookupGroups))

	// Anything that cannot be looked up refuses.
	broken := func(string) (*user.Group, error) { return nil, errors.New("nss down") }
	require.ErrorContains(t, checkAgentOSUserWith("alice", "basalt", broken, lookupGroups), "cannot be looked up")
	require.ErrorContains(t, checkAgentOSUserWith("carol", "basalt", engineGroup, lookupGroups), "cannot be read")
}

func TestInitRefusesAnOSUserInTheEngineGroup(t *testing.T) {
	t.Parallel()
	// The person's own primary group stands in for the engine's group: the
	// person is in it, so init refuses before anything else happens.
	cur, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(cur.Gid)
	require.NoError(t, err)
	if g.Name == cur.Username {
		t.Skip("the person's primary group has the person's name; --engine-user would be the person")
	}
	h := newFakeHost(t)
	r := cliOn(t, h, map[string]string{envAdminURL: "postgres://unused@127.0.0.1:1/x"}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--os-user", cur.Username, "--engine-user", g.Name, "--yes")
	require.NotEqual(t, exitOK, r.code)
	require.Contains(t, r.stderr, "is in the engine's group "+g.Name)
	require.Empty(t, h.sudo, "nothing is installed")
}

func TestPluginUnitEntries(t *testing.T) {
	t.Parallel()
	local := plugin.Verified{
		Dir: "/opt/basalt/plugins/acme-ner/default/abc",
		Manifest: plugin.Manifest{
			Endpoint:  plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: "jsonrpc-unix", Command: "bin/acme", Args: []string{"--serve"}}},
			Network:   plugin.Network{Egress: []string{"hooks.slack.com:443"}},
			Resources: &plugin.Resources{MemoryMB: 256},
		},
	}
	e, ok := unitEntry(config.Plugin{Name: "acme-ner", Enabled: true}, local)
	require.True(t, ok)
	require.Equal(t, service.PluginEntry{
		Name: "acme-ner", Instance: "default", Dir: local.Dir, Command: "bin/acme", Args: []string{"--serve"},
		Egress: []string{"hooks.slack.com:443"}, MemoryMB: 256, Enabled: true,
	}, e)

	remote := plugin.Verified{Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: "connectrpc", URL: "https://x.example"}}}}
	_, ok = unitEntry(config.Plugin{Name: "acme-ner"}, remote)
	require.False(t, ok, "a remote entry has no unit")

	cfg := config.Config{
		SocketDir: "/run/basalt",
		Agents: []config.Agent{
			{Name: "product_a", Store: config.PostgresStore("/etc/basalt/agents/product_a.url")},
			{Name: "client_x", Store: config.PostgresStore("/srv/x.url")},
		},
		Plugins: []config.Plugin{
			{Name: "acme-ner", Auth: &config.PluginAuth{CredentialFile: "/etc/basalt/acme.token"}},
			{Name: "acme-ner", Instance: "client_x"},
		},
	}
	h := servicePluginHost(cfg, "linux", "/etc/basalt/engine.json", "basalt")
	require.Equal(t, service.PluginHost{
		GOOS: "linux", EngineUser: "basalt", ConfigDir: "/etc/basalt", StateDir: config.DefaultStateDir("linux"), SocketDir: "/run/basalt",
		CredentialFiles: []string{"/etc/basalt/agents/product_a.url", "/srv/x.url"},
	}, h)

	names := serviceUnitNames(cfg)
	require.Equal(t, []service.PluginEntry{{Name: "acme-ner", Instance: "default"}, {Name: "acme-ner", Instance: "client_x"}}, names)

	// Copies that are not installed are left out of install, with a line.
	var warn strings.Builder
	require.Empty(t, serviceUnitEntries(cfg, "linux", "/etc/basalt/engine.json", &warn))
	require.Contains(t, warn.String(), "plugin acme-ner/default: its service unit is left as it is")
}

func TestGroupWritableDirectoryIsRefusedLikeAnyPath(t *testing.T) {
	t.Parallel()
	// No special case for a group-writable directory above the base: it is
	// refused as any other path the rule refuses (UNSAFE_PATH), and no chmod
	// is offered.
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
	c.goos = "linux"
	e := &pluginEnv{c: c, configPath: config.DefaultPath("linux"), mode: plugin.ModeService}
	err := e.verifyRefusal(&plugin.VerifyError{
		Reason: plugin.RefusedNotTrusted, File: "/opt", Why: plugin.WhyGroupWritable,
		Path: &plugin.PathFault{Kind: plugin.PathWritable, Mode: fs.ModeDir | fs.ModeSetgid | 0o775, GID: 4242424, Owners: []uint32{0}},
	}, "basalt plugin add /src --agents a")
	var r *pluginRefusedError
	require.ErrorAs(t, err, &r)
	require.Equal(t, reasonUnsafePath, r.reason)
	require.Contains(t, r.message, "/opt")
	require.Contains(t, r.person, "/opt can be written by members of group gid 4242424 (owner root, group gid 4242424, mode 2775)")
	require.NotContains(t, r.person, "chmod")
	for _, s := range r.steps {
		require.NotContains(t, s.Command, "chmod")
	}
}

// agentOSUser is an OS user that exists and is neither the test's user nor
// in its group, for an agent when the test's user stands in for the
// engine's: root.
func agentOSUser(t *testing.T) string {
	t.Helper()
	require.NoError(t, checkAgentOSUser("root", me(t)), "root stands in for an agent's OS user")
	return "root"
}
