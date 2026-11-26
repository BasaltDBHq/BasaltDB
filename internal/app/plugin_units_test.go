package app

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

func TestPluginUnitEntries(t *testing.T) {
	t.Parallel()
	local := pluginmodel.Verified{
		Dir: "/opt/basalt/plugins/acme-ner/default/abc",
		Manifest: pluginmodel.Manifest{
			Endpoint:  pluginmodel.Endpoint{Local: &pluginmodel.LocalEndpoint{Transport: "jsonrpc-unix", Command: "bin/acme", Args: []string{"--serve"}}},
			Network:   pluginmodel.Network{Egress: []string{"hooks.slack.com:443"}},
			Resources: &pluginmodel.Resources{MemoryMB: 256},
		},
	}
	e, ok := plugin.EntryFor(config.Plugin{Name: "acme-ner", Enabled: true}, local)
	require.True(t, ok)
	require.Equal(t, servicespec.PluginEntry{
		Name: "acme-ner", Instance: "default", Dir: local.Dir, Command: "bin/acme", Args: []string{"--serve"},
		Egress: []string{"hooks.slack.com:443"}, MemoryMB: 256, Enabled: true,
	}, e)

	remote := pluginmodel.Verified{Manifest: pluginmodel.Manifest{Endpoint: pluginmodel.Endpoint{Remote: &pluginmodel.RemoteEndpoint{Transport: "connectrpc", URL: "https://x.example"}}}}
	_, ok = plugin.EntryFor(config.Plugin{Name: "acme-ner"}, remote)
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
	h := plugin.HostFor(cfg, "linux", "/etc/basalt/engine.json", "basalt")
	require.Equal(t, servicespec.PluginHost{
		GOOS: "linux", EngineUser: "basalt", ConfigDir: "/etc/basalt", StateDir: config.DefaultStateDir("linux"), SocketDir: "/run/basalt",
		CredentialFiles: []string{"/etc/basalt/agents/product_a.url", "/srv/x.url"},
	}, h)

	// Copies that are not installed are left out of install, with a line.
	var warn strings.Builder
	require.Empty(t, plugin.ServiceUnits{Files: pluginPorts.Files, TerminalText: cli.TerminalText}.WithPluginUnits(servicespec.Spec{GOOS: "linux", ConfigPath: "/etc/basalt/engine.json", User: "basalt"}, cfg, &warn).Plugins)
	require.Contains(t, warn.String(), "plugin acme-ner/default: its service unit is left as it is")
}

// agentOSUser is an OS user that exists and is neither the test's user nor
// in its group, for an agent when the test's user stands in for the
// engine's: root.
func agentOSUser(t *testing.T) string {
	t.Helper()
	require.NoError(t, setupcli.CheckAgentOSUser("root", me(t)), "root stands in for an agent's OS user")
	return "root"
}
