package config_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

const pluginSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// pluginConfig is an engine.json with agents product_a and product_b and
// the given plugins value (raw JSON), or no plugins key when it is "".
func pluginConfig(plugins string) string {
	s := `{"socketDir": "/s", "agents": [
		{"name": "product_a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}},
		{"name": "product_b", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/d"}}]`
	if plugins != "" {
		s += `, "plugins": ` + plugins
	}
	return s + "}"
}

func entry(extra string) string {
	return `{"name": "acme-ner", "manifestSha256": "` + pluginSHA + `", "enabled": false` + extra + `}`
}

func loadPlugins(t *testing.T, plugins string) (config.Config, error) {
	t.Helper()
	return config.Load(write(t, "engine.json", pluginConfig(plugins), 0o600))
}

func TestNoPluginsKeyMeansNone(t *testing.T) {
	t.Parallel()
	c, err := loadPlugins(t, "")
	require.NoError(t, err)
	require.Empty(t, c.Plugins)
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "plugins", "a config with no entries writes no plugins key")

	c, err = loadPlugins(t, `[]`)
	require.NoError(t, err)
	require.Empty(t, c.Plugins)
}

func TestPluginsRequireAgents(t *testing.T) {
	t.Parallel()
	for name, p := range map[string]string{
		"missing": entry(""),
		"null":    entry(`, "agents": null`),
	} {
		_, err := loadPlugins(t, "["+p+"]")
		require.ErrorContains(t, err, "agents is required", name)
	}
	c, err := loadPlugins(t, "["+entry(`, "agents": []`)+"]")
	require.NoError(t, err, "an empty list serves none and is valid")
	require.NotNil(t, c.Plugins[0].Agents)
	require.Empty(t, c.Plugins[0].Agents)
}

func TestPluginsUnknownAgent(t *testing.T) {
	t.Parallel()
	_, err := loadPlugins(t, "["+entry(`, "agents": ["product_a", "client_x"]`)+"]")
	var unknown *config.UnknownAgentError
	require.ErrorAs(t, err, &unknown)
	require.Equal(t, "client_x", unknown.Agent)
	require.Equal(t, plugin.EntryKey{Name: "acme-ner", Instance: "default"}, unknown.Entry)

	_, err = loadPlugins(t, "["+entry(`, "agents": ["product_a", "product_a"]`)+"]")
	require.ErrorContains(t, err, "listed twice")

	c, err := loadPlugins(t, "["+entry(`, "agents": ["product_a", "product_b"]`)+"]")
	require.NoError(t, err)
	require.Equal(t, []string{"product_a", "product_b"}, c.Plugins[0].Agents)
}

func TestTimeoutBounds(t *testing.T) {
	t.Parallel()
	for _, ms := range []int{49, 60001, -1} {
		_, err := loadPlugins(t, "["+entry(fmt.Sprintf(`, "agents": [], "timeoutMs": %d`, ms))+"]")
		require.ErrorContains(t, err, "timeoutMs", "%d", ms)
	}
	for _, ms := range []int{50, 60000} {
		c, err := loadPlugins(t, "["+entry(fmt.Sprintf(`, "agents": [], "timeoutMs": %d`, ms))+"]")
		require.NoError(t, err, "%d", ms)
		require.Equal(t, time.Duration(ms)*time.Millisecond, c.Plugins[0].Timeout(false))
		require.Equal(t, time.Duration(ms)*time.Millisecond, c.Plugins[0].Timeout(true))
	}
	// Unset: the endpoint's default.
	p := config.Plugin{}
	require.Equal(t, 300*time.Millisecond, p.Timeout(false))
	require.Equal(t, 2*time.Second, p.Timeout(true))
}

func TestConfigCredentialRule(t *testing.T) {
	t.Parallel()
	refused := map[string]string{
		"url with password":   `{"db": "https://bot:hunter2@db.example/app"}`,
		"url with user":       `{"hook": "https://someone@hooks.example/x"}`,
		"password= in value":  `{"dsn": "host=db user=bot password=hunter2"}`,
		"PASSWORD= any case":  `{"dsn": "PassWord=hunter2"}`,
		"in a key":            `{"https://u:p@h.example": true}`,
		"nested in an array":  `{"targets": [{"url": "https://u:p@h.example"}]}`,
		"password= in a key":  `{"x password=y": 1}`,
		"not an object":       `["a"]`,
		"over 16 KiB compact": `{"s": "` + strings.Repeat("a", config.MaxPluginConfigBytes) + `"}`,
	}
	for name, cfg := range refused {
		_, err := loadPlugins(t, "["+entry(`, "agents": [], "config": `+cfg)+"]")
		require.Error(t, err, name)
		require.NotContains(t, err.Error(), "hunter2", "%s: the error quotes the config", name)
	}
	allowed := map[string]string{
		"plain url":       `{"endpoint": "https://hooks.example/x", "languages": ["en", "id"]}`,
		"word password":   `{"note": "no password here"}`,
		"16 KiB compact":  `{"s": "` + strings.Repeat("a", config.MaxPluginConfigBytes-8) + `"}`,
		"spaces not size": `{"s":` + strings.Repeat(" ", config.MaxPluginConfigBytes) + `"a"}`,
	}
	for name, cfg := range allowed {
		_, err := loadPlugins(t, "["+entry(`, "agents": [], "config": `+cfg)+"]")
		require.NoError(t, err, name)
	}
}

func TestPluginEntryRules(t *testing.T) {
	t.Parallel()
	refused := map[string]string{
		"duplicate default": "[" + entry(`, "agents": []`) + ", " + entry(`, "instance": "default", "agents": []`) + "]",
		"bad instance":      "[" + entry(`, "instance": "Client-X", "agents": []`) + "]",
		"bad sha":           `[{"name": "acme-ner", "manifestSha256": "ABC", "enabled": false, "agents": []}]`,
		"bad name":          `[{"name": "Acme", "manifestSha256": "` + pluginSHA + `", "enabled": false, "agents": []}]`,
		"relative auth":     "[" + entry(`, "agents": [], "auth": {"credentialFile": "token"}`) + "]",
		"empty auth":        "[" + entry(`, "agents": [], "auth": {}`) + "]",
		"confidence":        "[" + entry(`, "agents": [], "minConfidence": 1.5`) + "]",
		"unknown key":       "[" + entry(`, "agents": [], "secret": "x"`) + "]",
	}
	for name, p := range refused {
		_, err := loadPlugins(t, p)
		require.Error(t, err, name)
	}
	c, err := loadPlugins(t, "["+entry(`, "agents": ["product_a"]`)+", "+entry(`, "instance": "client_x", "agents": ["product_b"]`)+"]")
	require.NoError(t, err, "two instances of one plugin are two entries")
	require.Equal(t, plugin.EntryKey{Name: "acme-ner", Instance: "default"}, c.Plugins[0].Key())
	require.Equal(t, plugin.EntryKey{Name: "acme-ner", Instance: "client_x"}, c.Plugins[1].Key())
	require.Equal(t, 1, c.PluginIndex(plugin.EntryKey{Name: "acme-ner", Instance: "client_x"}))
}

func TestPluginEntry(t *testing.T) {
	t.Parallel()
	local := plugin.Manifest{Name: "acme-ner", Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: "jsonrpc-stdio", Command: "bin/x"}}}
	remote := plugin.Manifest{Name: "acme-ner", Endpoint: plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: "connectrpc", URL: "https://ner.example"}}}
	p := config.Plugin{Name: "acme-ner", Agents: []string{"product_a"}}

	e, err := p.Entry(local)
	require.NoError(t, err)
	require.Equal(t, plugin.EntryKey{Name: "acme-ner", Instance: "default"}, e.Key)
	require.Equal(t, 300*time.Millisecond, e.Timeout)
	require.JSONEq(t, `{}`, string(e.Config))
	require.Equal(t, []string{"product_a"}, e.Agents)

	p.Auth = &config.PluginAuth{CredentialFile: "/etc/basalt/plugins/acme.token"}
	_, err = p.Entry(local)
	require.True(t, errors.Is(err, config.ErrAuthNotRemote), "auth on a local plugin is refused")
	e, err = p.Entry(remote)
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, e.Timeout)
	require.Equal(t, "/etc/basalt/plugins/acme.token", p.CredentialFile())
}

func TestUpdateConfigLeavesTheFileOnFailure(t *testing.T) {
	t.Parallel()
	path := write(t, "engine.json", pluginConfig(""), 0o600)
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	written := false
	err = config.UpdateConfig(path, config.Change{Apply: func(c *config.Config) error {
		c.Plugins = append(c.Plugins, config.Plugin{Name: "acme-ner", ManifestSHA256: pluginSHA, Agents: []string{"client_x"}})
		return nil
	}, Written: func(config.Config) { written = true }})
	var unknown *config.UnknownAgentError
	require.ErrorAs(t, err, &unknown, "a change the engine would refuse to load is not written")
	err = config.UpdateConfig(path, config.Change{Apply: func(*config.Config) error { return errors.New("declined") }})
	require.EqualError(t, err, "declined")
	require.False(t, written, "Written runs only after a write")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)

	require.NoError(t, config.UpdateConfig(path, config.Change{Apply: func(c *config.Config) error {
		c.Plugins = append(c.Plugins, config.Plugin{Name: "acme-ner", ManifestSHA256: pluginSHA, Agents: []string{}})
		return nil
	}, Written: func(config.Config) { written = true }}))
	require.True(t, written)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, c.Plugins, 1)
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), fi.Mode().Perm())
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 2, "only engine.json and its lock: no temporary file left")
}

// The approval key loads as "REQUIRED" only, and the entry requires
// approval with it, or on an agent-operated engine without it. In service
// mode nothing changes: the key is refused when the config is loaded, as
// before, and no entry requires approval there.
func TestPluginApprovalKey(t *testing.T) {
	t.Parallel()
	c, err := loadPlugins(t, "["+entry(`, "agents": ["product_a"], "approval": "REQUIRED"`)+"]")
	require.NoError(t, err)
	require.Equal(t, config.PluginApprovalRequired, c.Plugins[0].Approval)
	require.True(t, c.PluginRequiresApproval(c.Plugins[0]))
	raw, err := json.Marshal(c.Plugins[0])
	require.NoError(t, err)
	require.Contains(t, string(raw), `"approval":"REQUIRED"`)

	for _, bad := range []string{`"required"`, `""`, `null`, `true`, `"OPTIONAL"`} {
		_, err := loadPlugins(t, "["+entry(`, "agents": ["product_a"], "approval": `+bad)+"]")
		require.Error(t, err, bad)
	}

	c, err = loadPlugins(t, "["+entry(`, "agents": ["product_a"]`)+"]")
	require.NoError(t, err)
	require.Empty(t, c.Plugins[0].Approval)
	raw, err = json.Marshal(c.Plugins[0])
	require.NoError(t, err)
	require.NotContains(t, string(raw), "approval", "no key is written for an entry without it")
	require.False(t, c.PluginRequiresApproval(c.Plugins[0]))
	c.OperatedBy = "AGENT"
	require.True(t, c.PluginRequiresApproval(c.Plugins[0]), "an agent-operated engine requires approval of every entry")

	c.Mode = config.ModeService
	require.False(t, c.PluginRequiresApproval(c.Plugins[0]), "service mode is unchanged")
	c.Plugins[0].Approval = config.PluginApprovalRequired
	require.False(t, c.PluginRequiresApproval(c.Plugins[0]), "service mode is unchanged")

	svc := strings.Replace(pluginConfig("["+entry(`, "agents": ["product_a"], "approval": "REQUIRED"`)+"]"), `{"socketDir"`, `{"mode": "SERVICE", "socketDir"`, 1)
	_, err = config.Load(write(t, "engine.json", svc, 0o600))
	require.ErrorContains(t, err, "approval", "service mode refuses the key as before")
}

// A config with a key repeated in any object is refused: Postgres keeps the
// last value, a plugin's parser may keep the first, so the person would
// approve a value the plugin never reads.
func TestPluginConfigRepeatedKeyRefused(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"dest": "evil", "dest": "good"}`,
		`{"a": {"dest": 1, "dest": 2}}`,
		`{"a": [{"x": 1}, {"y": 1, "y": 2}]}`,
	} {
		require.ErrorContains(t, config.CheckPluginConfig(json.RawMessage(raw)), "more than once", raw)
		_, err := loadPlugins(t, "["+entry(`, "agents": ["product_a"], "config": `+raw)+"]")
		require.Error(t, err, raw)
	}
	require.NoError(t, config.CheckPluginConfig(json.RawMessage(`{"a": {"x": 1}, "b": {"x": 2}, "c": [{"x": 1}, {"x": 2}]}`)),
		"the same key in different objects is fine")
}

// The settings an approval binds are the entry's keys besides name,
// instance, manifestSha256, enabled, agents and approval, each only when
// set, config as engine.json holds it.
func TestPluginApprovalSettings(t *testing.T) {
	t.Parallel()
	c, err := loadPlugins(t, "["+entry(`, "agents": ["product_a"], "approval": "REQUIRED", "timeoutMs": 300, "minConfidence": 0.60, `+
		`"config": {"threshold": 0.60, "max": 1e3}, "auth": {"credentialFile": "/etc/t"}`)+"]")
	require.NoError(t, err)
	raw, err := json.Marshal(c.Plugins[0].ApprovalSettings())
	require.NoError(t, err)
	require.JSONEq(t, `{"config": {"threshold": 0.60, "max": 1e3}, "auth": {"credentialFile": "/etc/t"}, "timeoutMs": 300, "minConfidence": 0.6}`, string(raw))
	require.Contains(t, string(raw), `0.60`, "config keeps how a number was written")

	c, err = loadPlugins(t, "["+entry(`, "agents": ["product_a"]`)+"]")
	require.NoError(t, err)
	raw, err = json.Marshal(c.Plugins[0].ApprovalSettings())
	require.NoError(t, err)
	require.Equal(t, `{}`, string(raw), "no default is filled in")
}

func TestRemoveAgentsTakesThemOffThePluginEntries(t *testing.T) {
	t.Parallel()
	path := write(t, "engine.json", pluginConfig(`[`+entry(`, "agents": ["product_a", "product_b"]`)+`]`), 0o600)
	removed, err := config.RemoveAgents(path, []string{"product_a"})
	require.NoError(t, err)
	require.False(t, removed)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, c.Agents, 1)
	require.Equal(t, []string{"product_b"}, c.Plugins[0].Agents)

	removed, err = config.RemoveAgents(path, []string{"product_b"})
	require.NoError(t, err)
	require.True(t, removed, "no agent is left, so the config goes")
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}
