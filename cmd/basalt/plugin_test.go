//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// The plugin's shipped file. Tests check no output ever quotes it.
const pluginBinary = "#!/bin/sh\necho TOP-SECRET-PLUGIN-BYTES\n"

// pluginEngine is a same-user engine under t.TempDir() with agents
// product_a and product_b, a trusted signing key, and a source directory
// holding a signed local plugin.
type pluginEngine struct {
	t          *testing.T
	base       string
	configPath string
	root       string
	trustDir   string
	src        string
	signer     *ecdsa.PrivateKey
	host       *fakeHost
	// agents is the config's agents array; product_a and product_b with
	// credential files that do not exist when empty.
	agents string
	// mode is the config's mode, SAME_USER when empty.
	mode string
}

func newPluginEngine(t *testing.T) *pluginEngine {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	e := &pluginEngine{t: t, base: base, configPath: filepath.Join(base, "config", "engine.json"), src: filepath.Join(base, "src"), host: newFakeHost(t)}
	require.NoError(t, os.Mkdir(filepath.Dir(e.configPath), 0o700))
	e.writeConfig("")
	dir := filepath.Dir(e.configPath)
	e.root, err = plugin.Root(plugin.ModeSameUser, runtime.GOOS, dir)
	require.NoError(t, err)
	e.trustDir, err = plugin.TrustDir(plugin.ModeSameUser, runtime.GOOS, dir)
	require.NoError(t, err)
	e.signer, err = plugin.GenerateKey()
	require.NoError(t, err)
	e.trustKey(&e.signer.PublicKey)
	e.writePlugin(e.src, pluginManifest("1.4.0", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME", "acme-ner.EMPLOYEE_ID"]}`, ""), e.signer)
	return e
}

func (e *pluginEngine) writeConfig(operatedBy string) {
	e.t.Helper()
	extra := ""
	if operatedBy != "" {
		extra = fmt.Sprintf(`, "operatedBy": %q`, operatedBy)
	}
	if operatedBy == "AGENT" {
		// An agent-operated engine uses the portal's pages.
		extra += `, "pagesUrl": "https://portal.basaltvault.app"`
	}
	var plugins json.RawMessage
	if c, err := config.Load(e.configPath); err == nil && len(c.Plugins) > 0 {
		plugins, err = json.Marshal(c.Plugins)
		require.NoError(e.t, err)
		extra += `, "plugins": ` + string(plugins)
	}
	agents := e.agents
	if agents == "" {
		agents = `[
		{"name": "product_a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}},
		{"name": "product_b", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/d"}}]`
	}
	mode := e.mode
	if mode == "" {
		mode = "SAME_USER"
	}
	require.NoError(e.t, config.WriteFile(e.configPath, []byte(`{"socketDir": "/run/x", "mode": "`+mode+`", "agents": `+agents+extra+`}`)))
}

func (e *pluginEngine) trustKey(pub *ecdsa.PublicKey) {
	e.t.Helper()
	ts, err := plugin.NewTrustStore(plugin.ModeSameUser, runtime.GOOS, filepath.Dir(e.configPath))
	require.NoError(e.t, err)
	pemBytes, err := plugin.MarshalPublicKey(pub)
	require.NoError(e.t, err)
	_, _, err = ts.Add(pemBytes)
	require.NoError(e.t, err)
}

// pluginManifest is a local plugin acme-ner with the given hooks object
// members and egress entries (raw JSON inside the brackets).
func pluginManifest(version, hooks, egress string) string {
	return fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": %q, "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { %s },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner" } },
  "files": { "bin/acme-ner": "sha256:%x" },
  "network": { "egress": [%s] }
}
`, version, hooks, sha256.Sum256([]byte(pluginBinary)), egress)
}

const remotePluginManifest = `{
  "manifestVersion": 1, "name": "acme-cloud", "version": "2.0.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE", "NAME_CUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "remote": { "transport": "connectrpc", "url": "https://ner.acme.example" } },
  "network": { "egress": ["ner.acme.example:443"] }
}
`

// writePlugin writes manifest, its signature by signer and the binary
// into dir.
func (e *pluginEngine) writePlugin(dir, manifest string, signer *ecdsa.PrivateKey) {
	e.t.Helper()
	require.NoError(e.t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	require.NoError(e.t, os.WriteFile(filepath.Join(dir, "bin", "acme-ner"), []byte(pluginBinary), 0o755))
	require.NoError(e.t, os.WriteFile(filepath.Join(dir, plugin.ManifestFile), []byte(manifest), 0o644))
	sig, err := plugin.SignManifest([]byte(manifest), signer)
	require.NoError(e.t, err)
	require.NoError(e.t, os.WriteFile(filepath.Join(dir, plugin.SignatureFile), sig, 0o644))
}

// newSource writes a plugin with manifest, signed by the trusted key, into
// a new directory.
func (e *pluginEngine) newSource(manifest string) string {
	e.t.Helper()
	dir, err := os.MkdirTemp(e.base, "src-")
	require.NoError(e.t, err)
	e.writePlugin(dir, manifest, e.signer)
	return dir
}

// run runs basalt plugin args with an environment holding only env, and
// stdin answering the prompt.
func (e *pluginEngine) run(env map[string]string, stdin string, args ...string) result {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr}, func(k string) string { return env[k] })
	c.host = e.host
	code := runPlugin(c, append(args, "--config", e.configPath))
	r := result{code, stdout.String(), stderr.String()}
	for _, s := range []string{"TOP-SECRET", "PRIVATE KEY"} {
		require.NotContains(e.t, r.stdout+r.stderr, s, "basalt plugin %v printed a file's contents", args)
	}
	return r
}

// person runs a command as the person, answering yes.
func (e *pluginEngine) person(args ...string) result {
	e.t.Helper()
	r := e.run(nil, "y\n", args...)
	require.Equal(e.t, exitOK, r.code, "%v: %s", args, r.stderr)
	return r
}

func (e *pluginEngine) config() config.Config {
	e.t.Helper()
	c, err := config.Load(e.configPath)
	require.NoError(e.t, err)
	return c
}

// snapshot is every file and directory under the engine's base with its
// mode and contents: engine.json, the plugin root and the trust store.
func (e *pluginEngine) snapshot() map[string]string {
	e.t.Helper()
	out := map[string]string{}
	require.NoError(e.t, filepath.WalkDir(e.base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(filepath.Base(p), "src") {
			return filepath.SkipDir
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[p] = v
		return nil
	}))
	return out
}

// refusal decodes a --json refusal body and checks it against the
// next-steps catalog.
func refusal(t *testing.T, r result, reason string) mcp.ToolError {
	t.Helper()
	require.Equal(t, exitError, r.code, r.stderr)
	var body mcp.ToolError
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &body), r.stdout+r.stderr)
	require.Equal(t, codePluginRefused, body.Code)
	require.Equal(t, reason, body.Reason, body.Message)
	require.NotEmpty(t, body.PersonMessage)
	catalog, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	want, ok := catalog.ErrorEntry(body.Code, body.Reason, "")
	require.True(t, ok)
	steps := want.Steps
	// On an agent-operated engine a variant may replace the steps.
	if v, ok := catalog.AgentOperatedEntry("ERROR", body.Code, body.Reason, ""); ok && len(body.NextSteps) > 0 &&
		body.NextSteps[0].Actor == mcp.ActorAgent && steps[0].Actor != mcp.ActorAgent {
		steps = v.Steps
	}
	require.Len(t, body.NextSteps, len(steps))
	for i, s := range steps {
		// An OPERATOR step is the person's, or the agent's on an
		// agent-operated engine.
		if s.Actor == "OPERATOR" {
			require.Contains(t, []string{mcp.ActorPerson, mcp.ActorAgent}, body.NextSteps[i].Actor)
		} else {
			require.Equal(t, s.Actor, body.NextSteps[i].Actor)
		}
		require.Equal(t, s.Action, body.NextSteps[i].Action)
	}
	return body
}

func TestAddShowsConsent(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	before := e.snapshot()

	// Declined: everything is shown, nothing is written or left behind.
	r := e.run(nil, "n\n", "add", e.src, "--agents", "product_a,product_b")
	require.Equal(t, exitError, r.code, r.stderr)
	for _, want := range []string{
		"Plugin acme-ner 1.4.0 from Acme, instance default",
		"Hooks:        wire.detect (roles VALUE)",
		"Entity types: PERSON_NAME, acme-ner.EMPLOYEE_ID",
		"Egress:       none",
		"LOCAL (runs on this machine)",
		"Agents:       product_a, product_b",
		"Same-user mode",
	} {
		require.Contains(t, r.stderr, want)
	}
	id := signerID(t, e.signer)
	require.Contains(t, r.stderr, "Signer:       "+id)
	require.Less(t, strings.Index(r.stderr, "Agents:"), strings.Index(r.stderr, "[y/N]"), "consent comes before the question")
	require.Contains(t, r.stderr, "nothing was written")
	after := e.snapshot()
	require.Equal(t, before[e.configPath], after[e.configPath], "engine.json unchanged")
	require.Empty(t, entriesUnder(t, filepath.Join(e.root, "acme-ner", "default")), "the staged copy is discarded")

	// Yes: the entry is added, disabled, naming the copy consent showed.
	r = e.person("add", e.src, "--agents", "product_a,product_b")
	require.Contains(t, r.stderr, "added, disabled")
	require.Contains(t, r.stderr, "basalt plugin enable acme-ner --config "+e.configPath)
	require.Contains(t, r.stderr, "basalt engine --config "+e.configPath, "prints the engine restart command")
	c := e.config()
	require.Len(t, c.Plugins, 1)
	p := c.Plugins[0]
	require.False(t, p.Enabled)
	require.Equal(t, []string{"product_a", "product_b"}, p.Agents)
	v, err := plugin.Verify(e.root, p.Key(), p.ManifestSHA256, e.trustStore(), plugin.ModeSameUser)
	require.NoError(t, err)
	require.Equal(t, id, v.SignerKeyID)

	list := e.run(nil, "", "list")
	require.Equal(t, exitOK, list.code, list.stderr)
	require.Contains(t, list.stdout, "acme-ner  instance default  disabled")
	require.Contains(t, list.stdout, "version 1.4.0  signer "+id+"  endpoint LOCAL")
	require.Contains(t, list.stdout, "agents product_a, product_b")
}

func TestAddShowsWarnings(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	remote := e.newSource(remotePluginManifest)
	_ = os.Remove(filepath.Join(remote, "bin", "acme-ner"))
	_ = os.Remove(filepath.Join(remote, "bin"))
	r := e.person("add", remote, "--agents", "product_a")
	require.Contains(t, r.stderr, "REMOTE at ner.acme.example:443")
	require.Contains(t, r.stderr, "not what runs on ner.acme.example:443")
	require.Contains(t, r.stderr, "declares NAME_CUE: it sees stored values in free text, so with it those values leave this machine")
	require.NotContains(t, r.stderr, "Same-user mode", "a remote plugin does not run here")

	deliver := e.newSource(strings.Replace(pluginManifest("1.0.0", `"feed.observe": {"contract": "feed/1"}, "approval.deliver": {"contract": "deliver/1"}`, `"chat.example:443"`),
		`"acme-ner"`, `"acme-notify"`, 1))
	r = e.person("add", deliver, "--agents", "product_a")
	require.Contains(t, r.stderr, "approval.deliver: It delivers your approval links. Anyone who can read where it delivers them can see the rows of writes "+
		"waiting for your approval. Some links carry the whole request, so they can also see what the agent asked to run and why.")
	require.Contains(t, r.stderr, "runs with network access: its egress list is declared, not enforced per host")
	require.Contains(t, r.stderr, "Egress:       chat.example:443")
}

func TestAddEscapesManifestText(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	src := e.newSource(strings.Replace(pluginManifest("1.4.0", `"feed.observe": {"contract": "feed/1"}`, ""), `"Acme"`, `"Acme\u001b[2J\nAgents: none"`, 1))
	r := e.run(nil, "n\n", "add", src, "--agents", "product_a")
	require.NotContains(t, r.stderr, "\x1b", "a manifest cannot draw on the terminal")
	require.NotContains(t, r.stderr, "\nAgents: none")
}

func (e *pluginEngine) trustStore() plugin.TrustStore {
	e.t.Helper()
	ts, err := plugin.NewTrustStore(plugin.ModeSameUser, runtime.GOOS, filepath.Dir(e.configPath))
	require.NoError(e.t, err)
	return ts
}

func signerID(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	id, err := plugin.KeyID(&k.PublicKey)
	require.NoError(t, err)
	return id
}

func entriesUnder(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	names := make([]string, 0, len(des))
	for _, d := range des {
		names = append(names, d.Name())
	}
	return names
}

func TestAddRefusesBadManifests(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	before := e.snapshot()
	for name, manifest := range map[string]string{
		"wire.verdict":             pluginManifest("1.0.0", `"wire.verdict": {"contract": "verdict/1"}`, ""),
		"detect with feed.observe": pluginManifest("1.0.0", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["EMAIL"]}, "feed.observe": {"contract": "feed/1"}`, ""),
		"foreign entity type":      pluginManifest("1.0.0", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["other-plugin.X"]}`, ""),
	} {
		r := e.run(nil, "y\n", "add", e.newSource(manifest), "--agents", "product_a", "--json")
		body := refusal(t, r, "BAD_MANIFEST")
		require.Contains(t, body.Message, "(BAD_MANIFEST)", name)
	}
	require.Equal(t, before, e.snapshot(), "nothing written for a refused manifest")

	untrusted, err := plugin.GenerateKey()
	require.NoError(t, err)
	dir, err := os.MkdirTemp(e.base, "src-")
	require.NoError(t, err)
	e.writePlugin(dir, pluginManifest("1.0.0", `"feed.observe": {"contract": "feed/1"}`, ""), untrusted)
	body := refusal(t, e.run(nil, "y\n", "add", dir, "--agents", "product_a", "--json"), "NOT_TRUSTED")
	require.Equal(t, "basalt plugin trust <publisher key file> --config "+e.configPath, body.NextSteps[0].Command)
	require.Contains(t, body.NextSteps[1].Command, "basalt plugin add "+dir+" --agents product_a --config "+e.configPath)

	body = refusal(t, e.run(nil, "y\n", "add", e.src, "--agents", "product_a,client_x", "--json"), "UNKNOWN_AGENT")
	require.Equal(t, "basalt plugin add "+e.src+" --agents product_a --config "+e.configPath, body.NextSteps[0].Command)
	require.Contains(t, body.PersonMessage, "product_a, product_b")
	require.Equal(t, before, e.snapshot(), "nothing written for a refused command; no plugin root made")
}

// TestWideningByAgentOpensNothingUnchecked: in same-user mode, under an
// agent marker or on an engine an agent operates, add and enable take the
// plugin approval flow, trust stays refused, and every refusal before the
// write leaves disk unchanged. These agents' credential files do not
// exist, so the flow refuses DATABASE_UNREACHABLE before writing.
func TestWideningByAgentOpensNothingUnchecked(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		env        map[string]string
		operatedBy string
	}{
		"CLAUDECODE=1":       {env: map[string]string{"CLAUDECODE": "1"}},
		"operatedBy AGENT":   {operatedBy: "AGENT"},
		"BASALT_AGENT set":   {env: map[string]string{envAgentContext: "1"}},
		"marker and AGENT":   {env: map[string]string{"CURSOR_AGENT": "1"}, operatedBy: "AGENT"},
		"operatedBy PERSON+": {env: map[string]string{"CODEX_SANDBOX": "seatbelt"}, operatedBy: "PERSON"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newPluginEngine(t)
			e.person("add", e.src, "--agents", "product_a")
			e.writeConfig(tc.operatedBy)
			newer := e.newSource(pluginManifest("1.5.0", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME", "acme-ner.EMPLOYEE_ID"]}`, ""))
			egress := e.newSource(pluginManifest("1.4.0", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME", "acme-ner.EMPLOYEE_ID"]}`, `"evil.example:443"`))
			key, err := plugin.GenerateKey()
			require.NoError(t, err)
			pub, err := plugin.MarshalPublicKey(&key.PublicKey)
			require.NoError(t, err)
			keyFile := filepath.Join(t.TempDir(), "publisher.pub")
			require.NoError(t, os.WriteFile(keyFile, pub, 0o644))
			before := e.snapshot()

			for what, c := range map[string]struct {
				args   []string
				reason string
			}{
				"enable":               {[]string{"enable", "acme-ner"}, reasonDatabaseUnreachable},
				"add another instance": {[]string{"add", e.src, "--agents", "product_a", "--instance", "client_x"}, reasonDatabaseUnreachable},
				"widen agents":         {[]string{"add", e.src, "--agents", "product_a,product_b"}, reasonDatabaseUnreachable},
				"swap agents":          {[]string{"add", e.src, "--agents", "product_b"}, reasonDatabaseUnreachable},
				"new version":          {[]string{"add", newer, "--agents", "product_a"}, reasonDatabaseUnreachable},
				"new egress":           {[]string{"add", egress, "--agents", "product_a"}, reasonDatabaseUnreachable},
				"new plugin":           {[]string{"add", e.newSource(remotePluginManifest), "--agents", "product_a"}, reasonDatabaseUnreachable},
				"trust":                {[]string{"trust", keyFile}, reasonAgentOperated},
				"unknown agent":        {[]string{"add", e.src, "--agents", "client_x"}, reasonUnknownAgent},
			} {
				r := e.run(tc.env, "y\n", append(c.args, "--json")...)
				refusal(t, r, c.reason)
				require.NotContains(t, r.stderr, "[y/N]", "%s: refused before any prompt", what)
				require.Equal(t, before, e.snapshot(), "%s: engine.json, the plugin root and the trust store are unchanged", what)
			}
			r := e.run(tc.env, "y\n", "add", filepath.Join(e.base, "nowhere"), "--agents", "product_a")
			require.Equal(t, exitError, r.code)
			r = e.run(tc.env, "y\n", "enable", "acme-ner", "--instance", "client_x")
			require.Equal(t, exitError, r.code)
			require.Equal(t, before, e.snapshot())
		})
	}
}

// Under an agent, the one add allowed removes agents from an existing
// entry with the same manifest bytes; disable and remove still work.
func TestDisableAllowedForAgent(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		env        map[string]string
		operatedBy string
	}{
		"CLAUDECODE=1":     {env: map[string]string{"CLAUDECODE": "1"}},
		"operatedBy AGENT": {operatedBy: "AGENT"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newPluginEngine(t)
			e.person("add", e.src, "--agents", "product_a,product_b")
			e.person("enable", "acme-ner")
			e.person("add", e.src, "--agents", "product_a", "--instance", "client_x")
			e.writeConfig(tc.operatedBy)
			require.True(t, e.config().Plugins[0].Enabled)

			r := e.run(tc.env, "", "add", e.src, "--agents", "product_a")
			require.Equal(t, exitOK, r.code, r.stderr)
			require.Equal(t, []string{"product_a"}, e.config().Plugins[0].Agents, "narrowing is allowed")
			require.True(t, e.config().Plugins[0].Enabled, "and keeps enabled")

			r = e.run(tc.env, "", "disable", "acme-ner")
			require.Equal(t, exitOK, r.code, r.stderr)
			require.Contains(t, r.stderr, "no restart is needed", "a same-user engine stops it while it runs")
			require.NotContains(t, r.stderr, "basalt engine --config ")
			require.False(t, e.config().Plugins[0].Enabled)

			client := e.config().Plugins[1]
			r = e.run(tc.env, "", "remove", "acme-ner")
			require.Equal(t, exitOK, r.code, r.stderr)
			c := e.config()
			require.Len(t, c.Plugins, 1)
			require.Equal(t, "client_x", c.Plugins[0].Instance)
			require.Empty(t, entriesUnder(t, filepath.Join(e.root, "acme-ner", "default")), "the removed entry's copies are gone")
			_, err := plugin.Verify(e.root, client.Key(), client.ManifestSHA256, e.trustStore(), plugin.ModeSameUser)
			require.NoError(t, err, "another instance shares nothing")
		})
	}
}

func TestChangeEntryShowsWhatChanges(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	e.person("add", e.src, "--agents", "product_a")
	e.person("enable", "acme-ner")
	first := e.config().Plugins[0]

	newer := e.newSource(pluginManifest("1.5.0", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE", "NAME_CUE"], "entityTypes": ["PERSON_NAME"]}`, ""))
	r := e.person("add", newer, "--agents", "product_b")
	for _, want := range []string{
		"Changes to the existing entry:",
		"Version: 1.4.0 -> 1.5.0",
		"Removes entity types: acme-ner.EMPLOYEE_ID",
		"Adds roles: NAME_CUE",
		"Adds agents: product_b",
		"Removes agents: product_a",
		"stays enabled",
	} {
		require.Contains(t, r.stderr, want)
	}
	p := e.config().Plugins[0]
	require.True(t, p.Enabled)
	require.Equal(t, []string{"product_b"}, p.Agents)
	require.NotEqual(t, first.ManifestSHA256, p.ManifestSHA256)
	require.Equal(t, []string{p.ManifestSHA256}, entriesUnder(t, filepath.Join(e.root, "acme-ner", "default")), "the old copy is swept")

	again := e.run(nil, "", "add", newer, "--agents", "product_b")
	require.Equal(t, exitOK, again.code)
	require.Contains(t, again.stderr, "nothing changed")

	// An enabled entry stays enabled, so a change enable would refuse is
	// refused here: auth on a local plugin.
	require.NoError(t, config.UpdateConfig(e.configPath, config.Change{Apply: func(c *config.Config) error {
		c.Plugins[0].Auth = &config.PluginAuth{CredentialFile: "/etc/basalt/plugins/acme.token"}
		return nil
	}}))
	before := e.snapshot()
	r = e.run(nil, "y\n", "add", e.src, "--agents", "product_b")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, config.ErrAuthNotRemote.Error())
	require.Equal(t, before, e.snapshot())
}

func TestEnableShowsConsentAndVerifies(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	e.person("add", e.src, "--agents", "product_a")
	before := e.snapshot()
	r := e.run(nil, "n\n", "enable", "acme-ner")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "Hooks:        wire.detect")
	require.Contains(t, r.stderr, "Agents:       product_a")
	require.Equal(t, before, e.snapshot())

	// A changed installed file is refused at enable.
	p := e.config().Plugins[0]
	bin := filepath.Join(e.root, "acme-ner", "default", p.ManifestSHA256, "bin", "acme-ner")
	require.NoError(t, os.WriteFile(bin, []byte(pluginBinary+"x"), 0o755))
	refusal(t, e.run(nil, "y\n", "enable", "acme-ner", "--json"), "NOT_TRUSTED")
	require.NoError(t, os.WriteFile(bin, []byte(pluginBinary), 0o755))

	r = e.person("enable", "acme-ner")
	require.Contains(t, r.stderr, "plugin acme-ner/default enabled")
	require.True(t, e.config().Plugins[0].Enabled)
	r = e.person("enable", "acme-ner")
	require.Contains(t, r.stderr, "already enabled; nothing changed")
	r = e.run(nil, "", "enable", "nope")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "has no plugin nope/default")
}

func TestTrustAsksAndAddsOnce(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	k, err := plugin.GenerateKey()
	require.NoError(t, err)
	pub, err := plugin.MarshalPublicKey(&k.PublicKey)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "acme.pub")
	require.NoError(t, os.WriteFile(file, pub, 0o644))
	id := signerID(t, k)

	r := e.run(nil, "n\n", "trust", file)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "Key id "+id)
	require.NotContains(t, entriesUnder(t, e.trustDir), id+".pem")

	r = e.person("trust", file)
	require.Contains(t, r.stderr, "key "+id+" trusted")
	require.Contains(t, entriesUnder(t, e.trustDir), id+".pem")
	require.Contains(t, r.stderr, "restart the engine so it trusts the key:\n  basalt engine --config "+e.configPath+"\n",
		"the engine reads its trust store at start, so trust names the restart")
	r = e.person("trust", file)
	require.Contains(t, r.stderr, "already trusted; nothing changed")
	require.NotContains(t, r.stderr, "restart the engine", "nothing changed, so nothing to restart for")

	bad := filepath.Join(t.TempDir(), "bad.pub")
	require.NoError(t, os.WriteFile(bad, []byte("not a key TOP-SECRET"), 0o644))
	r = e.run(nil, "y\n", "trust", bad)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, bad)
}

func TestPluginUsage(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	for _, args := range [][]string{
		{"add", e.src},
		{"add", e.src, "--agents", "product_a,product_a"},
		{"add", e.src, "--agents", "product_a", "--instance", "Client-X"},
		{"enable"},
		{"frobnicate"},
	} {
		r := e.run(nil, "", args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
	}
}

// TestPluginHelpSaysWhatTheCommandsTake: the usage line names every flag a
// command takes, approve's code as optional, and enable's real --wait
// default.
func TestPluginHelpSaysWhatTheCommandsTake(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	usage := e.run(nil, "", "frobnicate").stderr
	for _, part := range []string{
		"list [--json]",
		"add <dir> --agents a,b [--instance NAME] [--approve-with-passkey] [--wait SECONDS] [--json]",
		"enable <name> [--instance NAME] [--approve-with-passkey] [--approval-id ID[,ID]] [--wait SECONDS] [--json]",
		"approve [code] [--agent NAME] [--json]",
		"disable <name> [--instance NAME]",
		"check <name> [--instance NAME] [--json]",
		"trust <public key file> [--json]",
		"remove <name> [--instance NAME]",
		"keygen --out DIR",
		"sign <dir> --key FILE",
		"--config PATH",
	} {
		require.Contains(t, usage, part)
	}

	help := e.run(nil, "", "enable", "-h")
	require.Equal(t, exitOK, help.code)
	require.NotContains(t, help.stderr, "default -1")
	require.Contains(t, help.stderr, "default 0, or 90 with --approval-id")

	// The default is 0, and a negative --wait is refused, also the -1 that
	// used to stand for "not given".
	for _, wait := range []string{"-1", "-5", "111"} {
		r := e.run(nil, "", "enable", "acme-ner", "--wait", wait)
		require.Equal(t, exitUsage, r.code, "--wait %s: %s", wait, r.stderr)
		require.Contains(t, r.stderr, "--wait is seconds from 0 to 110")
	}
}

// TestPluginApproveWithoutCodeNeedsATerminal: approve asks for the code
// only at a terminal. With no code and no terminal it refuses at once,
// reading nothing, so a script or an agent never hangs on it.
func TestPluginApproveWithoutCodeNeedsATerminal(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	// A stdin that never yields a byte: a read of it would hang.
	stdin, w := io.Pipe()
	t.Cleanup(func() { _ = w.Close() })
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: stdin, out: &stdout, err: &stderr}, func(string) string { return "" })
	c.host = e.host
	var code int
	within(t, func() { code = runPlugin(c, []string{"approve", "--config", e.configPath}) })
	require.Equal(t, exitUsage, code, stderr.String())
	require.Contains(t, stderr.String(), "basalt plugin approve <code>")
	require.NotContains(t, stderr.String(), "Paste the code", "it does not ask where nobody can answer")

	// At a terminal it asks, and reads the pasted code.
	term, tw := fallbackIO(t, &stderr, noRawRead)
	term.host = e.host
	stderr.Reset()
	_, err := tw.WriteString("basalt-plugin.1.not-a-code\n")
	require.NoError(t, err)
	within(t, func() { code = runPlugin(term, []string{"approve", "--config", e.configPath}) })
	require.Equal(t, exitUsage, code, "the pasted text was read and is no code: %s", stderr.String())
	require.Contains(t, stderr.String(), "Paste the code the plugin approval page showed: ")
}
