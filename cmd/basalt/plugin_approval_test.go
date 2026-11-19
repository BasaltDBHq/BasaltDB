//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// agentEnv is the environment of a command an agent runs: the harness
// injects the marker, the test's own environment is never touched.
var agentEnv = map[string]string{envAgentContext: "1"}

// approvalEngine is a pluginEngine whose agents are real agent roles:
// product_a and product_b in one database, client_x in another, each with
// its credential file, and a person's passkey on the first database.
type approvalEngine struct {
	*pluginEngine
	db, other *guardtest.DB
	roles     map[string]*guardtest.Agent
	pk        *passkeytest.Authenticator
	// unsigned is a plugin source with no .sig.
	unsigned string
}

func newApprovalEngine(t *testing.T, operatedBy string) *approvalEngine {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	other := guardtest.New(t).WithDemo(t)
	return newApprovalEngineOn(t, d, other, operatedBy)
}

func newApprovalEngineOn(t *testing.T, d, other *guardtest.DB, operatedBy string) *approvalEngine {
	t.Helper()
	e := &approvalEngine{pluginEngine: newPluginEngine(t), db: d, other: other, roles: map[string]*guardtest.Agent{}}
	leads := []string{"public.leads"}
	e.roles["product_a"] = d.NewAgent(t, "product_a", leads, nil)
	e.roles["product_b"] = d.NewAgent(t, "product_b", leads, nil)
	if other != nil {
		e.roles["client_x"] = other.NewAgent(t, "client_x", leads, nil)
	}
	credDir := filepath.Join(e.base, "creds")
	require.NoError(t, os.Mkdir(credDir, 0o700))
	var agents []string
	for _, name := range []string{"product_a", "product_b", "client_x"} {
		a, ok := e.roles[name]
		if !ok {
			continue
		}
		file := filepath.Join(credDir, name+".url")
		require.NoError(t, os.WriteFile(file, []byte(a.URL+"\n"), 0o600))
		agents = append(agents, fmt.Sprintf(`{"name": %q, "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": %q}}`, name, file))
	}
	e.agents = "[" + strings.Join(agents, ",") + "]"
	e.writeConfig(operatedBy)
	var err error
	e.pk, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, e.pk.Credential(), "app"))
	e.unsigned = e.newSource(pluginManifest("0.3.1", `"wire.detect": {"contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"]}`, ""))
	require.NoError(t, os.Remove(filepath.Join(e.unsigned, plugin.SignatureFile)))
	return e
}

// result decodes and checks an approval result against
// api/plugin/approval/result.schema.json.
func approvalResultOf(t *testing.T, r result) approvalResult {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(r.stdout))
	require.NoError(t, err, r.stdout+r.stderr)
	require.NoError(t, resultSchema(t).Validate(inst), r.stdout)
	var res approvalResult
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &res))
	return res
}

var ecmaEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

func resultSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		return regexp.Compile(regexp.MustCompile(`\{([0-9]+),[0-9]{4,}\}`).ReplaceAllString(ecmaEscape.ReplaceAllString(s, `\x{$1}`), `{$1,}`))
	})
	for _, f := range []string{
		"../../api/plugin/approval/result.schema.json", "../../api/mcp/errors/next-step.schema.json",
		"../../api/mcp/links/link.schema.json", "../../api/mcp/links/request-file.schema.json",
	} {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		var head struct {
			ID string `json:"$id"`
		}
		require.NoError(t, json.Unmarshal(raw, &head))
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(head.ID, doc))
	}
	s, err := c.Compile("https://basaltvault.app/schemas/plugin/approval/result.v1.json")
	require.NoError(t, err)
	return s
}

// requestOf is the plugin approval request a long link carries.
func requestOf(t *testing.T, url string) (approval.PluginRequest, approval.PluginBinding) {
	t.Helper()
	_, frag, ok := strings.Cut(url, "#")
	require.True(t, ok, url)
	req, b, err := approval.ParsePluginRequest(frag)
	require.NoError(t, err)
	return req, b
}

// sign is the code the page gives the person after their passkey signs.
func (e *approvalEngine) sign(req approval.PluginRequest) string {
	e.t.Helper()
	as, err := e.pk.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(e.t, err)
	code, err := approval.NewPluginApprovalResponse(req.ApprovalID, as).Code()
	require.NoError(e.t, err)
	return code
}

func (e *approvalEngine) ledgerKind(name, kind string) int {
	e.t.Helper()
	d := e.db
	if name == "client_x" {
		d = e.other
	}
	var n int
	require.NoError(e.t, d.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM basalt_meta.ledger WHERE agent = $1 AND kind = $2`, e.roles[name].Role, kind).Scan(&n))
	return n
}

func stepKinds(steps []mcp.NextStep) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Actor + " " + s.Action
	}
	return out
}

// TestAddByAgentOpensApproval: an agent's add in same-user mode installs
// the copy, writes the entry enabled with "approval": "REQUIRED", opens one
// approval naming both agents and hands over a link: nothing is refused for
// an unsigned plugin, and its binding says UNKNOWN.
func TestAddByAgentOpensApproval(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a,product_b", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, "[y/N]", "no prompt: the page is where the person consents")
	res := approvalResultOf(t, r)

	c := e.config()
	require.Len(t, c.Plugins, 1)
	p := c.Plugins[0]
	require.True(t, p.Enabled)
	require.Equal(t, config.PluginApprovalRequired, p.Approval)
	require.Equal(t, []string{"product_a", "product_b"}, p.Agents)
	v, err := plugin.Verify(e.root, p.Key(), p.ManifestSHA256, e.trustStore(), plugin.ModeSameUser, plugin.RequireApproval(true))
	require.NoError(t, err, "the copy is in place")
	require.Equal(t, plugin.SignerUnknown, v.Signer)
	raw, err := os.ReadFile(e.configPath)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"approval": "REQUIRED"`)

	require.Equal(t, "acme-ner", res.Name)
	require.Len(t, res.Approvals, 1)
	a := res.Approvals[0]
	require.Nil(t, a.Refused)
	require.Equal(t, []string{"product_a", "product_b"}, a.Agents)
	require.Equal(t, dbName(t, e.db), a.Database.Name)
	require.True(t, strings.HasPrefix(a.URL, links.DefaultLocal+"/plugins/"+a.ApprovalID+"#2."), a.URL)
	req, b := requestOf(t, a.URL)
	require.Equal(t, guard.PluginSignerUnknown, b.Signer)
	require.Empty(t, b.SignerKeyID)
	require.Equal(t, []string{e.roles["product_a"].Role, e.roles["product_b"].Role}, b.Agents)
	require.Equal(t, e.roles["product_a"].Role, b.RequestedBy)
	require.Equal(t, p.ManifestSHA256, b.ManifestSHA256)
	require.Equal(t, []passkey.Bytes{e.pk.ID}, req.CredentialIDs)
	require.Equal(t, 1, e.ledgerKind("product_a", string(guard.PluginApprovalPending)))

	require.Contains(t, res.PersonMessage, "product_a asks you to approve the plugin acme-ner 0.3.1.")
	require.Contains(t, res.PersonMessage, levelUnknownHere)
	require.Contains(t, res.PersonMessage, "Approve it with your passkey only if you know who made it:\n"+a.URL+"\n")
	require.Equal(t, []mcp.Link{{Label: "Approve the plugin acme-ner", URL: a.URL}}, res.Links)
	// No restart: the running engine starts the plugin once it is signed.
	require.Equal(t, []string{"PERSON OPEN_LINK", "PERSON TELL_AGENT", "AGENT END_TURN"}, stepKinds(res.NextSteps))
	require.Contains(t, res.PersonMessage, "The plugin starts within seconds of your approval.")
	require.NotContains(t, res.PersonMessage, "restart")
	require.NotContains(t, r.stderr, "basalt engine --config", "no restart command")
}

// TestAddOnAgentOperatedEngine: on an engine an agent operates the link is
// on the portal, and no step restarts the engine.
func TestAddOnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "AGENT")
	r := e.run(nil, "", "add", e.unsigned, "--agents", "product_a", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	res := approvalResultOf(t, r)
	require.True(t, strings.HasPrefix(res.Approvals[0].URL, links.Portal+"/plugins/"+res.Approvals[0].ApprovalID+"#"), res.Approvals[0].URL)
	require.Equal(t, []string{"PERSON OPEN_LINK", "PERSON TELL_AGENT", "AGENT END_TURN"}, stepKinds(res.NextSteps))
	require.Equal(t, config.PluginApprovalRequired, e.config().Plugins[0].Approval)
}

// TestOneApprovalPerDatabase: agents on two databases get one approval and
// one link each, each naming only its own database's agents.
func TestOneApprovalPerDatabase(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a,client_x,product_b", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	res := approvalResultOf(t, r)
	require.Len(t, res.Approvals, 2)
	require.Equal(t, []string{"product_a", "product_b"}, res.Approvals[0].Agents)
	require.Equal(t, []string{"client_x"}, res.Approvals[1].Agents)
	require.Equal(t, dbName(t, e.other), res.Approvals[1].Database.Name)
	_, b := requestOf(t, res.Approvals[1].URL)
	require.Equal(t, []string{e.roles["client_x"].Role}, b.Agents)
	require.Len(t, res.Links, 2)
	require.Contains(t, res.Links[1].Label, labelText(dbName(t, e.other)))
	require.Contains(t, res.PersonMessage, "no passkey is registered for database "+dbName(t, e.other), "nobody can sign there yet")
	require.Equal(t, "PERSON RUN_COMMAND", stepKinds(res.NextSteps)[0], "registering a passkey comes first")
	require.Equal(t, 1, e.ledgerKind("client_x", string(guard.PluginApprovalPending)))
}

// TestPluginApproveRelaysCode: the code the page shows, pasted to the
// agent, is relayed with the opener's credential; Postgres records
// PLUGIN_APPROVED for every agent the approval names.
func TestPluginApproveRelaysCode(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	res := approvalResultOf(t, e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a,product_b", "--json"))
	req, _ := requestOf(t, res.Approvals[0].URL)

	forged, err := e.pk.Sign(approval.Challenge(req.Binding+" "), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	bad, err := approval.NewPluginApprovalResponse(req.ApprovalID, forged).Code()
	require.NoError(t, err)
	r := e.run(agentEnv, "", "approve", bad)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "does not verify")
	require.Zero(t, e.ledgerKind("product_a", string(guard.PluginApproved)))

	r = e.run(agentEnv, "", "approve", e.sign(req), "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out approvedJSON
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, req.ApprovalID.String(), out.ApprovalID)
	require.Equal(t, "APPROVED", out.Status)
	for _, name := range []string{"product_a", "product_b"} {
		require.Equal(t, 1, e.ledgerKind(name, string(guard.PluginApproved)), name)
	}
	r = e.run(agentEnv, "", "approve", e.sign(req))
	require.Equal(t, exitError, r.code, "signed once")
	require.Contains(t, r.stderr, guard.DetailAlreadyApproved)
	r = e.run(nil, "", "approve", "basalt-approval.1.e30")
	require.Equal(t, exitUsage, r.code)
}

// TestEnableAfterDisableOpensApproval: turning the entry off and on again
// opens a new approval, even for the same copy, agents and settings.
func TestEnableAfterDisableOpensApproval(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	res := approvalResultOf(t, e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a", "--json"))
	req, _ := requestOf(t, res.Approvals[0].URL)
	require.Equal(t, exitOK, e.run(agentEnv, "", "approve", e.sign(req)).code)

	require.Equal(t, exitOK, e.run(agentEnv, "", "disable", "acme-ner").code)
	require.False(t, e.config().Plugins[0].Enabled)
	require.Equal(t, config.PluginApprovalRequired, e.config().Plugins[0].Approval, "disable keeps the key")

	r := e.run(agentEnv, "", "enable", "acme-ner", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	again := approvalResultOf(t, r)
	require.NotEqual(t, res.Approvals[0].ApprovalID, again.Approvals[0].ApprovalID, "a new approval")
	_, b := requestOf(t, again.Approvals[0].URL)
	require.JSONEq(t, `{}`, string(b.Change), "the same entry turned on again")
	require.Contains(t, again.PersonMessage, "asks you to approve a change to the plugin acme-ner 0.3.1.")
	require.True(t, e.config().Plugins[0].Enabled)

	// enable always opens a new one, also on an enabled entry.
	r = e.run(agentEnv, "", "enable", "acme-ner", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotEqual(t, again.Approvals[0].ApprovalID, approvalResultOf(t, r).Approvals[0].ApprovalID)
}

// TestListShowsApprovalStatus: list shows, per listed agent, the state of
// the newest approval of an entry that requires one, and NOT_REQUIRED for
// one that does not; an agent whose database cannot be read is UNAVAILABLE.
func TestListShowsApprovalStatus(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	res := approvalResultOf(t, e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a", "--json"))
	e.person("add", e.src, "--agents", "product_b", "--instance", "terminal")

	list := func() map[string]listedEntry {
		t.Helper()
		r := e.run(nil, "", "list", "--json")
		require.Equal(t, exitOK, r.code, r.stderr)
		var out struct {
			Plugins []listedEntry `json:"plugins"`
		}
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
		m := map[string]listedEntry{}
		for _, p := range out.Plugins {
			m[p.Instance] = p
		}
		return m
	}
	got := list()
	pending := got["default"].Approval
	require.True(t, pending.Required)
	require.Equal(t, statePending, pending.Agents[0].State)
	require.Equal(t, res.Approvals[0].ApprovalID, pending.Agents[0].ApprovalID)
	require.NotEmpty(t, pending.Agents[0].ExpiresAt)
	require.False(t, got["terminal"].Approval.Required)
	require.Equal(t, stateNotRequired, got["terminal"].Approval.Agents[0].State)

	req, _ := requestOf(t, res.Approvals[0].URL)
	require.Equal(t, exitOK, e.run(agentEnv, "", "approve", e.sign(req)).code)
	require.Equal(t, stateApproved, list()["default"].Approval.Agents[0].State)
	text := e.run(nil, "", "list")
	require.Contains(t, text.stdout, "approval product_a APPROVED")

	// The person's entry made to require approval: none names product_b.
	require.NoError(t, config.UpdateConfig(e.configPath, config.Change{Apply: func(c *config.Config) error {
		c.Plugins[1].Approval = config.PluginApprovalRequired
		return nil
	}}))
	require.Equal(t, stateNone, list()["terminal"].Approval.Agents[0].State)

	// product_b's credential cannot be read: UNAVAILABLE, not a failure.
	require.NoError(t, os.WriteFile(filepath.Join(e.base, "creds", "product_b.url"), []byte("postgres://nobody@127.0.0.1:1/x\n"), 0o600))
	require.Equal(t, stateUnavailable, list()["terminal"].Approval.Agents[0].State)
}

// TestPersonAtTerminalUnchanged: a person at a terminal without the flag
// gets the consent screen and the entry as today, with no approval key and
// no database read (the agents' credential files do not exist); with
// --approve-with-passkey they get the approval flow, as an agent does.
func TestPersonAtTerminalUnchanged(t *testing.T) {
	t.Parallel()
	t.Run("without the flag", func(t *testing.T) {
		t.Parallel()
		e := newPluginEngine(t)
		r := e.person("add", e.src, "--agents", "product_a")
		require.Contains(t, r.stderr, "[y/N]")
		require.Contains(t, r.stderr, "added, disabled")
		p := e.config().Plugins[0]
		require.False(t, p.Enabled)
		require.Empty(t, p.Approval)
		raw, err := os.ReadFile(e.configPath)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "approval")
		r = e.person("enable", "acme-ner")
		require.Contains(t, r.stderr, "plugin acme-ner/default enabled")
		require.Empty(t, e.config().Plugins[0].Approval)
	})
	t.Run("with --approve-with-passkey", func(t *testing.T) {
		t.Parallel()
		e := newApprovalEngine(t, "")
		r := e.run(nil, "", "add", e.unsigned, "--agents", "product_a", "--approve-with-passkey", "--json")
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "[y/N]")
		res := approvalResultOf(t, r)
		require.NotEmpty(t, res.Approvals[0].ApprovalID)
		require.Equal(t, config.PluginApprovalRequired, e.config().Plugins[0].Approval)
		// The key stays: the person's later enable takes the flow without the flag.
		r = e.run(nil, "", "enable", "acme-ner", "--json")
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotEqual(t, res.Approvals[0].ApprovalID, approvalResultOf(t, r).Approvals[0].ApprovalID)
	})
}

// TestTrustStillRefused: an agent never adds a trust root, under a marker
// or on an agent-operated engine.
func TestTrustStillRefused(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		env        map[string]string
		operatedBy string
	}{"marker": {env: agentEnv}, "operatedBy AGENT": {operatedBy: "AGENT"}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newPluginEngine(t)
			e.writeConfig(tc.operatedBy)
			k, err := plugin.GenerateKey()
			require.NoError(t, err)
			pub, err := plugin.MarshalPublicKey(&k.PublicKey)
			require.NoError(t, err)
			file := filepath.Join(t.TempDir(), "publisher.pub")
			require.NoError(t, os.WriteFile(file, pub, 0o644))
			before := e.snapshot()
			refusal(t, e.run(tc.env, "y\n", "trust", file, "--json"), reasonAgentOperated)
			require.Equal(t, before, e.snapshot())
		})
	}
}

// TestAddInServiceModeStillRefused: in service mode an agent's add and
// enable are refused as before, and the flag and approve are usage errors.
func TestAddInServiceModeStillRefused(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	e.mode = "SERVICE"
	e.writeConfig("")
	refusal(t, e.run(agentEnv, "y\n", "add", e.src, "--agents", "product_a", "--json"), reasonAgentOperated)
	refusal(t, e.run(agentEnv, "y\n", "enable", "acme-ner", "--json"), reasonAgentOperated)
	require.Equal(t, exitUsage, e.run(nil, "", "add", e.src, "--agents", "product_a", "--approve-with-passkey").code)
	require.Equal(t, exitUsage, e.run(nil, "", "enable", "acme-ner", "--approve-with-passkey").code)
	require.Equal(t, exitUsage, e.run(agentEnv, "", "approve", "basalt-plugin.1.e30").code)
	require.Empty(t, e.config().Plugins)
}

// TestRefusedDatabaseUnreachable: a listed agent whose database does not
// answer refuses before anything is written.
func TestRefusedDatabaseUnreachable(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	before := e.snapshot()
	body := refusal(t, e.run(agentEnv, "", "add", e.src, "--agents", "product_a", "--json"), reasonDatabaseUnreachable)
	require.Contains(t, body.Message, "Nothing was written")
	require.Contains(t, body.NextSteps[1].Command, "--approve-with-passkey --json")
	require.Equal(t, before, e.snapshot(), "nothing written")
}

// TestRefusedTooManyPending: a database that already holds 8 pending
// approvals refuses the open after the entry is written: the result names
// the reason, the entry stays written, and the command exits 1.
func TestRefusedTooManyPending(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	for i := range 8 {
		d := guard.PluginApprovalDetail{
			Agents: []string{e.roles["product_b"].Role}, Name: fmt.Sprintf("other-%d", i), Instance: "default", Version: "1.0.0",
			ManifestSHA256: strings.Repeat("ab", 32), Hooks: []string{"feed.observe"}, Egress: []string{},
			Endpoint:  guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
			Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
			Signer:    guard.PluginSignerUnknown,
		}
		_, err := guard.OpenPluginApproval(context.Background(), e.roles["product_b"].Conn, d, guard.PluginSettings{})
		require.NoError(t, err)
	}
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a,client_x", "--json")
	require.Equal(t, exitError, r.code, r.stderr)
	res := approvalResultOf(t, r)
	require.NotNil(t, res.Approvals[0].Refused)
	require.Equal(t, reasonTooManyPending, res.Approvals[0].Refused.Reason)
	require.Nil(t, res.Approvals[1].Refused, "the other database opened its approval")
	require.Contains(t, stepKinds(res.NextSteps), "AGENT STOP")
	require.Len(t, e.config().Plugins, 1, "the entry stays written, withheld")
}

// TestRefusedGuardOutdated: a guard older than schema version 5 refuses
// before anything is written. Not parallel: it installs an older guard.
func TestRefusedGuardOutdated(t *testing.T) {
	restore := guardtest.UpToVersion(t, guard.PluginApprovalsVersion-1)
	d := guardtest.New(t).WithDemo(t)
	e := newApprovalEngineOn(t, d, nil, "")
	restore()
	before := e.snapshot()
	body := refusal(t, e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a", "--json"), reasonGuardOutdated)
	require.Contains(t, body.NextSteps[0].Command, "basalt upgrade")
	require.Equal(t, before, e.snapshot())

	e.writeConfig("AGENT")
	body = refusal(t, e.run(nil, "", "add", e.unsigned, "--agents", "product_a", "--json"), reasonGuardOutdated)
	require.Equal(t, mcp.ActorAgent, body.NextSteps[0].Actor, "the agent makes an UPGRADE setup code")
	require.Contains(t, body.NextSteps[0].Command, "basalt init --remote")
}

// TestPersonMessageCarriesThePageWarning: the level lines personMessage
// carries are the page's, word for word.
func TestPersonMessageCarriesThePageWarning(t *testing.T) {
	t.Parallel()
	page, err := os.ReadFile("../../web/lib/plugin.js")
	require.NoError(t, err)
	contract, err := os.ReadFile("../../CONTRACT.md")
	require.NoError(t, err)
	for _, line := range []string{levelKnown, levelUnknown, levelUnknownHere} {
		require.Contains(t, string(page), line)
		require.Contains(t, string(contract), line)
	}
}

// TestAddHandsOverShortLink: when the engine serves the local pages the
// link is a short link the engine issued for proof of the binding text.
func TestAddHandsOverShortLink(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.host.pagesUp = true
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	res := approvalResultOf(t, r)
	id := res.Approvals[0].ApprovalID
	require.Equal(t, links.DefaultLocal+"/plugins/"+id+"#s="+fakeSecret, res.Approvals[0].URL)
	require.Len(t, e.host.issued, 1)
	require.Equal(t, links.DefaultLocal+"/api/v1/plugins/"+id+"/links", e.host.issued[0].endpoint)
	rec, ok, err := guard.ReadPluginApproval(context.Background(), e.roles["product_a"].Conn, uuid.MustParse(id))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, links.IssueProof(rec.BindingText), e.host.issued[0].proof)
}

// TestHashLinkWithoutPasskeyFits: over the link budget the link is a hash
// link with its request file, and the person's message stays within its
// limit with the level 3 warning and a database that has no passkey: the
// command never fails after the entry is written.
func TestHashLinkWithoutPasskeyFits(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	budget := 200
	require.NoError(t, config.UpdateConfig(e.configPath, config.Change{Apply: func(c *config.Config) error {
		c.LinkBudget = &budget
		return nil
	}}))
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "client_x,product_a", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	res := approvalResultOf(t, r)
	require.Len(t, res.Approvals, 2)
	for _, a := range res.Approvals {
		require.NotNil(t, a.RequestFile, "a hash link carries its request file")
		require.Contains(t, a.URL, "#h=")
	}
	require.Contains(t, res.PersonMessage, levelUnknownHere)
	require.NoError(t, agent.CheckPersonMessage(res.PersonMessage))
	require.Contains(t, stepKinds(res.NextSteps), "AGENT SEND_REQUEST")
}

// TestOneDatabaseTwoSpellings: two agents whose credentials name the same
// database by different host spellings get one approval, not two that
// cancel each other.
func TestOneDatabaseTwoSpellings(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	url := e.roles["product_b"].URL
	// The same server under the other name of the loopback address.
	respelled := strings.Replace(url, "@127.0.0.1:", "@localhost:", 1)
	if respelled == url {
		respelled = strings.Replace(url, "@localhost:", "@127.0.0.1:", 1)
	}
	require.NotEqual(t, url, respelled, "the test database is on the loopback address")
	require.NoError(t, os.WriteFile(filepath.Join(e.base, "creds", "product_b.url"), []byte(respelled+"\n"), 0o600))
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a,product_b", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	res := approvalResultOf(t, r)
	require.Len(t, res.Approvals, 1)
	require.Equal(t, []string{"product_a", "product_b"}, res.Approvals[0].Agents)
	_, b := requestOf(t, res.Approvals[0].URL)
	require.Equal(t, []string{e.roles["product_a"].Role, e.roles["product_b"].Role}, b.Agents)
}
