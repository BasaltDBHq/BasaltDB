//go:build unix

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The tests here hold one rule of CONTRACT.md, Plugin approval: turning an
// entry off and on again with the commands always needs a new signature,
// even when both happen between two engine starts.

// fillPending leaves 8 pending plugin approvals in e's first database, so
// the next open there is refused TOO_MANY_PENDING.
func (e *approvalEngine) fillPending() {
	e.t.Helper()
	for i := range 8 {
		d := guard.PluginApprovalDetail{
			Agents: []string{e.roles["product_b"].Role}, Name: fmt.Sprintf("other-%d", i), Instance: "default", Version: "1.0.0",
			ManifestSHA256: strings.Repeat("ab", 32), Hooks: []string{"feed.observe"}, Egress: []string{},
			Endpoint:  guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
			Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
			Signer:    guard.PluginSignerUnknown,
		}
		_, err := guard.OpenPluginApproval(context.Background(), e.roles["product_b"].Conn, d, guard.PluginSettings{})
		require.NoError(e.t, err)
	}
}

// approvalState is the state basalt plugin list shows for agentName's
// approval of the default instance of acme-ner.
func (e *approvalEngine) approvalState(agentName string) string {
	e.t.Helper()
	r := e.run(nil, "", "list", "--json")
	require.Equal(e.t, exitOK, r.code, r.stderr)
	var out struct {
		Plugins []listedEntry `json:"plugins"`
	}
	require.NoError(e.t, json.Unmarshal([]byte(r.stdout), &out))
	for _, p := range out.Plugins {
		for _, a := range p.Approval.Agents {
			if p.Name == "acme-ner" && a.Agent == agentName {
				return a.State
			}
		}
	}
	e.t.Fatalf("no approval of %s listed", agentName)
	return ""
}

// signedApproval adds the entry for agents as an agent does and signs the
// approval, as a person does.
func (e *approvalEngine) signedApproval(agents string) {
	e.t.Helper()
	res := approvalResultOf(e.t, e.run(agentEnv, "", "add", e.unsigned, "--agents", agents, "--json"))
	req, _ := requestOf(e.t, res.Approvals[0].URL)
	require.Equal(e.t, exitOK, e.run(agentEnv, "", "approve", e.sign(req)).code)
	require.Equal(e.t, stateApproved, e.approvalState("product_a"))
}

// setEnabled flips the entry in engine.json as a hand edit would, without a
// command, so no approval end is written for it.
func (e *approvalEngine) setEnabled(on bool) {
	e.t.Helper()
	require.NoError(e.t, config.UpdateConfig(e.configPath, config.Change{Apply: func(c *config.Config) error {
		c.Plugins[0].Enabled = on
		return nil
	}}))
}

// TestEnableAfterDisableNeverRevivesTheOldApproval: with the product's own
// commands only, turning a plugin off and on again never serves it on its
// old signature, even when the database refuses the new approval (8 wait)
// and the engine never ran in between.
func TestEnableAfterDisableNeverRevivesTheOldApproval(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a")

	require.Equal(t, exitOK, e.run(agentEnv, "", "disable", "acme-ner").code)
	e.fillPending()
	r := e.run(agentEnv, "", "enable", "acme-ner", "--json")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Equal(t, reasonTooManyPending, approvalResultOf(t, r).Approvals[0].Refused.Reason)
	require.True(t, e.config().Plugins[0].Enabled)
	require.Equal(t, stateEnded, e.approvalState("product_a"), "the old signature is over; the new approval was never opened")
}

// TestEnableEndsTheApprovalADisableLeftOwed: a disable that never wrote the
// end (the entry was turned off by a hand edit, or its database did not
// answer) leaves the end owed, and the next enable writes it before the
// entry is written, whether or not the new approval can be opened.
func TestEnableEndsTheApprovalADisableLeftOwed(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a")
	e.setEnabled(false)
	require.Equal(t, stateApproved, e.approvalState("product_a"))

	e.fillPending()
	r := e.run(agentEnv, "", "enable", "acme-ner", "--json")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Equal(t, stateEnded, e.approvalState("product_a"))
}

// TestAddNeverRevivesTheOldApprovalOfARemovedAgent: an agent taken off the
// entry and added again is served on a new signature only.
func TestAddNeverRevivesTheOldApprovalOfARemovedAgent(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a,product_b")
	require.Equal(t, stateApproved, e.approvalState("product_b"))
	r := e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a")
	require.Equal(t, exitOK, r.code, "narrowing needs no approval: "+r.stderr)
	require.Equal(t, []string{"product_a"}, e.config().Plugins[0].Agents)

	e.fillPending()
	r = e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a,product_b", "--json")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Equal(t, []string{"product_a", "product_b"}, e.config().Plugins[0].Agents)
	require.Equal(t, stateEnded, e.approvalState("product_b"), "the old signature does not come back")
	require.Equal(t, stateApproved, e.approvalState("product_a"), "an agent that stayed keeps its approval")
}

// TestAddOfARemovedEntryNeverRevivesItsApproval: removing the entry and
// adding it again is the same.
func TestAddOfARemovedEntryNeverRevivesItsApproval(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a")
	cred := filepath.Join(e.base, "creds", "product_a.url")
	good, err := os.ReadFile(cred)
	require.NoError(t, err)
	// The database does not answer when the entry is removed: the end is
	// owed, and the removal still happens.
	require.NoError(t, os.WriteFile(cred, []byte("postgres://nobody@127.0.0.1:1/x\n"), 0o600))
	r := e.run(agentEnv, "", "remove", "acme-ner")
	require.Equal(t, exitOK, r.code, "turning off is never blocked: "+r.stderr)
	require.Empty(t, e.config().Plugins)
	require.NoError(t, os.WriteFile(cred, good, 0o600))

	e.fillPending()
	r = e.run(agentEnv, "", "add", e.unsigned, "--agents", "product_a", "--json")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Equal(t, stateEnded, e.approvalState("product_a"))
}

// TestDisableAndRemoveEndTheApproval: when the database answers, disable
// and remove write the end themselves.
func TestDisableAndRemoveEndTheApproval(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a")
	require.Equal(t, exitOK, e.run(agentEnv, "", "disable", "acme-ner").code)
	require.Equal(t, stateEnded, e.approvalState("product_a"))

	e = newApprovalEngine(t, "")
	e.signedApproval("product_a")
	require.Equal(t, exitOK, e.run(agentEnv, "", "remove", "acme-ner").code)
	recs, err := guard.ReadPluginApprovals(context.Background(), e.roles["product_a"].Conn)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.True(t, recs[0].Ended(), "the removal ended the signed approval")
}

// TestDisableStillTurnsOffWithoutTheDatabase: turning off is never blocked
// by a database that does not answer.
func TestDisableStillTurnsOffWithoutTheDatabase(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a")
	cred := filepath.Join(e.base, "creds", "product_a.url")
	good, err := os.ReadFile(cred)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cred, []byte("postgres://nobody@127.0.0.1:1/x\n"), 0o600))
	r := e.run(agentEnv, "", "disable", "acme-ner")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.False(t, e.config().Plugins[0].Enabled)
	require.NoError(t, os.WriteFile(cred, good, 0o600))
	require.Equal(t, stateApproved, e.approvalState("product_a"), "the end is owed")

	e.fillPending()
	require.Equal(t, exitError, e.run(agentEnv, "", "enable", "acme-ner", "--json").code)
	require.Equal(t, stateEnded, e.approvalState("product_a"), "the next enable writes it")
}

// TestEnableRefusedWhenTheEndCannotBeWritten: an end that cannot be written
// refuses enable and add with DATABASE_UNREACHABLE and writes nothing.
func TestEnableRefusedWhenTheEndCannotBeWritten(t *testing.T) {
	t.Parallel()
	e := newApprovalEngine(t, "")
	e.signedApproval("product_a")
	e.setEnabled(false)
	// The database answers, but the agent can no longer record events.
	_, err := e.db.Admin.Exec(context.Background(), `
DO $$ DECLARE r name; BEGIN
  FOR r IN SELECT pg_catalog.pg_get_userbyid(x.grantee) FROM (SELECT (pg_catalog.aclexplode(proacl)).grantee AS grantee FROM pg_catalog.pg_proc
           WHERE oid = 'basalt_meta.record_plugin_event(text, jsonb)'::regprocedure) x WHERE x.grantee <> 0 LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION basalt_meta.record_plugin_event(text, jsonb) FROM %I', r);
  END LOOP;
END $$`)
	require.NoError(t, err)
	before := e.snapshot()
	for _, args := range [][]string{
		{"enable", "acme-ner", "--json"},
		{"add", e.unsigned, "--agents", "product_a", "--json"},
	} {
		body := refusal(t, e.run(agentEnv, "", args...), reasonDatabaseUnreachable)
		require.Contains(t, body.Message, "Nothing was written")
		require.Equal(t, before, e.snapshot(), "nothing written")
	}
	require.False(t, e.config().Plugins[0].Enabled)
}
