package setupcode_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// An AGENT code that names no tables keeps the role's grants: it encodes
// with write and read as empty lists, decodes, and says so. An INSTALL code
// still needs a table or agent.allTables.
func TestAgentCodeWithNoTablesKeepsTheGrants(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
	p.Agent.Write, p.Agent.Read = nil, nil
	require.True(t, p.KeepsGrants())

	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	got, err := setupcode.Decode(code)
	require.NoError(t, err)
	require.True(t, got.KeepsGrants())
	raw, err := json.Marshal(got.Agent)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"write":[],"read":[]`, "both lists are present and empty")

	lines := setupcode.Summary(got, setupcode.SummaryState{})
	require.Equal(t, "This changes nothing for the existing agent lead_bot (role basalt_agent_lead_bot): its password and its tables stay.", lines[0])
	require.Equal(t, "lead_bot keeps the tables it can use now: this setup grants and revokes none.", lines[len(lines)-1])

	// With a verifier it rotates the password, and still keeps the grants.
	withVerifier := validPayload(t)
	withVerifier.Kind = setupcode.KindAgent
	withVerifier.Agent.Write, withVerifier.Agent.Read = []string{}, []string{}
	require.True(t, withVerifier.KeepsGrants())
	_, err = setupcode.Encode(withVerifier)
	require.NoError(t, err)
	lines = setupcode.Summary(withVerifier, setupcode.SummaryState{})
	require.Contains(t, lines[0], "This replaces the password of the existing agent lead_bot")
	require.Equal(t, "lead_bot keeps the tables it can use now: this setup grants and revokes none.", lines[len(lines)-1])

	// The role is gone: it runs as an INSTALL and the person ticks tables
	// in schema public, never every one of them unasked.
	lines = setupcode.Summary(withVerifier, setupcode.SummaryState{RunsAsInstall: true, Tables: []string{"public.leads"}, ReadOnly: []string{}})
	require.Contains(t, lines[0], "This creates the agent lead_bot")
	require.Contains(t, lines[len(lines)-1], "change rows in public.leads")

	install := validPayload(t)
	install.Agent.Write, install.Agent.Read = nil, nil
	require.False(t, install.KeepsGrants())
	_, err = setupcode.Encode(install)
	require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err), "an INSTALL code needs a table")

	all := validPayload(t)
	all.Kind, all.Agent.Write, all.Agent.Read = setupcode.KindAgent, nil, nil
	all.Agent.AllTables = &setupcode.AllTables{Schemas: []string{"public"}}
	require.False(t, all.KeepsGrants(), "agent.allTables names its tables")
}
