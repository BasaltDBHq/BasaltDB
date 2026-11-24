package setupcode_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

func TestSummaryWords(t *testing.T) {
	t.Parallel()
	p := validPayload(t) // INSTALL through the Supabase pooler: write public.leads, read public.companies
	lines := setupcode.Summary(p, setupcode.SummaryState{})
	require.Equal(t, []string{
		"This creates the agent lead_bot (role basalt_agent_lead_bot). Its password comes from the code: only whoever made this code can log in as basalt_agent_lead_bot.",
		"Prefix basalt, statement timeout 30000 ms, at most 8 connections.",
		"Setup fingerprint: " + p.Fingerprint() + ". Check that lead_bot shows the same fingerprint.",
		"lead_bot will be able to read public.companies and change rows in public.leads, up to 10 rows at a time without asking you, " +
			"11 to 50 with your passkey, never more. It cannot change your tables' structure.",
	}, lines)

	// Outside public: flagged; Supabase's own schemas more strongly.
	p.Agent.Write = []string{"public.leads", "crm.deals", "auth.users"}
	shown := strings.Join(setupcode.Summary(p, setupcode.SummaryState{}), "\n")
	require.Contains(t, shown, "change rows in public.leads, crm.deals and auth.users,")
	require.Contains(t, shown, "Note: crm.deals is not in schema public")
	require.Contains(t, shown, "Warning: auth.users is in Supabase's own auth schema")
	require.NotContains(t, shown, "Note: auth.users")

	// Without Supabase, auth is only another schema.
	p.Target.SupabaseRef = ""
	shown = strings.Join(setupcode.Summary(p, setupcode.SummaryState{}), "\n")
	require.Contains(t, shown, "Note: auth.users is not in schema public")

	// An AGENT code that keeps the password and changes the timeout.
	p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
	p.Agent.Write, p.Agent.Read = nil, []string{"public.companies"}
	lines = setupcode.Summary(p, setupcode.SummaryState{TimeoutNow: "15000 ms"})
	require.Equal(t, "This changes the tables of the existing agent lead_bot (role basalt_agent_lead_bot); its password stays.", lines[0])
	require.Equal(t, "Prefix basalt, statement timeout 30000 ms (now 15000 ms), at most 8 connections.", lines[1])
	require.Equal(t, "lead_bot will be able to read public.companies. It cannot change their rows. It cannot change your tables' structure.", lines[3])
}
