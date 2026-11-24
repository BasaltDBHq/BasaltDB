package guard

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The revoke of an existing role's unpicked grants names the picked tables
// as literals of quoted identifiers, revokes only the kinds the setup
// grants, and renders every format verb.
func TestAgentExactStatementRendersThePicks(t *testing.T) {
	t.Parallel()
	st, err := agentExactStatement("bt_agent_bot", guardmodel.AgentSpec{
		Write: []string{"public.orders"}, Read: []string{"sales.notes", "logs"},
	})
	require.NoError(t, err)
	require.Contains(t, st.SQL, `v_write oid[] := ARRAY['"public"."orders"']::text[]`)
	require.Contains(t, st.SQL, `v_read  oid[] := ARRAY['"sales"."notes"', '"public"."logs"']::text[]`)
	require.Contains(t, st.SQL, `('SELECT', 'INSERT', 'UPDATE', 'DELETE')`)
	require.Contains(t, st.SQL, `IN ('USAGE', 'SELECT')`)
	require.Contains(t, st.SQL, `NOT LIKE 'pg\_%'`)
	require.Contains(t, st.SQL, `'REVOKE %s ON %s %s FROM %I'`)
	require.NotContains(t, st.SQL, "%!", "every verb is rendered")
	require.NotContains(t, st.SQL, "REVOKE ALL")

	none, err := agentExactStatement("bt_agent_bot", guardmodel.AgentSpec{})
	require.NoError(t, err)
	require.Contains(t, none.SQL, "ARRAY[]::text[]", "no picks revoke every setup grant")

	_, err = agentExactStatement("bt_agent_bot", guardmodel.AgentSpec{Read: []string{"a.b.c"}})
	require.ErrorIs(t, err, guardmodel.ErrInvalidAgent)
	require.False(t, strings.Contains(none.SQL, "{{"), "no template left")
}
