package guard_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// lineChangeIDs is every change id the lines name.
func lineChangeIDs(t *testing.T, lines []string) []uuid.UUID {
	t.Helper()
	out := make([]uuid.UUID, 0, len(lines))
	for _, l := range lines {
		var line struct {
			ChangeIDs []uuid.UUID `json:"changeIds"`
		}
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		out = append(out, line.ChangeIDs...)
	}
	return out
}

// requireChangeAgents checks the catalog's map against the ledger: each
// entry is the change's own agent, the agents' change counts match the
// catalog's, and every change id the lines name is in it.
func requireChangeAgents(t *testing.T, d *guardtest.DB, out action.RescopedRevert, want map[string]int) {
	t.Helper()
	require.NotNil(t, out.Catalog)
	got := map[string]int{}
	for id, agent := range out.Catalog.ChangeAgents {
		require.Equal(t, scalarOf[string](t, d.Admin, `SELECT agent::text FROM basalt_meta.changes WHERE change_id = $1`, id), agent, "change %s", id)
		got[agent]++
	}
	require.Equal(t, want, got)
	for _, id := range lineChangeIDs(t, out.Lines) {
		require.Contains(t, out.Catalog.ChangeAgents, id, "every change a line names has its agent")
	}
}

// Q-11: the catalog maps each change in the ceiling to its agent, on a
// proven widen and on a narrow under its token. The map follows the
// ceiling, so a narrow keeps it whole.
func TestRescopeCatalogChangeAgents(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()

	wide := e.widen(t, e.every())
	requireChangeAgents(t, e.d, wide, map[string]int{e.bot.Role: 3, e.helper.Role: 2})
	require.Len(t, lineChangeIDs(t, wide.Lines), 5)

	helperOnly := revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Role}}
	narrow, err := guard.RescopeRevert(ctx, e.bot.Conn,
		action.RescopeRequest{RevertID: e.prep.RevertID, Select: helperOnly, Token: []byte(wide.ScopeToken)})
	require.NoError(t, err)
	requireChangeAgents(t, e.d, narrow, map[string]int{e.bot.Role: 3, e.helper.Role: 2})
	require.Equal(t, wide.Catalog.ChangeAgents, narrow.Catalog.ChangeAgents)
}

// The requesting agent never learns which agent made which change: an
// own-work rescope, a refused widen and a reset return no catalog, and the
// role cannot call the catalog function or read the map from a view.
func TestChangeAgentsNeverReachTheAgent(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID

	own, err := guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: e.own()})
	require.NoError(t, err)
	require.Nil(t, own.Catalog, "an unproven own-work rescope gets no map")

	_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: e.every()})
	requireWidenRefused(t, err)
	as, _ := e.proof(t, id, e.every(), "the page's new secret")
	other, err := revert.RescopeKey([]byte("another secret"))
	require.NoError(t, err)
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: e.every(), Proof: &as, RescopeKey: other})
	requireWidenRefused(t, err)

	wide := e.widen(t, e.every())
	require.NotEmpty(t, wide.Catalog.ChangeAgents)
	reset, err := guard.ResetRevert(ctx, e.bot.Conn, id)
	require.NoError(t, err)
	require.Nil(t, reset.Catalog, "a reset returns no map")

	ceiling := json.RawMessage(`{"scope":"TASK","scopeId":"` + e.task.String() + `","agents":null,"runs":null,"tables":null}`)
	_, err = e.bot.Conn.Exec(ctx, `SELECT basalt_meta._revert_catalog($1::jsonb)`, string(ceiling))
	require.Equal(t, "42501", guardtest.SQLState(err), "the agent role cannot call the catalog function")

	for _, view := range []string{"basalt_meta.agent_reverts", "basalt_meta.agent_revert_lines"} {
		var text string
		require.NoError(t, e.bot.Conn.QueryRow(ctx, `SELECT coalesce(string_agg(v::text, ''), '') FROM `+view+` v`).Scan(&text))
		require.NotContains(t, text, "changeAgents", view)
	}
}
