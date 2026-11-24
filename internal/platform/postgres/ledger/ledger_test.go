package ledger_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

var leads = []string{"public.leads"}

func newRun(t *testing.T, a *guardtest.Agent, text string) guard.Intent {
	t.Helper()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: text}
	require.NoError(t, guard.StartRun(context.Background(), a.Conn, in))
	return in
}

func writes(t *testing.T, a *guardtest.Agent, in guard.Intent, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in,
			fmt.Sprintf(`UPDATE public.leads SET score = score + 1 WHERE id = %d`, i)))
	}
}

func list(t *testing.T, a *guardtest.Agent, p action.ChangeListParams) pagination.Page[action.Change] {
	t.Helper()
	page, err := ledger.ListChanges(context.Background(), a.Conn, p)
	require.NoError(t, err)
	return page
}

func TestListChangesPaginates(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	writes(t, a, newRun(t, a, "page"), 1, 25)

	seen := make([]uuid.UUID, 0, 25)
	p := action.ChangeListParams{Params: pagination.Params{Limit: 10}}
	for _, want := range []int{10, 10, 5} {
		page := list(t, a, p)
		require.Len(t, page.Items, want)
		for _, c := range page.Items {
			seen = append(seen, c.ID)
		}
		p.Cursor = page.NextCursor
	}
	require.Empty(t, p.Cursor, "no cursor on the last page")
	require.Len(t, seen, 25)
	for i := 1; i < len(seen); i++ {
		require.Greater(t, seen[i-1].String(), seen[i].String(), "newest first")
	}

	asc := list(t, a, action.ChangeListParams{Params: pagination.Params{Limit: 200, Sort: "id"}})
	require.Len(t, asc.Items, 25)
	require.Equal(t, seen[24], asc.Items[0].ID)
	first := asc.Items[0]
	require.Equal(t, "APPLIED", first.Status)
	require.Equal(t, 1, first.Rows)
	require.Equal(t, "public.leads", first.Table)
	require.Equal(t, "UPDATE public.leads SET score = score + 1 WHERE id = 1", first.Statement)

	ctx := context.Background()
	for _, bad := range []action.ChangeListParams{
		{Params: pagination.Params{Limit: 0}},
		{Params: pagination.Params{Limit: pagination.MaxLimit + 1}},
		{Params: pagination.Params{Limit: 10, Sort: "-at"}},
		{Params: pagination.Params{Limit: 10, Cursor: "!!"}},
	} {
		_, err := ledger.ListChanges(ctx, a.Conn, bad)
		require.ErrorIs(t, err, ledger.ErrInvalidParams)
	}
}

func TestListChangesFiltersRunAndAgent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	b := d.NewAgent(t, "other", leads, nil)
	one, two := newRun(t, a, "one"), newRun(t, a, "two")
	writes(t, a, one, 1, 2)
	writes(t, a, two, 3, 3)
	writes(t, b, newRun(t, b, "theirs"), 10, 4)

	page := list(t, a, action.ChangeListParams{Params: pagination.Params{Limit: 50}, RunID: two.RunID})
	require.Len(t, page.Items, 3)
	for _, c := range page.Items {
		require.Equal(t, two.RunID, c.RunID.UUID)
		require.Equal(t, "two", c.Intent)
	}
	require.Len(t, list(t, a, action.ChangeListParams{Params: pagination.Params{Limit: 50}}).Items, 5)
	require.Len(t, list(t, b, action.ChangeListParams{Params: pagination.Params{Limit: 50}}).Items, 4)
	require.Empty(t, list(t, b, action.ChangeListParams{Params: pagination.Params{Limit: 50}, RunID: one.RunID}).Items)
}

func TestLedgerRedactsUnreadableTables(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "renumber a lead")

	// lead_owner 1 points at lead 101 with ON UPDATE SET NULL; the agent
	// cannot read lead_owner.
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET id = 9101 WHERE id = 101`))
	page := list(t, a, action.ChangeListParams{Params: pagination.Params{Limit: 10}, RunID: in.RunID})
	require.Len(t, page.Items, 1)
	require.Equal(t, 2, page.Items[0].Rows)
	require.Equal(t, 1, page.Items[0].CascadedRows)

	byChange, err := ledger.RowChanges(ctx, a.Conn, []uuid.UUID{page.Items[0].ID})
	require.NoError(t, err)
	rows := byChange[page.Items[0].ID]
	require.Len(t, rows, 2)
	require.Equal(t, "public.leads", rows[0].Table)
	require.False(t, rows[0].Redacted)
	require.Equal(t, float64(101), rows[0].Before["id"])
	require.Equal(t, float64(9101), rows[0].After["id"])

	require.Equal(t, "public.lead_owner", rows[1].Table)
	require.True(t, rows[1].Cascaded)
	require.True(t, rows[1].Redacted)
	require.Nil(t, rows[1].Key)
	require.Nil(t, rows[1].Before)
	require.Nil(t, rows[1].After)

	// Readable once the agent may SELECT the table.
	d.Exec(t, `GRANT SELECT ON public.lead_owner TO `+a.Role)
	byChange, err = ledger.RowChanges(ctx, a.Conn, []uuid.UUID{page.Items[0].ID})
	require.NoError(t, err)
	owner := byChange[page.Items[0].ID][1]
	require.False(t, owner.Redacted)
	require.Equal(t, "owner 1", owner.Before["owner"])
	require.Nil(t, owner.After["lead_id"])

	// Another agent sees nothing of it.
	b := d.NewAgent(t, "other", leads, nil)
	byChange, err = ledger.RowChanges(ctx, b.Conn, []uuid.UUID{page.Items[0].ID})
	require.NoError(t, err)
	require.Empty(t, byChange)
}
