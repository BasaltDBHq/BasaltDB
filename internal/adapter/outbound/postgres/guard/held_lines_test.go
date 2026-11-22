package guard_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
)

// bigRowTimeout is the statement timeout of a test that moves 64 MiB.
const bigRowTimeout = time.Minute

// docsAgent is an agent on a table docs whose row 1 has a body of size
// bytes.
func docsAgent(t *testing.T, size int) (*guardtest.DB, *guardtest.Agent) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.docs (id int PRIMARY KEY, body text);
		INSERT INTO public.docs VALUES (1, repeat('x', %d)), (2, 'two')`, size))
	tables := []string{"public.docs"}
	a := d.NewAgent(t, "bot", tables, tables)
	return d, a
}

// requireHoldTooLarge is the guard's refusal of a held write whose
// preview lines are over guard.MaxHeldLinesBytes.
func requireHoldTooLarge(t *testing.T, err error) {
	t.Helper()
	requireCode(t, err, guard.CodeNotAllowed)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Equal(t, guard.DetailHoldTooLarge, pg.Detail)
	require.Contains(t, pg.Hint, fmt.Sprint(guard.MaxHeldLinesBytes))
}

// A held DELETE of a row with a 2 MB value is held whole, signed and
// applied: a preview line is no longer capped at 64 KiB (version 37).
func TestHoldKeepsALargeLine(t *testing.T) {
	t.Parallel()
	d, a := docsAgent(t, 2_000_000)
	p := person(t, d)
	in := newRun(t, a, "drop the large doc")
	const stmt = `DELETE FROM public.docs WHERE id = $1`
	params := []any{1}

	held, lines := previewAndHold(t, a.Conn, in, stmt, params, []string{})
	require.Len(t, lines, 1)
	require.Greater(t, len(lines[0]), 2_000_000, "the line carries the value whole")
	require.Contains(t, lines[0], `"op": "DELETE"`)

	_, err := guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, sign(t, p, held, nil))
	require.NoError(t, err)
	require.NoError(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, params))
	require.Zero(t, scalarOf[int](t, d.Admin, `SELECT count(id)::int FROM public.docs WHERE id = 1`))
}

// Lines over the cap are refused with NOT_ALLOWED HOLD_TOO_LARGE, by
// preview_lines before the engine reads them and by hold_action for lines
// it is handed: never LEDGER_INPUT_INVALID, which the agent sees as
// INTERNAL. Not parallel, and with a long statement timeout: it moves
// 64 MiB rows, which a loaded machine can take seconds over.
func TestHoldRefusesLinesOverTheCap(t *testing.T) {
	_, a := docsAgent(t, guard.MaxHeldLinesBytes)
	in := newRun(t, a, "drop the huge doc")
	ctx := context.Background()

	tx, err := a.Conn.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, guard.BeginPreview(ctx, tx, in, bigRowTimeout))
	_, err = tx.Exec(ctx, `DELETE FROM public.docs WHERE id = 1`)
	require.NoError(t, err)
	_, err = guard.PreviewLines(ctx, tx, []string{})
	requireHoldTooLarge(t, err)
	require.NoError(t, tx.Rollback(ctx))

	line := `{"op": "DELETE", "key": {"id": 1}, "old": {"id": 1, "body": "` + strings.Repeat("x", guard.MaxHeldLinesBytes) +
		`"}, "set": null, "table": "public.docs", "cascaded": false}`
	_, err = guard.Hold(ctx, a.Conn, in, bigRowTimeout, guard.HoldRequest{
		Statement: `DELETE FROM public.docs WHERE id = $1`, Params: []any{1}, Assigned: []string{}, Lines: []string{line},
	})
	requireHoldTooLarge(t, err)
}
