package ledger_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

func hexSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// largeLedger is an agent run with one change whose new value is over
// 1 MiB, and one whose images take it past 8 MiB. (A statement is at most
// 16 KiB: the guard refuses a longer one.)
func largeLedger(t *testing.T) (*guardtest.Agent, uuid.UUID, string) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.docs (id int PRIMARY KEY, body text);
		INSERT INTO public.docs VALUES (1, 'small');
		CREATE TABLE public.wide (id int PRIMARY KEY, a text, b text, c text, d text, e text);
		INSERT INTO public.wide SELECT 1, repeat('a', 1000000), repeat('b', 1000000), repeat('c', 1000000),
			repeat('d', 1000000), repeat('e', 1000000)`)
	tables := []string{"public.docs", "public.wide"}
	a := d.NewAgent(t, "bot", tables, tables)
	in := newRun(t, a, "large values")
	big := strings.Repeat("x", 1100000)
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.docs SET body = repeat('x', 1100000) WHERE id = 1`,
		`UPDATE public.wide SET a = upper(a), b = upper(b), c = upper(c), d = upper(d), e = upper(e) WHERE id = 1`))
	return a, in.RunID, big
}

// TestMarkedReadsLeaveOutLargeValuesThePersonsReadsDoNot: the agent's
// reads name the value over 1 MiB and leave the image past
// 8 MiB out whole (absent in the record, never null); basalt log's reads
// of the same changes return every value in full.
func TestMarkedReadsLeaveOutLargeValuesThePersonsReadsDoNot(t *testing.T) {
	t.Parallel()
	a, run, big := largeLedger(t)
	ctx := context.Background()
	p := ledger.ChangeListParams{Params: pagination.Params{Limit: 10, Sort: "id"}, RunID: run}

	full, err := ledger.ListChanges(ctx, a.Conn, p)
	require.NoError(t, err)
	require.Len(t, full.Items, 2)
	fullRows, err := ledger.RowChanges(ctx, a.Conn, []uuid.UUID{full.Items[0].ID, full.Items[1].ID})
	require.NoError(t, err)
	require.Equal(t, big, fullRows[full.Items[0].ID][0].After["body"])
	require.Len(t, fullRows[full.Items[1].ID][0].After, 6)
	require.Nil(t, fullRows[full.Items[0].ID][0].LargeValues)
	// The person's read carries a summary of each value over 1 MiB for the
	// CLI to print, matching the marker the agent sees.
	require.Equal(t, "(1.0 MiB, sha256 "+hexSHA(big)+")", fullRows[full.Items[0].ID][0].Marks.After["body"])
	require.Empty(t, fullRows[full.Items[0].ID][0].Marks.Before)
	require.Empty(t, fullRows[full.Items[0].ID][0].Marks.Key)

	marked, err := ledger.ListChangesMarked(ctx, a.Conn, p)
	require.NoError(t, err)
	require.Len(t, marked.Items, 2)
	first, second := marked.Items[0], marked.Items[1]
	require.Equal(t, full.Items[0].Statement, first.Statement)
	require.Nil(t, first.LargeValues, "the statement is small")
	require.Equal(t, full.Items[1].Statement, second.Statement)

	rows, err := ledger.RowChangesMarked(ctx, a.Conn, []uuid.UUID{first.ID, second.ID})
	require.NoError(t, err)
	r := rows[first.ID][0]
	require.Equal(t, map[string]any{"id": float64(1)}, r.After, "body is absent")
	require.Equal(t, map[string]any{"id": float64(1), "body": "small"}, r.Before)
	require.Equal(t, []largevalue.Entry{{In: "AFTER", Column: "body", Bytes: int64(len(big)), SHA256: hexSHA(big)}}, r.LargeValues)

	w := rows[second.ID][0]
	require.Len(t, w.Before, 6, "the first 5 MB image fits")
	require.True(t, w.AfterLeftOut, "the second takes the item past 8 MiB")
	require.Nil(t, w.After)
	require.Len(t, w.LargeValues, 1)
	require.Equal(t, "AFTER", w.LargeValues[0].In)
	require.Empty(t, w.LargeValues[0].Column)

	raw, err := json.Marshal(ledger.RecordFromDomain(second, rows[second.ID]))
	require.NoError(t, err)
	var rec map[string]any
	require.NoError(t, json.Unmarshal(raw, &rec))
	row, ok := rec["rowChanges"].([]any)[0].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, row, "after", "an image left out whole is absent, never null")
	require.Contains(t, row, "before")
	require.Contains(t, row, "largeValues")

	raw, err = json.Marshal(ledger.RecordFromDomain(full.Items[1], fullRows[full.Items[1].ID]))
	require.NoError(t, err)
	require.NotContains(t, string(raw), "largeValues", "basalt log --json is unchanged")
}

// TestMarkedRevertLinesCutChangeIDs: a plan line of a row touched by more
// than 100 changes carries the first 100 on the agent's read, with the
// rest counted; the person's read has them all.
func TestMarkedRevertLinesCutChangeIDs(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.counter (id int PRIMARY KEY, n int);
		INSERT INTO public.counter SELECT g, 0 FROM generate_series(1, 1001) g`)
	tables := []string{"public.counter"}
	a := d.NewAgent(t, "bot", tables, tables)
	in := newRun(t, a, "count")
	stmts := make([]string, 0, 220)
	for range 120 {
		stmts = append(stmts, `UPDATE public.counter SET n = n + 1 WHERE id = 1`)
	}
	for i := 2; i <= 1001; i += 10 {
		stmts = append(stmts, `UPDATE public.counter SET n = n + 1 WHERE id BETWEEN `+itoa(i)+` AND `+itoa(i+9))
	}
	ctx := context.Background()
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, stmts...))
	prep, err := guardPrepare(t, a, in.RunID)
	require.NoError(t, err)

	p := ledger.RevertLineParams{Params: pagination.Params{Limit: pagination.MaxLimit}, RevertID: prep}
	cut := 0
	for {
		full, err := ledger.ListRevertLines(ctx, a.Conn, p)
		require.NoError(t, err)
		marked, err := ledger.ListRevertLinesMarked(ctx, a.Conn, p)
		require.NoError(t, err)
		require.Len(t, marked.Items, len(full.Items))
		require.Equal(t, full.NextCursor, marked.NextCursor)
		for i, l := range marked.Items {
			var line, whole struct {
				ChangeIDs []string `json:"changeIds"`
				More      int      `json:"moreChangeIds"`
			}
			require.NoError(t, json.Unmarshal([]byte(l.Text), &line))
			require.NoError(t, json.Unmarshal([]byte(full.Items[i].Text), &whole))
			if len(whole.ChangeIDs) <= largevalue.MaxChangeIDs {
				require.Equal(t, whole.ChangeIDs, line.ChangeIDs)
				require.Zero(t, line.More)
				continue
			}
			cut++
			require.Equal(t, whole.ChangeIDs[:largevalue.MaxChangeIDs], line.ChangeIDs)
			require.Equal(t, len(whole.ChangeIDs)-largevalue.MaxChangeIDs, line.More)
		}
		if full.NextCursor == "" {
			break
		}
		p.Cursor = full.NextCursor
	}
	require.Equal(t, 1, cut, "row 1's line, touched by 121 changes")
}

func itoa(i int) string { return strconv.Itoa(i) }

// guardPrepare prepares a revert of run as the agent, as basalt revert
// does on the agent's credential.
func guardPrepare(t *testing.T, a *guardtest.Agent, run uuid.UUID) (uuid.UUID, error) {
	t.Helper()
	prep, err := guard.PrepareRevert(context.Background(), a.Conn, guard.RevertScope{Kind: revert.ScopeRun, ID: run}, "Undo the counts")
	if err != nil {
		return uuid.Nil, err
	}
	require.True(t, prep.Batched, "over revert.MaxLines lines: a batched plan")
	return prep.RevertID, nil
}

// TestListOpenApprovalsReadsAHeldWrite: list_pending's marked read returns
// a held write's statement and params as they are when they are small (the
// guard takes at most 64 KiB of each, under the 1 MiB a value may cost
// even when every byte is escaped: Elide's tests cover the markers).
func TestListOpenApprovalsReadsAHeldWrite(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "remove a lead")
	ctx := context.Background()
	sql := "DELETE FROM public.leads WHERE id = $1"
	store := postgres.NewStore(a.Conn, sqlguard.DefaultLimits(), time.Now)
	lines, err := store.Preview(ctx, action.Intent(in), sql, []any{1}, nil)
	require.NoError(t, err)
	_, err = store.Hold(ctx, action.Intent(in), action.HoldRequest{Statement: sql, Params: []any{1}, Lines: lines})
	require.NoError(t, err)
	page, err := ledger.ListOpenApprovals(ctx, a.Conn, ledger.ApprovalListParams{Params: pagination.Params{Limit: 1}})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, sql, page.Items[0].Statement)
	require.JSONEq(t, `[1]`, string(page.Items[0].Params))
	require.Nil(t, page.Items[0].LargeValues)
}
