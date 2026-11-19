//go:build unix

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/contractdoc"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// marker is in every value, key, statement, intent, refusal message and
// note the test writes. Nothing a feed plugin receives, and nothing the
// engine logs, may hold it.
const marker = "ZQXMARK"

// The store seeded with marker values and every kind of operation run on
// it: an insert, an update, a refused write and a refused read, a held
// cascaded delete signed and applied, a revert prepared, signed and
// applied, and one prepared and rejected. What the plugin receives holds
// every kind of event and no marker; neither does the engine's log.
func TestNothingLeaksToNotifier(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.start()
	e.started(p.key, "product_a")
	ctx := context.Background()
	c := e.l.dbs["product_a"].db.(*pgx.Conn)
	pk := registerPerson(t, e.l.d)

	run := func(text string) guard.Intent {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: uuid.Must(uuid.NewV7()), Text: text + " " + marker}
		require.NoError(t, guard.StartRun(ctx, c, in))
		return in
	}
	write := func(in guard.Intent, stmt string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		require.NoError(t, pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if err := guard.BeginGuarded(ctx, tx, in, 5*time.Second); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, stmt); err != nil {
				return err
			}
			var err error
			id, err = guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: stmt, Params: []any{marker + "-param"}})
			return err
		}))
		return id
	}

	inserted := write(run("add a lead"), `INSERT INTO public.leads (id, name, status) VALUES (9001, '`+marker+`-insert', '`+marker+`-key')`)
	updated := write(run("rename a lead"), `UPDATE public.leads SET name = '`+marker+`-update' WHERE id = 1`)

	refused := run("drop a table")
	_, err := guard.RecordRefusal(ctx, c, guard.Refusal{
		Intent: refused, Op: "UPDATE", Statement: "UPDATE " + marker + "-statement",
		Params: []any{marker + "-param"}, Code: "STATEMENT_REFUSED", Reason: marker + "-reason",
	})
	require.NoError(t, err)
	_, err = guard.RecordRefusal(ctx, c, guard.Refusal{
		Intent: refused, Op: "DELETE", Statement: "DELETE " + marker,
		Code: marker, Reason: marker + "-reason",
	})
	require.NoError(t, err)
	_, err = guard.RecordRefusal(ctx, c, guard.Refusal{
		Intent: refused, Op: "SELECT", Statement: "SELECT " + marker,
		Code: "QUERY_TIMEOUT", Reason: marker + "-reason",
	})
	require.NoError(t, err)

	// A cascaded delete is held, signed by the person and applied.
	del := run("remove a spam lead")
	stmt := `DELETE FROM public.leads WHERE id = $1 AND name <> '` + marker + `-statement'`
	held := holdWrite(t, c, del, stmt, []any{3})
	as, err := pk.Sign(approval.Challenge(held.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.SubmitApproval(ctx, c, held.ApprovalID, as)
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		if err := guard.BeginApproved(ctx, tx, del, 5*time.Second, held.ApprovalID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, stmt, 3); err != nil {
			return err
		}
		_, err := guard.FinishChange(ctx, tx, guard.Finish{Op: "DELETE", Statement: stmt, Params: []any{3}})
		return err
	}))

	// A revert of the update, signed and applied; one of the insert,
	// rejected with a note.
	prep, err := guard.PrepareRevert(ctx, c, guard.RevertScope{Kind: revert.ScopeChange, ID: updated}, "undo the rename "+marker)
	require.NoError(t, err)
	sig, err := pk.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, c, prep.RevertID, sig)
	require.NoError(t, err)
	rejected, err := guard.PrepareRevert(ctx, c, guard.RevertScope{Kind: revert.ScopeChange, ID: inserted}, "undo the insert "+marker)
	require.NoError(t, err)
	_, err = guard.RejectRevert(ctx, c, rejected.RevertID, "not this one "+marker, nil)
	require.NoError(t, err)

	want := []string{
		"dev.basaltdb.write.applied", "dev.basaltdb.write.refused", "dev.basaltdb.write.held", "dev.basaltdb.approval.signed",
		"dev.basaltdb.revert.prepared", "dev.basaltdb.revert.applied", "dev.basaltdb.revert.rejected",
	}
	head := e.head()
	require.Eventually(t, func() bool {
		cur, _ := e.cursor(p.key, "product_a")
		return cur.Seq >= head
	}, 10*time.Second, 10*time.Millisecond, "everything was delivered")
	var types []string
	for _, call := range p.received() {
		require.NotContains(t, string(call.raw), marker, "a plugin received a value, statement, intent or message")
		for _, ev := range call.events {
			if !slices.Contains(types, ev.Type) {
				types = append(types, ev.Type)
			}
		}
	}
	require.ElementsMatch(t, want, types, "every kind of event was sent")
	// The ledger does hold the marker: the search above is not empty by
	// accident.
	var stored int
	require.NoError(t, e.l.d.Admin.QueryRow(ctx, `SELECT count(seq) FROM basalt_meta.ledger WHERE detail::text LIKE '%'||$1||'%'`, marker).Scan(&stored))
	require.Positive(t, stored)
	require.NotContains(t, e.logs.String(), marker, "the engine logged a value")
}

// holdWrite previews stmt, reads its lines and holds it, as the engine does
// after APPROVAL_REQUIRED.
func holdWrite(t *testing.T, c *pgx.Conn, in guard.Intent, stmt string, params []any) guard.Held {
	t.Helper()
	ctx := context.Background()
	tx, err := c.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, guard.BeginPreview(ctx, tx, in, 5*time.Second))
	_, err = tx.Exec(ctx, stmt, params...)
	require.NoError(t, err)
	lines, err := guard.PreviewLines(ctx, tx, []string{})
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	held, err := guard.Hold(ctx, c, in, 5*time.Second, guard.HoldRequest{Statement: stmt, Params: params, Assigned: []string{}, Lines: lines})
	require.NoError(t, err)
	return held
}

// Every event feedEventOf makes, with every field its kind may carry, and
// the skipped marker, validates against feed.schema.json; a row that cannot
// be carried as the schema fixes is not made into one.
func TestFeedEventsMatchTheSchema(t *testing.T) {
	t.Parallel()
	sch := feedSchema(t)
	install := uuid.Must(uuid.NewV7())
	s := func(v string) *string { return &v }
	id := func() *string { return s(uuid.Must(uuid.NewV7()).String()) }
	change := uuid.NullUUID{UUID: uuid.Must(uuid.NewV7()), Valid: true}
	at := time.Date(2026, 11, 19, 6, 2, 11, 513958000, time.UTC)
	rows := []guard.FeedRow{
		{Seq: 1, At: at, Kind: guard.KindChange, ChangeID: change, Op: s("INSERT"), RunID: id(), TaskID: id(), Table: s("public.\"we\x01ird\""), Rows: s("3"), CascadedRows: s("2")},
		{Seq: 2, At: at, Kind: guard.KindChange, ChangeID: change, Op: s("DELETE")},
		{Seq: 3, At: at, Kind: guard.KindRefused, ChangeID: change, Op: s("OTHER"), RunID: id(), TaskID: id(), Code: s("SQL_ERROR")},
		{Seq: 4, At: at, Kind: guard.KindApprovalPending, ChangeID: change, Op: s("UPDATE"), RunID: id(), ApprovalID: id(), Rows: s("27"), ExpiresAt: s("2026-11-20T06:02:11+00:00")},
		{Seq: 5, At: at, Kind: guard.KindApproved, ChangeID: change, ApprovalID: id()},
		{Seq: 6, At: at, Kind: guard.KindRevertPending, RevertID: id()},
		{Seq: 7, At: at, Kind: guard.KindRevertSigned, ChangeID: change, RevertID: id()},
		{Seq: 8, At: at, Kind: guard.KindReverted, ChangeID: change, RevertID: id()},
		{Seq: 9, At: at, Kind: guard.KindRevertRejected, RevertID: id()},
	}
	events := make([]feedEvent, 0, 1+len(rows))
	events = append(events, skippedEvent(install, "product_a", 0, 1))
	for _, r := range rows {
		ev, ok := feedEventOf(install, "product_a", r)
		require.True(t, ok, r.Kind)
		events = append(events, ev)
	}
	for _, ev := range events {
		raw, _, err := feedBatch([]feedEvent{ev})
		require.NoError(t, err)
		req, err := json.Marshal(protocol.FeedObserveRequest{Agent: "product_a", Events: raw})
		require.NoError(t, err)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(req))
		require.NoError(t, err)
		require.NoError(t, sch.Validate(inst), string(req))
	}
	require.Equal(t, "public.\"we�ird\"", events[1].Data.Table)

	for _, bad := range []guard.FeedRow{
		{Seq: 1, At: at, Kind: "READ", ChangeID: change, Op: s("SELECT")},
		{Seq: 1, At: at, Kind: guard.KindChange, Op: s("UPDATE")},                                          // no change id
		{Seq: 1, At: at, Kind: guard.KindChange, ChangeID: change, Op: s("REVERT")},                        // no such op
		{Seq: 1, At: at, Kind: guard.KindChange, ChangeID: change, Op: s("UPDATE"), RunID: s("x")},         // not an id
		{Seq: 1, At: at, Kind: guard.KindApprovalPending, ChangeID: change, Op: s("UPDATE"), Rows: s("1")}, // no approval, run or expiry
		{Seq: 1, At: at, Kind: guard.KindRevertPending},                                                    // no revert id
		{Seq: 0, At: at, Kind: guard.KindRevertPending, RevertID: id()},
	} {
		_, ok := feedEventOf(install, "product_a", bad)
		require.False(t, ok, "%+v", bad)
	}
}

// The sender never makes its caller wait: a full queue refuses at once, a
// call past its time is dropped unsent, and Stop ends the calls in flight
// and drops the waiting ones, each told why.
func TestSenderNeverBlocks(t *testing.T) {
	t.Parallel()
	h := plugin.NewHost()
	p := &feedPlugin{key: plugin.EntryKey{Name: "acme-feed", Instance: "default"}, m: feedManifest("acme-feed"), mode: hangMode, schema: feedSchema(t)}
	require.NoError(t, h.Register(context.Background(), plugin.Entry{Key: p.key, Manifest: p.m, Agents: []string{"product_a"}, Timeout: time.Minute}, p))
	s := newPluginSender(h, p.key, time.Now)
	var stopped, expired atomic.Int32
	call := func(notAfter time.Time) pluginCall {
		return pluginCall{
			notAfter: notAfter,
			run: func(ctx context.Context, h *plugin.Host, k plugin.EntryKey) error {
				_, err := h.ObserveFeedOn(ctx, k, 0, "product_a", json.RawMessage(`[{"data":{"seq":1}}]`))
				return err
			},
			done: func(err error) {
				switch {
				case errors.Is(err, errSenderStopped):
					stopped.Add(1)
				case errors.Is(err, errCallExpired):
					expired.Add(1)
				}
			},
		}
	}
	begun := time.Now()
	full := 0
	for range pluginSenderQueue + 10 {
		if errors.Is(s.Send(context.Background(), call(time.Time{})), errSenderFull) {
			full++
		}
	}
	require.Positive(t, full, "a full queue refuses")
	require.Less(t, time.Since(begun), time.Second, "Send never waits on the plugin")
	begun = time.Now()
	s.Stop()
	require.Less(t, time.Since(begun), 5*time.Second)
	require.Equal(t, int32(pluginSenderQueue+10-full), stopped.Load(), "every call taken is told it was stopped")
	require.ErrorIs(t, s.Send(context.Background(), call(time.Time{})), errSenderStopped)

	s = newPluginSender(h, p.key, time.Now)
	t.Cleanup(s.Stop)
	sent := len(p.received())
	require.NoError(t, s.Send(context.Background(), call(time.Now().Add(-time.Second))))
	require.Eventually(t, func() bool { return expired.Load() == 1 }, 5*time.Second, 5*time.Millisecond)
	require.Len(t, p.received(), sent, "an expired call is never sent")
}

// poolOf is the pool a test ledger reads through.
func poolOf(t *testing.T, l pluginLedger) *pgxpool.Pool {
	t.Helper()
	p, ok := l.db.(*pgxpool.Pool)
	require.True(t, ok)
	return p
}

// The feed and its senders stop with nothing left behind: no goroutine,
// no connection held, whatever the plugin does when the engine stops.
func TestFeedStopsWithoutLeaks(t *testing.T) {
	e := newFeedEnv(t)
	hang := e.serve("acme-hang", "product_a", "client_x")
	ok := e.serve("acme-ok", "product_a", "client_x")
	hang.setMode(hangMode)
	snapshot := goleak.IgnoreCurrent()
	e.start()
	for _, k := range []plugin.EntryKey{ok.key, hang.key} {
		e.started(k, "product_a")
		e.started(k, "client_x")
	}
	a := e.applied("product_a")
	x := e.applied("client_x")
	waitSeqs(t, ok, "product_a", a)
	waitSeqs(t, ok, "client_x", x)
	require.Eventually(t, func() bool { return len(hang.received()) == 2 }, 10*time.Second, 5*time.Millisecond)

	begun := time.Now()
	e.stop()
	require.Less(t, time.Since(begun), 2*time.Second, "a hanging call does not hold the stop")
	for name, l := range e.pools {
		require.Zero(t, poolOf(t, l).Stat().AcquiredConns(), name)
	}
	goleak.VerifyNone(t, snapshot)
}

// A batch read for one registration of an entry is never sent to the next:
// read, the entry starts again (restarted, or for other agents), and the
// send fails, nothing sent, the cursor where it was.
func TestBatchNeverReachesALaterRegistration(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.start()
	start := e.started(p.key, "product_a")
	e.stop()
	e.applied("product_a")

	f := newPluginFeed(e.host, e.served, e.pools, e.stateDir, newPluginSenders(e.host, time.Now), plugin.RealClock(), e.log)
	f.senders.sync([]plugin.EntryKey{p.key})
	t.Cleanup(f.senders.stop)
	r := &feedReader{f: f, pair: feedPair{key: p.key, agent: "product_a"}, ledger: e.pools["product_a"], log: e.log}
	ctx := context.Background()
	reg, ok := e.host.Registration(p.key)
	require.True(t, ok)
	b, err := r.read(ctx)
	require.NoError(t, err)
	require.Len(t, b.events, 1)

	e.unserve(p.key)
	e.serveAgain(p, "product_a")
	require.Equal(t, roundFailed, r.send(ctx, reg, b))
	require.Empty(t, p.received(), "nothing reached the new registration")
	c, _ := e.cursor(p.key, "product_a")
	require.Equal(t, start, c)

	now, _ := e.host.Registration(p.key)
	require.Equal(t, roundIdle, r.send(ctx, now, b), "read again for it, it goes")
	require.Len(t, p.received(), 1)
}

// feedReasonCodes is the table of CONTRACT.md, Error codes: a refusal's
// code is sent only when the contract names it.
func TestReasonCodesAreTheContracts(t *testing.T) {
	t.Parallel()
	raw, err := contractdoc.Read()
	require.NoError(t, err)
	text := string(raw)
	start := strings.Index(text, "\n## Error codes\n")
	require.Positive(t, start)
	section := text[start+1:]
	end := strings.Index(section, "\n## Next steps\n")
	require.Positive(t, end)
	row := regexp.MustCompile("(?m)^\\| `([A-Z_]+)` \\|")
	rows := row.FindAllStringSubmatch(section[:end], -1)
	codes := make([]string, 0, len(rows))
	for _, m := range rows {
		codes = append(codes, m[1])
	}
	require.NotEmpty(t, codes)
	require.ElementsMatch(t, codes, slices.Collect(maps.Keys(feedReasonCodes)))
}
