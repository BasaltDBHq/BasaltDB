package upkeep_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/pinfile"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/service/upkeep"
)

type event struct {
	detail map[string]any
}

// events returns the agent's ledger rows of kind, oldest first.
func events(t *testing.T, c *pgx.Conn, kind string) []event {
	t.Helper()
	// Plain SQL: test read of the agent view.
	rows, err := c.Query(context.Background(), `SELECT detail FROM basalt_meta.agent_ledger WHERE kind = $1 ORDER BY seq`, kind)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (event, error) {
		var e event
		return e, r.Scan(&e.detail)
	})
	require.NoError(t, err)
	return out
}

func heartbeats(t *testing.T, c *pgx.Conn) []event { return events(t, c, "HEARTBEAT") }

func newUpkeep(c *pgx.Conn, now func() time.Time) *upkeep.Upkeep {
	return upkeep.New("bot", "test", store.NewUpkeep(c), slog.New(slog.DiscardHandler), now)
}

// rewriteHistory changes row 1 and re-hashes the whole chain: the full
// check passes, only a pinned head notices.
const rewriteHistory = `DO $$
DECLARE prev bytea := '\x0000000000000000000000000000000000000000000000000000000000000000'; l basalt_meta.ledger;
BEGIN
	UPDATE basalt_meta.ledger SET detail = detail || '{"forged": true}' WHERE seq = 1;
	FOR l IN SELECT * FROM basalt_meta.ledger ORDER BY seq LOOP
		UPDATE basalt_meta.ledger SET prev_hash = prev, hash = sha256(prev || basalt_meta._canonical(l))
		 WHERE seq = l.seq RETURNING hash INTO prev;
	END LOOP;
	UPDATE basalt_meta.chain_head SET hash = prev WHERE id;
END $$`

func TestTickChecksIn(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()

	u := newUpkeep(a.Conn, time.Now)
	require.NoError(t, u.Tick(ctx))
	hb := heartbeats(t, a.Conn)
	require.Len(t, hb, 1)
	require.Equal(t, "test", hb[0].detail["engineVersion"])
	require.Equal(t, "PERSON", hb[0].detail["operatedBy"], "PERSON unless the config says AGENT")
	require.NotContains(t, hb[0].detail, "chainBrokenAt")
	require.Empty(t, events(t, a.Conn, "DEAD_MAN"))
	require.Empty(t, events(t, a.Conn, "UNCOVERED_TABLES"), "nothing to report")
	_, pinned := u.Head()
	require.True(t, pinned)

	// basalt log sees a fresh heartbeat.
	health, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{})
	require.NoError(t, err)
	require.False(t, health.HeartbeatStale)
	require.True(t, health.Chain.Intact)
}

// Every heartbeat records who operates the engine's machine, so the ledger
// shows the periods when enforcement was guard-only (CO-15).
func TestHeartbeatRecordsOperatedBy(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)

	require.NoError(t, newUpkeep(a.Conn, time.Now).WithOperatedBy("AGENT").Tick(context.Background()))
	hb := heartbeats(t, a.Conn)
	require.Len(t, hb, 1)
	require.Equal(t, "AGENT", hb[0].detail["operatedBy"])
}

func TestTickAfterSilenceWritesTheDeadManRow(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()

	require.NoError(t, newUpkeep(a.Conn, time.Now).Tick(ctx))
	later := func() time.Time { return time.Now().Add(guardmodel.DeadManAfter + 24*time.Hour) }
	require.NoError(t, newUpkeep(a.Conn, later).Tick(ctx))

	require.Len(t, heartbeats(t, a.Conn), 2)
	dm := events(t, a.Conn, "DEAD_MAN")
	require.Len(t, dm, 1)
	require.NotEmpty(t, dm[0].detail["lastHeartbeat"])
	require.GreaterOrEqual(t, dm[0].detail["silentHours"], float64(7*24))

	// basalt log shows the dead-man row.
	health, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{})
	require.NoError(t, err)
	require.NotNil(t, health.DeadMan)
	require.GreaterOrEqual(t, health.DeadMan.SilentHours, int64(7*24))
}

func TestTickReportsABrokenChain(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()

	u := newUpkeep(a.Conn, time.Now)
	require.NoError(t, u.Tick(ctx))
	require.NoError(t, u.Tick(ctx)) // the second tick pins the first heartbeat
	head, ok := u.Head()
	require.True(t, ok)

	// Someone with the admin credential rewrites the pinned row's hash.
	d.Exec(t, `UPDATE basalt_meta.ledger SET hash = sha256(hash) WHERE seq = $1`, head.Seq)
	require.NoError(t, u.Tick(ctx))
	require.NoError(t, u.Tick(ctx))

	hb := heartbeats(t, a.Conn)
	require.Len(t, hb, 4)
	require.InDelta(t, float64(head.Seq), hb[2].detail["chainBrokenAt"], 0)
	require.InDelta(t, float64(head.Seq), hb[3].detail["chainBrokenAt"], 0, "the old head stays pinned until a person looks")
	still, _ := u.Head()
	require.Equal(t, head, still)
}

func TestPinnedHeadSurvivesARestart(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}

	first := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, first.Tick(ctx))
	require.NoError(t, first.Tick(ctx)) // pins the first heartbeat
	saved, ok, err := pins.Load("bot")
	require.NoError(t, err)
	require.True(t, ok, "the verified head is saved")

	// While the engine is stopped, history is rewritten consistently: the
	// full check passes, the saved pin does not.
	d.Exec(t, rewriteHistory)
	st, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{Full: true})
	require.NoError(t, err)
	require.True(t, st.Chain.Intact, "a consistent rewrite passes the full check")

	u := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, u.Tick(ctx))
	hb := heartbeats(t, a.Conn)
	require.InDelta(t, float64(saved.Head.Seq), hb[len(hb)-1].detail["chainBrokenAt"], 0)
	after, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.Equal(t, saved, after, "a broken chain does not move the pin")
}

func TestStartRunsTheFullCheck(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}
	first := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, first.Tick(ctx))
	require.NoError(t, first.Tick(ctx)) // pins the first heartbeat

	// An edit behind the pin that leaves every hash alone: only the full
	// check on start sees it, and it keeps being reported.
	d.Exec(t, `UPDATE basalt_meta.ledger SET detail = '{}' WHERE seq = 1`)
	u := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, u.Tick(ctx))
	require.NoError(t, u.Tick(ctx))
	hb := heartbeats(t, a.Conn)
	require.InDelta(t, float64(1), hb[len(hb)-2].detail["chainBrokenAt"], 0)
	require.InDelta(t, float64(1), hb[len(hb)-1].detail["chainBrokenAt"], 0)
}

func TestTickRecordsUncoveredTablesWhenTheyChange(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	u := newUpkeep(a.Conn, time.Now)
	require.NoError(t, u.Tick(ctx))

	d.Exec(t, `CREATE TABLE public.lead_files (id bigint PRIMARY KEY, lead_id bigint REFERENCES public.leads ON DELETE CASCADE)`)
	require.NoError(t, u.Tick(ctx))
	require.NoError(t, u.Tick(ctx))
	ev := events(t, a.Conn, "UNCOVERED_TABLES")
	require.Len(t, ev, 1, "recorded once while the set is unchanged")
	tables, ok := ev[0].detail["tables"].([]any)
	require.True(t, ok)
	require.Len(t, tables, 1)
	require.Equal(t, "lead_files", tables[0].(map[string]any)["table"])

	d.Init(t, guardmodel.AgentSpec{})
	require.NoError(t, u.Tick(ctx))
	ev = events(t, a.Conn, "UNCOVERED_TABLES")
	require.Len(t, ev, 2, "the fix is recorded too")
	require.Empty(t, ev[1].detail["tables"])
}

func TestRunStopsWithTheContext(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u := newUpkeep(a.Connect(t), time.Now)
	go func() { u.Run(ctx, time.Hour); close(done) }()
	require.Eventually(t, func() bool { return len(heartbeats(t, a.Conn)) == 1 }, 10*time.Second, 20*time.Millisecond)
	cancel()
	<-done
}

func TestNewPanicsWithoutDeps(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { upkeep.New("", "v", nil, slog.New(slog.DiscardHandler), time.Now) })
}

func TestTickWarnsAboutTablesRLSHides(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY`)
	var buf bytes.Buffer
	u := upkeep.New("bot", "test", store.NewUpkeep(a.Conn), slog.New(slog.NewTextHandler(&buf, nil)), time.Now)
	require.NoError(t, u.Tick(context.Background()))
	require.Contains(t, buf.String(), "row-level security hides every row")
	require.Contains(t, buf.String(), "table=public.leads")

	d.Exec(t, `CREATE POLICY bot ON public.leads FOR ALL TO `+a.Role+` USING (true)`)
	buf.Reset()
	require.NoError(t, u.Tick(context.Background()))
	require.NotContains(t, buf.String(), "row-level security")
}

type countingRefresher struct{ n int }

func (c *countingRefresher) Refresh() { c.n++ }

// Every cycle has the engine forget which tables row-level security hides, so
// a policy the person adds shows in the agent's next warning.
func TestTickRefreshesTheRLSCache(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	r := &countingRefresher{}
	u := newUpkeep(a.Conn, time.Now).WithRLSCache(r)
	require.NoError(t, u.Tick(context.Background()))
	require.NoError(t, u.Tick(context.Background()))
	require.Equal(t, 2, r.n)
}

// reinstall drops the guard and installs it again for the agent bot:
// basalt uninstall, then basalt init, on the same database.
func reinstall(t *testing.T, d *guardtest.DB, a *guardtest.Agent) *guardtest.Agent {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, a.Conn.Close(ctx))
	require.NoError(t, guard.Uninstall(ctx, d.Admin, d.Names))
	return d.NewAgent(t, "bot", []string{"public.leads"}, nil)
}

// A reinstall over a kept state directory sets the old install's pin aside
// without a tamper alarm, never silently: the engine reports it in the new
// ledger (PIN_SET_ASIDE with the pinned head), keeps a copy in its pin
// file, and the notice shows. The new pin carries the new install, and a
// rewrite of the new ledger is still caught.
func TestReinstallOverAKeptPinIsRecorded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}

	u := newUpkeep(a.Conn, time.Now).WithPins(pins)
	for range 3 {
		require.NoError(t, u.Tick(ctx))
	}
	old, ok, err := pins.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotZero(t, old.Install, "a pin names its install")

	b := reinstall(t, d, a)
	var logs bytes.Buffer
	again := upkeep.New("bot", "test", store.NewUpkeep(b.Conn), slog.New(slog.NewTextHandler(&logs, nil)), time.Now).WithPins(pins)
	require.NoError(t, again.Tick(ctx))
	require.NoError(t, again.Tick(ctx))
	for _, hb := range heartbeats(t, b.Conn) {
		require.NotContains(t, hb.detail, "chainBrokenAt", "no tamper alarm on a reinstall")
	}
	require.Contains(t, logs.String(), "set aside and reported in the ledger")

	set := events(t, b.Conn, "PIN_SET_ASIDE")
	require.Len(t, set, 1, "reported once")
	require.InDelta(t, float64(old.Head.Seq), set[0].detail["pinnedSeq"], 0)
	require.Equal(t, hex.EncodeToString(old.Head.Hash), set[0].detail["pinnedHash"])
	require.Equal(t, old.Install.String(), set[0].detail["pinnedInstall"])
	require.NotEmpty(t, set[0].detail["installedAt"])

	fresh, ok, err := pins.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEqual(t, old.Install, fresh.Install)
	require.Len(t, fresh.SetAside, 1, "the engine keeps its own copy")
	require.Equal(t, old.Head.Seq, fresh.SetAside[0].PinnedSeq)
	require.Equal(t, fresh.Install, fresh.SetAside[0].Install)

	rs, err := guard.ReadReinstalls(ctx, b.Conn, store.GuardSetAside(fresh.SetAside))
	require.NoError(t, err)
	lines := ledger.ReinstallNotices(rs)
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "This database's ledger was reinstalled on ")
	require.Contains(t, lines[0], fmt.Sprintf("Previous ledger ended at entry %d (hash %s), as reported with the credential of %s.",
		old.Head.Seq, hex.EncodeToString(old.Head.Hash), b.Role))

	// The new chain is pinned and checked like any other.
	d.Exec(t, `UPDATE basalt_meta.ledger SET hash = sha256(hash) WHERE seq = $1`, fresh.Head.Seq)
	require.NoError(t, again.Tick(ctx))
	hb := heartbeats(t, b.Conn)
	require.InDelta(t, float64(fresh.Head.Seq), hb[len(hb)-1].detail["chainBrokenAt"], 0)
}

// A running engine notices a reinstall since its last tick the same way.
func TestReinstallWhileRunningIsRecorded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}
	sw := &switchDB{q: a.Conn}
	u := upkeep.New("bot", "test", store.NewUpkeep(sw), slog.New(slog.DiscardHandler), time.Now).WithPins(pins)
	// Twice: the second pins the first heartbeat, past the genesis.
	require.NoError(t, u.Tick(ctx))
	require.NoError(t, u.Tick(ctx))

	b := reinstall(t, d, a)
	sw.q = b.Conn
	require.NoError(t, u.Tick(ctx))
	require.Len(t, events(t, b.Conn, "PIN_SET_ASIDE"), 1)
	for _, hb := range heartbeats(t, b.Conn) {
		require.NotContains(t, hb.detail, "chainBrokenAt")
	}
}

// switchDB is a guard.Querier whose connection a test replaces.
type switchDB struct{ q guard.Querier }

func (s *switchDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.q.Exec(ctx, sql, args...)
}

func (s *switchDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return s.q.Query(ctx, sql, args...)
}

func (s *switchDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.q.QueryRow(ctx, sql, args...)
}

// otherInstall replaces the saved pin's install with another id: the same
// chain under another install, as when the installs row was deleted and
// basalt init wrote a new one. Returns the pin and the current install.
func otherInstall(t *testing.T, pins pinfile.File) (chainpin.Pin, uuid.UUID) {
	t.Helper()
	p, ok, err := pins.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	moved := chainpin.Pin{Head: p.Head, Install: uuid.New()}
	require.NoError(t, pins.Save("bot", moved))
	return moved, p.Install
}

// The same chain under a new install id moves the pin with a warning naming
// both installs, and records nothing.
func TestSameLedgerUnderANewInstallMovesThePin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}
	first := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, first.Tick(ctx))
	require.NoError(t, first.Tick(ctx))
	moved, current := otherInstall(t, pins)
	require.Positive(t, moved.Head.Seq, "a pinned row, not the genesis")

	var logs bytes.Buffer
	u := upkeep.New("bot", "test", store.NewUpkeep(a.Conn), slog.New(slog.NewTextHandler(&logs, nil)), time.Now).WithPins(pins)
	require.NoError(t, u.Tick(ctx))
	require.Empty(t, events(t, a.Conn, "PIN_SET_ASIDE"), "nothing recorded")
	for _, hb := range heartbeats(t, a.Conn) {
		require.NotContains(t, hb.detail, "chainBrokenAt")
	}
	require.Contains(t, logs.String(), "the guard was installed again over the same ledger")
	require.Contains(t, logs.String(), fmt.Sprintf("pinnedInstall=%s install=%s", moved.Install, current))
	now, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.Equal(t, current, now.Install)
	require.Empty(t, now.SetAside)
	require.Greater(t, now.Head.Seq, moved.Head.Seq)
}

// A pin before an anchor that moved, or at a later anchor, is not on the
// chain any more: the history before the anchor was cut. It is recorded,
// never moved.
func TestPinAtOrBeforeAMovedAnchorIsRecorded(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"before", "at"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
			ctx := context.Background()
			pins := pinfile.File{Dir: t.TempDir()}
			require.NoError(t, newUpkeep(a.Conn, time.Now).WithPins(pins).Tick(ctx))
			// The pin is the head, past the genesis; "before" adds a row
			// after it, so retention's anchor lands past the pin.
			head, err := guardtest.Head(ctx, a.Conn)
			require.NoError(t, err)
			require.Positive(t, head.Seq)
			pin := chainpin.Pin{Head: action.ChainHead(head), Install: uuid.New()}
			require.NoError(t, pins.Save("bot", pin))
			if name == "before" {
				require.NoError(t, guard.Heartbeat(ctx, a.Conn, nil))
			}
			d.Exec(t, `SELECT basalt_meta._prune(now() + interval '2 years')`)

			require.NoError(t, newUpkeep(a.Conn, time.Now).WithPins(pins).Tick(ctx))
			set := events(t, a.Conn, "PIN_SET_ASIDE")
			require.Len(t, set, 1)
			require.InDelta(t, float64(pin.Head.Seq), set[0].detail["pinnedSeq"], 0)
			for _, hb := range heartbeats(t, a.Conn) {
				require.NotContains(t, hb.detail, "chainBrokenAt")
			}
		})
	}
}

// keptPinFixture pins a real head of another install and moves the anchor past
// it, so verify_chain_from would accept it: a restored, rewritten ledger
// whose anchor moved. Returns the pin.
func keptPinFixture(t *testing.T, d *guardtest.DB, a *guardtest.Agent, pins pinfile.File) chainpin.Pin {
	t.Helper()
	ctx := context.Background()
	first := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, first.Tick(ctx))
	require.NoError(t, first.Tick(ctx))
	pin, _ := otherInstall(t, pins)
	require.Positive(t, pin.Head.Seq)
	require.NoError(t, guard.Heartbeat(ctx, a.Conn, nil))
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '2 years')`)
	return pin
}

// noReport makes record_pin_set_aside fail for the agents, as on a guard
// older than version 36 (where it does not exist): kind is "revoke" or
// "older" (the version 36 objects dropped).
func noReport(t *testing.T, d *guardtest.DB, kind string) {
	t.Helper()
	if kind == "revoke" {
		d.Exec(t, `REVOKE EXECUTE ON FUNCTION basalt_meta.record_pin_set_aside(bigint, bytea, uuid) FROM `+d.Names.Agents())
		return
	}
	d.Exec(t, `DROP VIEW basalt_meta.agent_reinstalls;
		DROP FUNCTION basalt_meta.record_pin_set_aside(bigint, bytea, uuid);
		DROP FUNCTION basalt_meta.pin_on_chain(bigint, bytea)`)
}

// When the pin of another install cannot be reported (step 3), the engine
// keeps it and reports the chain broken at it on every tick: it never
// verifies from it (a pin before the anchor would pass) and never replaces
// it. Once the report works, it is recorded and set aside.
func TestUnreportedPinIsKeptAndReportedBroken(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"revoke", "older"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
			ctx := context.Background()
			pins := pinfile.File{Dir: t.TempDir()}
			pin := keptPinFixture(t, d, a, pins)
			noReport(t, d, kind)

			var logs bytes.Buffer
			u := upkeep.New("bot", "test", store.NewUpkeep(a.Conn), slog.New(slog.NewTextHandler(&logs, nil)), time.Now).WithPins(pins)
			for range 2 {
				require.NoError(t, u.Tick(ctx))
				hb := heartbeats(t, a.Conn)
				require.InDelta(t, float64(pin.Head.Seq), hb[len(hb)-1].detail["chainBrokenAt"], 0)
			}
			require.Equal(t, 2, strings.Count(logs.String(), "could not be reported in the ledger"), "one report attempt per tick")
			after, _, err := pins.Load("bot")
			require.NoError(t, err)
			require.Equal(t, pin, after, "the pin is kept")
			if kind == "older" {
				return
			}
			rs, err := guard.ReadReinstalls(ctx, a.Conn, nil)
			require.NoError(t, err)
			require.Empty(t, rs.List)

			d.Exec(t, `GRANT EXECUTE ON FUNCTION basalt_meta.record_pin_set_aside(bigint, bytea, uuid) TO `+d.Names.Agents())
			require.NoError(t, u.Tick(ctx))
			require.Len(t, events(t, a.Conn, "PIN_SET_ASIDE"), 1)
			hb := heartbeats(t, a.Conn)
			require.NotContains(t, hb[len(hb)-1].detail, "chainBrokenAt")
		})
	}
}

// basalt log's check keeps an unreported pin the same way: the chain is
// broken at it, and nothing tells basalt log to save a new pin.
func TestCheckHealthKeepsAnUnreportedPin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}
	kept := keptPinFixture(t, d, a, pins)
	noReport(t, d, "revoke")

	// basalt log's side reads the pin in the guard's types.
	pin := struct {
		Head    guard.ChainHead
		Install uuid.UUID
	}{guard.ChainHead(kept.Head), kept.Install}
	h, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{Pin: &pin.Head, PinInstall: pin.Install})
	require.NoError(t, err)
	require.False(t, h.Chain.Intact)
	require.Equal(t, pin.Head.Seq, h.Chain.BrokenAt)
	require.Equal(t, pin.Head, h.Head, "the pin, not a new head")
	require.False(t, h.PinSetAside)
	require.False(t, h.PinMoved)
	require.Empty(t, events(t, a.Conn, "PIN_SET_ASIDE"))
}

// basalt log's check (CHECK_HEALTH) runs the same steps for its own pin and
// shows its kept copy even when the ledger rows are gone.
func TestCheckHealthSettlesAPinOfAnotherInstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	require.NoError(t, newUpkeep(a.Conn, time.Now).Tick(ctx))
	first, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{})
	require.NoError(t, err)
	require.NotZero(t, first.Install)
	require.Empty(t, first.Reinstalls.List)

	pin := first.Head
	same, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{Pin: &pin, PinInstall: first.Install})
	require.NoError(t, err)
	require.False(t, same.PinSetAside)
	require.False(t, same.PinMoved)

	far := guard.ChainHead{Seq: first.Head.Seq + 100, Hash: first.Head.Hash}
	broken, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{Pin: &far, PinInstall: first.Install})
	require.NoError(t, err)
	require.False(t, broken.Chain.Intact, "a pin of this install still catches a ledger that went backwards")

	another := uuid.New()
	moved, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{Pin: &pin, PinInstall: another})
	require.NoError(t, err)
	require.True(t, moved.PinMoved, "the same chain under another install")
	require.True(t, moved.Chain.Intact)
	require.Empty(t, moved.Reinstalls.List)

	other, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{Pin: &far, PinInstall: another})
	require.NoError(t, err)
	require.True(t, other.PinSetAside)
	require.True(t, other.Chain.Intact, "the new ledger is checked from its start")
	require.Len(t, other.Reinstalls.List, 1)
	require.Equal(t, far.Seq, other.Reinstalls.List[0].Reports[0].PinnedSeq)

	// The rows deleted: the kept copy still shows the notice.
	d.Exec(t, `DELETE FROM basalt_meta.ledger WHERE kind = 'PIN_SET_ASIDE'`)
	kept := []guard.SetAside{{PinnedSeq: far.Seq, PinnedHash: far.Hash, PinnedInstall: another, Install: first.Install, At: time.Now()}}
	h, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{SetAside: kept})
	require.NoError(t, err)
	require.Len(t, h.Reinstalls.List, 1)
	require.Contains(t, ledger.ReinstallNotices(h.Reinstalls)[0], "(no install record)")
}

// The database removed and created again the same way (a Postgres
// container removed and started again from the same image): basalt_meta
// has the same schema oid, but it is a new install. An engine with a kept
// state directory reports its old pin and sets it aside, with the notice,
// never a broken chain; the new ledger is pinned on the new install.
func TestRecreatedDatabaseIsARecordedReinstall(t *testing.T) {
	t.Parallel()
	d := guardtest.NewRecreatable(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}
	u := newUpkeep(a.Conn, time.Now).WithPins(pins)
	for range 3 {
		require.NoError(t, u.Tick(ctx))
	}
	old, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.Positive(t, old.Head.Seq)

	d.Recreate(t)
	d.WithDemo(t)
	b := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	again := newUpkeep(b.Conn, time.Now).WithPins(pins)
	require.NoError(t, again.Tick(ctx))
	require.NoError(t, again.Tick(ctx))
	for _, hb := range heartbeats(t, b.Conn) {
		require.NotContains(t, hb.detail, "chainBrokenAt", "a recreated database is not a broken chain")
	}
	set := events(t, b.Conn, "PIN_SET_ASIDE")
	require.Len(t, set, 1, "reported once")
	require.Equal(t, old.Install.String(), set[0].detail["pinnedInstall"])
	fresh, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.NotEqual(t, old.Install, fresh.Install)
	require.Len(t, fresh.SetAside, 1)
	rs, err := guard.ReadReinstalls(ctx, b.Conn, store.GuardSetAside(fresh.SetAside))
	require.NoError(t, err)
	require.Len(t, ledger.ReinstallNotices(rs), 1)
}

// basalt log's check after the same recreate: the pin is reported and set
// aside, the new chain checked from its start.
func TestCheckHealthAfterARecreatedDatabase(t *testing.T) {
	t.Parallel()
	d := guardtest.NewRecreatable(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	require.NoError(t, guard.Heartbeat(ctx, a.Conn, nil))
	first, err := ledger.CheckHealth(ctx, a.Conn, time.Now(), ledger.HealthOptions{})
	require.NoError(t, err)
	require.Positive(t, first.Head.Seq)

	d.Recreate(t)
	d.WithDemo(t)
	b := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	opts := ledger.HealthOptions{Pin: &first.Head, PinInstall: first.Install}
	h, err := ledger.CheckHealth(ctx, b.Conn, time.Now(), opts)
	require.NoError(t, err)
	require.True(t, h.Chain.Intact, "not a broken chain")
	require.True(t, h.PinSetAside)
	require.NotEqual(t, first.Install, h.Install)
	require.Len(t, h.Reinstalls.List, 1)
	require.Equal(t, first.Head.Seq, h.Reinstalls.List[0].Reports[0].PinnedSeq)
}

// A pin saved before install ids has no install. It is never checked as
// the current install's: on the current chain it moves, otherwise it is
// reported and set aside.
func TestPinWithoutAnInstallIsSettled(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := pinfile.File{Dir: t.TempDir()}
	first := newUpkeep(a.Conn, time.Now).WithPins(pins)
	require.NoError(t, first.Tick(ctx))
	require.NoError(t, first.Tick(ctx))
	p, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.NoError(t, pins.Save("bot", chainpin.Pin{Head: p.Head}))

	require.NoError(t, newUpkeep(a.Conn, time.Now).WithPins(pins).Tick(ctx))
	require.Empty(t, events(t, a.Conn, "PIN_SET_ASIDE"), "the same chain: moved")
	moved, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.Equal(t, p.Install, moved.Install)

	far := action.ChainHead{Seq: p.Head.Seq + 100, Hash: p.Head.Hash}
	require.NoError(t, pins.Save("bot", chainpin.Pin{Head: far}))
	require.NoError(t, newUpkeep(a.Conn, time.Now).WithPins(pins).Tick(ctx))
	require.Len(t, events(t, a.Conn, "PIN_SET_ASIDE"), 1, "not on the chain: reported")
	for _, hb := range heartbeats(t, a.Conn) {
		require.NotContains(t, hb.detail, "chainBrokenAt")
	}
}
