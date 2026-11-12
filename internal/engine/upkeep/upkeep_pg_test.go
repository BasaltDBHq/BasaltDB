package upkeep_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/upkeep"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
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
	return upkeep.New("bot", "test", c, slog.New(slog.DiscardHandler), now)
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
	later := func() time.Time { return time.Now().Add(ledger.DeadManAfter + 24*time.Hour) }
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
	pins := chainpin.File{Dir: t.TempDir()}

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
	require.InDelta(t, float64(saved.Seq), hb[len(hb)-1].detail["chainBrokenAt"], 0)
	after, _, err := pins.Load("bot")
	require.NoError(t, err)
	require.Equal(t, saved, after, "a broken chain does not move the pin")
}

func TestStartRunsTheFullCheck(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	pins := chainpin.File{Dir: t.TempDir()}
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

	d.Init(t, guard.AgentSpec{})
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
	u := upkeep.New("bot", "test", a.Conn, slog.New(slog.NewTextHandler(&buf, nil)), time.Now)
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
