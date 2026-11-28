package handoff

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// removalOf is the removal link certSetup's code makes: an AGENT code for
// db, carrying the engine's key.
func removalOf(t *testing.T, now time.Time) config.Removal {
	t.Helper()
	s := certSetup(t, now)
	return config.Removal{SetupID: s.SetupID, ExpiresAt: s.ExpiresAt, Code: s.Code, Fingerprint: s.Fingerprint}
}

// removedCollector answers every collect with one hold, counts them and
// records the ReportRemoved calls.
type removedCollector struct {
	holdCollector
	collects int
	reports  []string
}

func (c *removedCollector) Collect(ctx context.Context, id, fp string) (Collected, error) {
	c.collects++
	return c.holdCollector.Collect(ctx, id, fp)
}

func (c *removedCollector) ReportRemoved(_ context.Context, setupID, _, result, reason string) error {
	c.reports = append(c.reports, setupID+" "+result+" "+reason)
	return nil
}

type selfRemoveRun struct {
	c       *removedCollector
	r       *SelfRemove
	got     []Removed
	pending *config.Removal
}

func newSelfRemoveRun(t *testing.T, hold Collected, login error, pending *config.Removal, now func() time.Time) *selfRemoveRun {
	t.Helper()
	s := &selfRemoveRun{c: &removedCollector{holdCollector: holdCollector{hold: hold}}, pending: pending}
	s.r = NewSelfRemove(SelfRemoveOptions{
		Agent: "lead_bot", Credential: db, Collector: s.c,
		Login: func(context.Context) error { return login },
		Pending: func() (config.Removal, bool, error) {
			if s.pending == nil {
				return config.Removal{}, false, nil
			}
			return *s.pending, true, nil
		},
		Confirmed: func(_ context.Context, r Removed) bool { s.got = append(s.got, r); return true },
		Log:       slog.New(slog.DiscardHandler), Now: now,
	})
	return s
}

// The engine removes itself only on a REMOVED hold of the credential's own
// database for the removal engine.json records now, and only once a fresh
// login shows the agent's role is gone. A hold the service made up (the
// role still logs in), another database, a setup hold, a database it
// cannot reach and a removal past its window remove nothing. A removal
// written while the engine runs is collected at the next tick.
func TestSelfRemove(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	removed := Collected{Address: db, Phase: HoldRemoved}

	t.Run("a removal written while the engine runs", func(t *testing.T) {
		t.Parallel()
		s := newSelfRemoveRun(t, removed, ErrLoginRefused, nil, clock)
		require.True(t, s.r.Step(context.Background()), "no removal: the watch goes on")
		require.Zero(t, s.c.collects, "nothing is collected with no removal pending")
		rm := removalOf(t, now)
		s.pending = &rm
		require.False(t, s.r.Step(context.Background()))
		require.True(t, s.r.Done())
		require.Len(t, s.got, 1)
		require.NoError(t, s.got[0].Report(context.Background(), RemovedAll, ""))
		require.Equal(t, []string{rm.SetupID + " REMOVED "}, s.c.reports, "the report is signed for the removal's own setupId")
	})
	cases := map[string]struct {
		hold  Collected
		login error
	}{
		"a forged hold: the role still logs in": {removed, nil},
		"another database":                      {Collected{Address: setupcodeAddr("another"), Phase: HoldRemoved}, ErrLoginRefused},
		"a setup hold":                          {Collected{Address: db, Phase: HoldSetUp}, ErrLoginRefused},
		"the database cannot be reached":        {removed, errors.New("dial tcp: i/o timeout")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rm := removalOf(t, now)
			s := newSelfRemoveRun(t, c.hold, c.login, &rm, clock)
			require.True(t, s.r.Step(context.Background()))
			require.False(t, s.r.Done())
			require.Empty(t, s.got)
		})
	}
	t.Run("past the collect window", func(t *testing.T) {
		t.Parallel()
		rm := removalOf(t, now)
		s := newSelfRemoveRun(t, removed, ErrLoginRefused, &rm, func() time.Time { return now.Add(time.Hour) })
		require.True(t, s.r.Step(context.Background()))
		require.Zero(t, s.c.collects)
	})
}

func setupcodeAddr(database string) setupcode.Address {
	a := db
	a.Database = database
	return a
}

// A removal whose code names another database than the credential, or
// that is not an AGENT code with the engine's key for its setupId, is not
// collected for.
func TestCheckRemoval(t *testing.T) {
	t.Parallel()
	rm := removalOf(t, time.Now())
	_, err := CheckRemoval(rm, db)
	require.NoError(t, err)
	_, err = CheckRemoval(rm, setupcodeAddr("another"))
	require.ErrorIs(t, err, ErrNotARemoval)
	wrongID := rm
	wrongID.SetupID = "01a1f78c-52b8-7c3a-9f00-0000000000e1"
	_, err = CheckRemoval(wrongID, db)
	require.ErrorIs(t, err, ErrNotARemoval)
	co := rm
	co.Code = fixtureCode
	_, err = CheckRemoval(co, db)
	require.ErrorIs(t, err, ErrNotARemoval)
}
