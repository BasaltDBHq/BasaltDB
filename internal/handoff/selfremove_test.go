package handoff

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// removalOf is the removal link certSetup's code makes: an AGENT code with
// no change for db, carrying the engine's key.
func removalOf(t *testing.T, now time.Time) config.Removal {
	t.Helper()
	s := certSetup(t, now)
	return config.Removal{SetupID: s.SetupID, ExpiresAt: s.ExpiresAt, Code: s.Code, Fingerprint: s.Fingerprint}
}

// removedCollector answers every collect with one hold and records the
// ReportRemoved calls.
type removedCollector struct {
	holdCollector
	reports []string
}

func (c *removedCollector) ReportRemoved(_ context.Context, setupID, _, result, reason string) error {
	c.reports = append(c.reports, setupID+" "+result+" "+reason)
	return nil
}

// The engine removes itself only on a REMOVED hold of the credential's own
// database for the removal engine.json records now, and only once a fresh
// login shows the agent's role is gone. A hold the service made up (the
// role still logs in), another database, a setup hold, an older link and a
// database it cannot reach remove nothing.
func TestSelfRemove(t *testing.T) {
	t.Parallel()
	now := time.Now()
	removed := Collected{Address: db, Phase: HoldRemoved}
	run := func(t *testing.T, hold Collected, login error, pending func(config.Removal) (config.Removal, bool)) (*removedCollector, *SelfRemove, []Removed, bool) {
		t.Helper()
		rm := removalOf(t, now)
		c := &removedCollector{holdCollector: holdCollector{hold: hold}}
		var got []Removed
		r, err := NewSelfRemove(SelfRemoveOptions{
			Agent: "lead_bot", Removal: rm, Credential: db, Collector: c,
			Login: func(context.Context) error { return login },
			Pending: func() (config.Removal, bool, error) {
				p, ok := pending(rm)
				return p, ok, nil
			},
			Confirmed: func(_ context.Context, r Removed) { got = append(got, r) },
			Log:       slog.New(slog.DiscardHandler), Now: func() time.Time { return now },
		})
		require.NoError(t, err)
		more := r.Step(context.Background())
		return c, r, got, more
	}
	same := func(r config.Removal) (config.Removal, bool) { return r, true }

	c, r, got, more := run(t, removed, ErrLoginRefused, same)
	require.False(t, more)
	require.True(t, r.Done())
	require.Len(t, got, 1)
	require.NoError(t, got[0].Report(context.Background(), RemovedAll, ""))
	require.Equal(t, []string{got[0].SetupID + " REMOVED "}, c.reports, "the report is signed for the removal's own setupId")

	t.Run("a forged hold: the role still logs in", func(t *testing.T) {
		t.Parallel()
		_, r, got, more := run(t, removed, nil, same)
		require.True(t, more)
		require.False(t, r.Done())
		require.Empty(t, got)
	})
	t.Run("another database", func(t *testing.T) {
		t.Parallel()
		other := db
		other.Database = "another"
		_, _, got, more := run(t, Collected{Address: other, Phase: HoldRemoved}, ErrLoginRefused, same)
		require.True(t, more)
		require.Empty(t, got)
	})
	t.Run("a setup hold", func(t *testing.T) {
		t.Parallel()
		_, _, got, _ := run(t, Collected{Address: db, Phase: HoldSetUp}, ErrLoginRefused, same)
		require.Empty(t, got)
	})
	t.Run("an older link: engine.json records another removal", func(t *testing.T) {
		t.Parallel()
		_, _, got, more := run(t, removed, ErrLoginRefused, func(r config.Removal) (config.Removal, bool) {
			r.SetupID = "01a1f78c-52b8-7c3a-9f00-0000000000e1"
			return r, true
		})
		require.False(t, more, "collecting ends with the removal it was for")
		require.Empty(t, got)
	})
	t.Run("the database cannot be reached", func(t *testing.T) {
		t.Parallel()
		_, _, got, more := run(t, removed, errors.New("dial tcp: i/o timeout"), same)
		require.True(t, more)
		require.Empty(t, got)
	})
}

// A removal whose code names another database than the credential, or
// that is not an AGENT code with the engine's key, is not collected for.
func TestSelfRemoveRefusesAnotherCode(t *testing.T) {
	t.Parallel()
	rm := removalOf(t, time.Now())
	opts := SelfRemoveOptions{
		Removal: rm, Credential: db, Collector: holdCollector{},
		Login: func(context.Context) error { return nil }, Pending: func() (config.Removal, bool, error) { return rm, true, nil },
		Confirmed: func(context.Context, Removed) {}, Log: slog.New(slog.DiscardHandler), Now: time.Now,
	}
	other := opts
	other.Credential.Database = "another"
	_, err := NewSelfRemove(other)
	require.ErrorIs(t, err, ErrNotARemoval)
	wrongID := opts
	wrongID.Removal.SetupID = "01a1f78c-52b8-7c3a-9f00-0000000000e1"
	_, err = NewSelfRemove(wrongID)
	require.ErrorIs(t, err, ErrNotARemoval)
	co := opts
	co.Removal.Code = fixtureCode
	_, err = NewSelfRemove(co)
	require.ErrorIs(t, err, ErrNotARemoval)
}
