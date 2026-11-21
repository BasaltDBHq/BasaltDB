package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/laststop"
)

// superviseRig is supervise with a fake clock: a child "runs" by moving the
// clock forward, and a sleep moves it by the wait.
type superviseRig struct {
	clock     time.Time
	starts    []string
	sleeps    []time.Duration
	stops     []string
	childEnds []func(ctx context.Context, r *superviseRig) error
}

func (r *superviseRig) options() superviseOptions {
	return superviseOptions{
		firstStartedBy: startedByMCP,
		start: func(ctx context.Context, by string) (func() error, error) {
			i := len(r.starts)
			r.starts = append(r.starts, by)
			return func() error { return r.childEnds[min(i, len(r.childEnds)-1)](ctx, r) }, nil
		},
		sleep: func(ctx context.Context, d time.Duration) bool {
			r.sleeps = append(r.sleeps, d)
			r.clock = r.clock.Add(d)
			return ctx.Err() == nil
		},
		now:      func() time.Time { return r.clock },
		log:      slog.New(slog.DiscardHandler),
		lastStop: func(reason string) { r.stops = append(r.stops, reason) },
	}
}

func failsAfter(d time.Duration) func(context.Context, *superviseRig) error {
	return func(_ context.Context, r *superviseRig) error {
		r.clock = r.clock.Add(d)
		return errors.New("exit status 2")
	}
}

func TestSuperviseRestartsAfterCrash(t *testing.T) {
	t.Parallel()
	r := &superviseRig{clock: time.Unix(1000, 0)}
	ctx, cancel := context.WithCancel(context.Background())
	r.childEnds = []func(context.Context, *superviseRig) error{
		failsAfter(20 * time.Second),
		func(c context.Context, _ *superviseRig) error { cancel(); <-c.Done(); return c.Err() },
	}
	opts := r.options()

	require.NoError(t, supervise(ctx, opts))

	require.Equal(t, []string{"mcp", "crash"}, r.starts)
	require.Equal(t, []time.Duration{time.Second}, r.sleeps)
	require.Empty(t, r.stops)
}

func TestSuperviseGivesUpAfterFastCrashes(t *testing.T) {
	t.Parallel()
	r := &superviseRig{clock: time.Unix(1000, 0)}
	r.childEnds = []func(context.Context, *superviseRig) error{failsAfter(time.Second)}

	err := supervise(context.Background(), r.options())

	require.ErrorContains(t, err, "crashed 5 times within 10s")
	require.Len(t, r.starts, 5)
	require.Equal(t, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}, r.sleeps)
	require.Len(t, r.stops, 1)
	require.Contains(t, r.stops[0], "crashed 5 times within 10s")
	require.Contains(t, r.stops[0], "exit status 2")
}

// A child that ran for a while before it failed resets the count and the
// backoff: only consecutive fast crashes give up.
func TestSuperviseLongRunResetsTheCrashCount(t *testing.T) {
	t.Parallel()
	r := &superviseRig{clock: time.Unix(1000, 0)}
	short, long := failsAfter(time.Second), failsAfter(time.Minute)
	r.childEnds = []func(context.Context, *superviseRig) error{
		short, short, short, short, long, short, short, short, short,
		func(context.Context, *superviseRig) error { return nil },
	}

	require.NoError(t, supervise(context.Background(), r.options()))

	require.Len(t, r.starts, 10)
	require.Empty(t, r.stops)
	// 1s 2s 4s 8s, then the long run restarts the backoff at 1s.
	require.Equal(t, []time.Duration{1, 2, 4, 8, 1, 2, 4, 8, 16}, secondsOf(r.sleeps))
}

func secondsOf(ds []time.Duration) []time.Duration {
	out := make([]time.Duration, len(ds))
	for i, d := range ds {
		out[i] = d / time.Second
	}
	return out
}

func TestSuperviseCleanExitStops(t *testing.T) {
	t.Parallel()
	r := &superviseRig{clock: time.Unix(1000, 0)}
	r.childEnds = []func(context.Context, *superviseRig) error{func(context.Context, *superviseRig) error { return nil }}

	require.NoError(t, supervise(context.Background(), r.options()))

	require.Equal(t, []string{"mcp"}, r.starts)
	require.Empty(t, r.sleeps)
}

func TestSuperviseAnotherEngineStopsWithoutCrashLooping(t *testing.T) {
	t.Parallel()
	r := &superviseRig{clock: time.Unix(1000, 0)}
	r.childEnds = []func(context.Context, *superviseRig) error{func(context.Context, *superviseRig) error { return errAnotherEngine }}

	require.NoError(t, supervise(context.Background(), r.options()))

	require.Len(t, r.starts, 1)
	require.Empty(t, r.stops, "another engine running is not a crash")
}

func TestSuperviseStopSignalStopsChild(t *testing.T) {
	t.Parallel()
	r := &superviseRig{clock: time.Unix(1000, 0)}
	ctx, cancel := context.WithCancel(context.Background())
	running := make(chan struct{})
	childCtxDone := make(chan struct{})
	r.childEnds = []func(context.Context, *superviseRig) error{func(c context.Context, _ *superviseRig) error {
		close(running)
		<-c.Done()
		close(childCtxDone)
		return errors.New("signal: terminated")
	}}
	done := make(chan error, 1)
	go func() { done <- supervise(ctx, r.options()) }()
	<-running
	cancel()

	require.NoError(t, <-done)
	<-childCtxDone
	require.Len(t, r.starts, 1)
	require.Empty(t, r.sleeps)
	require.Empty(t, r.stops)
}

func TestSuperviseSecondInstanceExits(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bsup") // short: macOS bounds socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "engine.json")
	raw := `{"socketDir":"` + filepath.Join(dir, "run") + `","stateDir":"` + filepath.Join(dir, "state") + `","mode":"SAME_USER",` +
		`"agents":[{"name":"bot","osUser":"someone","store":{"kind":"POSTGRES","credentialFile":"` + filepath.Join(dir, "bot.url") + `"}}]}`
	require.NoError(t, config.WriteFile(cfgPath, []byte(raw)))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "run"), 0o700))
	release, err := config.LockFile(filepath.Join(dir, "run", superviseLock))
	require.NoError(t, err)
	defer release()
	var stderr bytes.Buffer

	code := runSupervise(context.Background(), cfgPath, startedByHand, stdio{in: bytes.NewReader(nil), out: &bytes.Buffer{}, err: &stderr}, osHost{})

	require.Equal(t, exitOK, code, stderr.String())
	require.Contains(t, stderr.String(), "another basalt engine --supervise runs")
}

func TestSuperviseRefusesUser(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := runEngineOn(context.Background(), []string{"--supervise", "--user", "basalt"}, stdio{in: bytes.NewReader(nil), out: &bytes.Buffer{}, err: &stderr}, osHost{})
	require.Equal(t, exitUsage, code)
	require.Contains(t, stderr.String(), "--supervise runs as the engine's own user; drop --user")
}

func TestStartedByRefusesUnknownValue(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := runEngineOn(context.Background(), []string{"--started-by", "cron"}, stdio{in: bytes.NewReader(nil), out: &bytes.Buffer{}, err: &stderr}, osHost{})
	require.Equal(t, exitUsage, code)
}

func TestLastStopIsWrittenAndCleared(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state")
	log := slog.New(slog.DiscardHandler)

	cfg := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(cfg, []byte("cfg-v1\n"), 0o600))
	writeLastStop(dir, "the engine crashed 5 times within 10s", cfg, time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC), log)
	raw, err := os.ReadFile(filepath.Join(dir, lastStopFile))
	require.NoError(t, err)
	want := `{"reason":"the engine crashed 5 times within 10s","at":"2026-11-20T01:02:03Z","engineSha256":"` + laststop.HashEngineJSON(cfg) + `"}`
	require.JSONEq(t, want, string(raw))

	clearLastStop(dir, log)
	_, err = os.Stat(filepath.Join(dir, lastStopFile))
	require.ErrorIs(t, err, os.ErrNotExist)
	clearLastStop(dir, log) // nothing to remove: no error
}

// A stray probe of the engine lock reads as a holder for a moment; only a
// lock held at every look is another engine.
func TestAnotherEngineNeedsEveryLookHeld(t *testing.T) {
	t.Parallel()
	looks := func(seq ...bool) func() bool {
		i := 0
		return func() bool { v := seq[min(i, len(seq)-1)]; i++; return v }
	}
	nap := func(time.Duration) {}
	require.True(t, heldAtEveryLook(looks(true, true, true), nap))
	require.False(t, heldAtEveryLook(looks(true, false, true), nap), "a probe that ended is not an engine")
	require.False(t, heldAtEveryLook(looks(false), nap))
}
