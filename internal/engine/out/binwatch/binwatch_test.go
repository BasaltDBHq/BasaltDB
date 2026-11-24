package binwatch_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/out/binwatch"
)

// fakeSystem serves the identities of a binary as an installer changes it.
type fakeSystem struct {
	mu sync.Mutex
	// growing makes every look see a bigger file: a copy still running.
	growing bool
	id      binwatch.Identity
	statErr error
	// untrusted is the trust error for the binary's current inode.
	untrusted map[uint64]error
	// probeErr is the probe error for the binary's current inode.
	probeErr map[uint64]error
	probes   int
}

func (f *fakeSystem) set(id binwatch.Identity, statErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.id, f.statErr = id, statErr
}

func (f *fakeSystem) Stat(string) (binwatch.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.growing {
		f.id.Size++
	}
	return f.id, f.statErr
}

func (f *fakeSystem) setGrowing(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.growing = on
}

func (f *fakeSystem) Trusted(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.untrusted[f.id.Ino]
}

func (f *fakeSystem) Probe(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return "0.0.2", f.probeErr[f.id.Ino]
}

func (f *fakeSystem) probed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probes
}

const tick = 5 * time.Millisecond

func watcher(t *testing.T, sys *fakeSystem, asRoot bool) *binwatch.Watcher {
	t.Helper()
	w, err := binwatch.New("/usr/local/bin/basalt", "/usr/local/bin/basalt", sys, asRoot, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return w.WithInterval(tick)
}

// waitResult runs Wait for up to d and returns its error, or
// context.DeadlineExceeded when it did not return.
func waitResult(w *binwatch.Watcher, d time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return w.Wait(ctx)
}

func TestANewBinaryIsUsedOnceItStopsChanging(t *testing.T) {
	t.Parallel()
	sys := &fakeSystem{id: binwatch.Identity{Ino: 1, Size: 10}}
	w := watcher(t, sys, false)
	require.ErrorIs(t, waitResult(w, 20*tick), context.DeadlineExceeded, "the running binary is not new")

	sys.set(binwatch.Identity{Ino: 2, Size: 20}, nil)
	require.NoError(t, waitResult(w, time.Second))
	require.Equal(t, 1, sys.probed())

	// The file restarted onto is the base now: no second restart for it.
	require.ErrorIs(t, waitResult(w, 20*tick), context.DeadlineExceeded)
}

func TestABinaryStillBeingWrittenIsNotUsed(t *testing.T) {
	t.Parallel()
	sys := &fakeSystem{id: binwatch.Identity{Ino: 1, Size: 10}}
	w := watcher(t, sys, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Wait(ctx) }()
	// A copy in place: the size grows on every look.
	sys.setGrowing(true)
	time.Sleep(30 * tick)
	require.Zero(t, sys.probed(), "never run while it changes")
	sys.setGrowing(false)
	select {
	case err := <-done:
		require.NoError(t, err, "used once the copy is done")
	case <-time.After(time.Second):
		t.Fatal("the finished binary was not used")
	}
}

func TestAMissingBinaryIsWaitedFor(t *testing.T) {
	t.Parallel()
	sys := &fakeSystem{id: binwatch.Identity{Ino: 1}}
	w := watcher(t, sys, false)
	sys.set(binwatch.Identity{}, errors.New("no such file"))
	require.ErrorIs(t, waitResult(w, 20*tick), context.DeadlineExceeded)
	require.Zero(t, sys.probed())
}

func TestANewBinaryThatDoesNotRunIsSkippedUntilItChanges(t *testing.T) {
	t.Parallel()
	sys := &fakeSystem{id: binwatch.Identity{Ino: 1}, probeErr: map[uint64]error{2: errors.New("exec format error")}}
	w := watcher(t, sys, false)
	sys.set(binwatch.Identity{Ino: 2}, nil)
	require.ErrorIs(t, waitResult(w, 40*tick), context.DeadlineExceeded)
	require.Equal(t, 1, sys.probed(), "tried once, not on every look")

	sys.set(binwatch.Identity{Ino: 3}, nil)
	require.NoError(t, waitResult(w, time.Second))
}

func TestARestartIsNeverOntoALessProtectedBinary(t *testing.T) {
	t.Parallel()
	open := errors.New("is writable by group or others")
	sys := &fakeSystem{id: binwatch.Identity{Ino: 1}, untrusted: map[uint64]error{2: open}}
	w := watcher(t, sys, false)
	sys.set(binwatch.Identity{Ino: 2}, nil)
	require.ErrorIs(t, waitResult(w, 40*tick), context.DeadlineExceeded)
	require.Zero(t, sys.probed(), "an unprotected binary is not even run")

	// As root, the check applies whatever the first binary was.
	sys = &fakeSystem{id: binwatch.Identity{Ino: 1}, untrusted: map[uint64]error{1: open, 2: open}}
	w = watcher(t, sys, true)
	sys.set(binwatch.Identity{Ino: 2}, nil)
	require.ErrorIs(t, waitResult(w, 40*tick), context.DeadlineExceeded)
	require.Zero(t, sys.probed())

	// A binary that was never protected (the engine user's own build) is
	// not held to the check.
	sys = &fakeSystem{id: binwatch.Identity{Ino: 1}, untrusted: map[uint64]error{1: open, 2: open}}
	w = watcher(t, sys, false)
	sys.set(binwatch.Identity{Ino: 2}, nil)
	require.NoError(t, waitResult(w, time.Second))
}

func TestNewNeedsAnAbsoluteReadablePath(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	_, err := binwatch.New("basalt", "/x/basalt", &fakeSystem{}, false, log)
	require.ErrorContains(t, err, "must be absolute")
	_, err = binwatch.New("/x/basalt", "/x/basalt", &fakeSystem{statErr: errors.New("gone")}, false, log)
	require.ErrorContains(t, err, "gone")
}

func TestExecPathIsTheStartPathWhenItIsTheRunningBinary(t *testing.T) {
	t.Parallel()
	ids := map[string]binwatch.Identity{
		"/opt/homebrew/bin/basalt":                 {Ino: 7},
		"/opt/homebrew/Cellar/basalt/1/bin/basalt": {Ino: 7},
		"/usr/bin/basalt":                          {Ino: 9},
	}
	stat := func(p string) (binwatch.Identity, error) {
		id, ok := ids[p]
		if !ok {
			return binwatch.Identity{}, errors.New("no such file")
		}
		return id, nil
	}
	exe := func() (string, error) { return "/opt/homebrew/Cellar/basalt/1/bin/basalt", nil }
	onPath := func(p string) func(string) (string, error) {
		return func(string) (string, error) { return p, nil }
	}
	notOnPath := func(string) (string, error) { return "", errors.New("not found") }

	for _, tc := range []struct {
		name, arg0 string
		look       func(string) (string, error)
		want       string
	}{
		{"found on PATH: the symlink, so a new version is followed", "basalt", onPath("/opt/homebrew/bin/basalt"), "/opt/homebrew/bin/basalt"},
		{"absolute start path", "/opt/homebrew/bin/basalt", notOnPath, "/opt/homebrew/bin/basalt"},
		{"PATH finds another basalt", "basalt", onPath("/usr/bin/basalt"), "/opt/homebrew/Cellar/basalt/1/bin/basalt"},
		{"not on PATH", "basalt", notOnPath, "/opt/homebrew/Cellar/basalt/1/bin/basalt"},
		{"argv[0] names nothing", "/nowhere/basalt", notOnPath, "/opt/homebrew/Cellar/basalt/1/bin/basalt"},
	} {
		got, err := binwatch.ExecPath(tc.arg0, tc.look, exe, stat)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}

// pathSystem judges trust by path: only the paths in protected pass.
type pathSystem struct {
	fakeSystem
	protected map[string]bool
}

func (p *pathSystem) Trusted(path string) error {
	if p.protected[path] {
		return nil
	}
	return errors.New("is writable by group or others")
}

func TestAProtectedBinaryIsNeverWatchedThroughAnUnprotectedPath(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	// Started through /app/basalt, a link in a directory a build user owns,
	// to the root-owned /usr/local/bin/basalt.
	sys := &pathSystem{fakeSystem: fakeSystem{id: binwatch.Identity{Ino: 1}}, protected: map[string]bool{"/usr/local/bin/basalt": true}}
	w, err := binwatch.New("/app/basalt", "/usr/local/bin/basalt", sys, false, log)
	require.NoError(t, err)
	require.Equal(t, "/usr/local/bin/basalt", w.Path(), "the protected running binary's own path")
	require.NoError(t, w.Recheck())

	// An unprotected start binary is not held to the check.
	sys = &pathSystem{fakeSystem: fakeSystem{id: binwatch.Identity{Ino: 1}}}
	w, err = binwatch.New("/home/me/bin/basalt", "/home/me/bin/basalt", sys, false, log)
	require.NoError(t, err)
	require.Equal(t, "/home/me/bin/basalt", w.Path())
	require.NoError(t, w.Recheck())

	// As root the check applies to the new binary whatever the first was.
	w, err = binwatch.New("/home/me/bin/basalt", "/home/me/bin/basalt", sys, true, log)
	require.NoError(t, err)
	require.Error(t, w.Recheck())
}
