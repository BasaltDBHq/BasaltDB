//go:build unix

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

const testEuid = 1234

type starterRig struct {
	cfg      config.Config
	exe      string
	launches atomic.Int32
	// engineLock is held by the "engine" a launch starts.
	mu    sync.Mutex
	locks []*server.Lock
	args  []string
}

func newStarterRig(t *testing.T) *starterRig {
	t.Helper()
	dir, err := os.MkdirTemp("", "bst") // short: macOS bounds socket paths
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	r := &starterRig{cfg: config.Config{SocketDir: filepath.Join(dir, "run"), StateDir: filepath.Join(dir, "state"), Mode: config.ModeSameUser}}
	r.exe = filepath.Join(dir, "basalt")
	require.NoError(t, os.WriteFile(r.exe, []byte("#!/bin/sh\n"), 0o755))
	t.Cleanup(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, l := range r.locks {
			l.Release()
		}
		os.RemoveAll(dir)
	})
	return r
}

// deps launch an "engine" that takes the engine lock a moment later; a
// launch that fails does not.
func (r *starterRig) deps(owner int, launchErr error) starterDeps {
	return starterDeps{
		owner: func(string) (int, error) { return owner, nil },
		launch: func(exe string, args []string, logFile *os.File) error {
			r.launches.Add(1)
			if launchErr != nil {
				return launchErr
			}
			r.mu.Lock()
			r.args = args
			r.mu.Unlock()
			go func() {
				time.Sleep(100 * time.Millisecond)
				// A probe by the starter holds the lock for a moment: try again,
				// as the supervisor's engine does.
				var l *server.Lock
				for range 100 {
					var err error
					if l, err = server.AcquireLock(engine.LockPath(r.cfg.SocketDir)); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if l == nil {
					return
				}
				r.mu.Lock()
				r.locks = append(r.locks, l)
				r.mu.Unlock()
			}()
			return nil
		},
		wait: 3 * time.Second,
	}
}

func TestEngineStarterNilForServiceConfig(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	r.cfg.Mode = config.ModeService
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
	require.Nil(t, failure)
}

func TestEngineStarterNilWithoutConfig(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", nil, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
}

func TestEngineStarterNilForOtherOwner(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid+1, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
}

func TestEngineStarterNilForRoot(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(0, nil), "/x/engine.json", &r.cfg, 0, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
}

func TestEngineStarterStartsOneEngine(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.NotNil(t, start)

	require.NoError(t, start(context.Background()))

	require.EqualValues(t, 1, r.launches.Load())
	require.Equal(t, []string{"engine", "--supervise", "--config", "/x/engine.json", "--started-by", "mcp"}, r.args)
	require.Empty(t, failure())
	_, up, _ := server.Running(engine.LockPath(r.cfg.SocketDir))
	require.True(t, up, "the start returns once the engine holds its lock")
	fi, err := os.Stat(filepath.Join(r.cfg.StateDir, engineLogName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "the engine log is private")
	// An engine that runs is not started again.
	require.NoError(t, start(context.Background()))
	require.EqualValues(t, 1, r.launches.Load())
}

func TestEngineStarterTwoAtOnce(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, start(context.Background()))
		}()
	}
	wg.Wait()

	require.EqualValues(t, 1, r.launches.Load(), "exactly one engine is started")
}

func TestEngineStarterBinaryGone(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	require.NoError(t, os.Remove(r.exe))
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	err := start(context.Background())

	require.ErrorContains(t, err, "is gone")
	require.EqualValues(t, 0, r.launches.Load())
	require.Contains(t, failure(), "is gone")
	require.Contains(t, failure(), filepath.Join(r.cfg.StateDir, engineLogName), "the log's path is named")
	require.Contains(t, failure(), "basalt mcp could not start the engine: ")
}

// An engine that never takes its lock is reported within the wait, and the
// next call tries again.
func TestEngineStarterTimesOutThenTriesAgain(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	d := r.deps(testEuid, nil)
	d.wait = 200 * time.Millisecond
	d.launch = func(string, []string, *os.File) error { r.launches.Add(1); return nil } // never starts one
	start, failure := newEngineStarter(d, "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	began := time.Now()
	err := start(context.Background())
	require.ErrorContains(t, err, "did not start within")
	require.Less(t, time.Since(began), 3*time.Second)
	require.Contains(t, failure(), "did not start")

	// The next message tries again: nothing is remembered but the text.
	require.Error(t, start(context.Background()))
	require.EqualValues(t, 2, r.launches.Load(), "a failure is not remembered across messages")
}

func TestEngineStarterLaunchFailure(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, failure := newEngineStarter(r.deps(testEuid, os.ErrPermission), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.Error(t, start(context.Background()))
	require.Contains(t, failure(), "permission denied")
}

func TestEngineStarterRecreatesFolders(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	_, err := os.Stat(r.cfg.SocketDir)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, start(context.Background()))

	for _, d := range []string{r.cfg.SocketDir, r.cfg.StateDir} {
		fi, err := os.Stat(d)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), fi.Mode().Perm(), d)
	}
}

// A symlink where the log should be is never followed.
func TestEngineStarterRefusesASymlinkedLog(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	require.NoError(t, os.MkdirAll(r.cfg.StateDir, 0o700))
	target := filepath.Join(filepath.Dir(r.cfg.StateDir), "elsewhere")
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(r.cfg.StateDir, engineLogName)))
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.Error(t, start(context.Background()))
	require.Contains(t, failure(), "open the engine log")
	require.EqualValues(t, 0, r.launches.Load())
}
