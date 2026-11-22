//go:build unix

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/httpserver"
	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/app/laststop"
	"github.com/basaltdbhq/basaltdb/internal/config"
)

const testEuid = 1234

type starterRig struct {
	cfg      config.Config
	exe      string
	launches atomic.Int32
	// engineLock is held by the "engine" a launch starts.
	mu    sync.Mutex
	locks []*httpserver.Lock
	args  []string
	// listeners are the fake engines' sockets.
	listeners []net.Listener
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
		for _, ln := range r.listeners {
			ln.Close()
		}
		os.RemoveAll(dir)
	})
	return r
}

// deps launch an "engine" that takes the engine lock a moment later; a
// launch that fails does not.
func (r *starterRig) socket() string { return filepath.Join(r.cfg.SocketDir, "bot.sock") }

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
				// A probe by someone else holds the lock for a moment: try again.
				var l *httpserver.Lock
				for range 100 {
					var err error
					if l, err = httpserver.AcquireLock(app.LockPath(r.cfg.SocketDir)); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if l == nil {
					return
				}
				ln, err := net.Listen("unix", r.socket())
				r.mu.Lock()
				r.locks = append(r.locks, l)
				if err == nil {
					r.listeners = append(r.listeners, ln)
				}
				r.mu.Unlock()
				for err == nil {
					c, aerr := ln.Accept()
					if aerr != nil {
						return
					}
					c.Close()
				}
			}()
			return nil
		},
		answers: func(socket string) bool {
			c, err := net.Dial("unix", socket)
			if err != nil {
				return false
			}
			c.Close()
			return true
		},
		wait: 3 * time.Second,
	}
}

func TestEngineStarterNilForServiceConfig(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	r.cfg.Mode = config.ModeService
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
	require.Nil(t, failure)
}

func TestEngineStarterNilWithoutConfig(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), nil, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
}

func TestEngineStarterNilForOtherOwner(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid+1, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
}

func TestEngineStarterNilForRoot(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(0, nil), "/x/engine.json", r.socket(), &r.cfg, 0, r.exe, slog.New(slog.DiscardHandler))
	require.Nil(t, start)
}

func TestEngineStarterStartsOneEngine(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.NotNil(t, start)

	require.NoError(t, start(context.Background()))

	require.EqualValues(t, 1, r.launches.Load())
	require.Equal(t, []string{"engine", "--supervise", "--config", "/x/engine.json", "--started-by", "mcp"}, r.args)
	require.Empty(t, failure())
	require.True(t, r.deps(testEuid, nil).answers(r.socket()), "the start returns once the agent's socket answers")
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
	start, _ := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
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
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

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
	start, failure := newEngineStarter(d, "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	began := time.Now()
	err := start(context.Background())
	require.ErrorContains(t, err, "did not answer on")
	require.Less(t, time.Since(began), 3*time.Second)
	require.Contains(t, failure(), "did not answer on")

	// The next message tries again: nothing is remembered but the text.
	require.Error(t, start(context.Background()))
	require.EqualValues(t, 2, r.launches.Load(), "a failure is not remembered across messages")
}

func TestEngineStarterLaunchFailure(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, failure := newEngineStarter(r.deps(testEuid, os.ErrPermission), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.Error(t, start(context.Background()))
	require.Contains(t, failure(), "permission denied")
}

func TestEngineStarterRecreatesFolders(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	start, _ := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
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
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.Error(t, start(context.Background()))
	require.Contains(t, failure(), "open the engine log")
	require.EqualValues(t, 0, r.launches.Load())
}

// An engine that holds its lock but never serves this socket (an agent
// added after it started) costs one wait; the next calls look once, and
// the reason and the log's path stay in the failure.
func TestEngineStarterEngineRunsButNeverServesThisSocket(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	l, err := httpserver.AcquireLock(app.LockPath(r.cfg.SocketDir))
	require.NoError(t, err)
	t.Cleanup(l.Release)
	d := r.deps(testEuid, nil)
	d.wait = 600 * time.Millisecond
	start, failure := newEngineStarter(d, "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	began := time.Now()
	require.ErrorContains(t, start(context.Background()), "did not answer on")
	require.GreaterOrEqual(t, time.Since(began), 600*time.Millisecond)
	require.Contains(t, failure(), "Its log is "+filepath.Join(r.cfg.StateDir, engineLogName))

	began = time.Now()
	require.Error(t, start(context.Background()))
	require.Less(t, time.Since(began), 200*time.Millisecond, "the next call does not wait again")
	require.EqualValues(t, 0, r.launches.Load(), "an engine that runs is not started again")
	require.NotEmpty(t, failure())

	// The engine goes away: the next call starts one.
	l.Release()
	require.NoError(t, start(context.Background()))
	require.EqualValues(t, 1, r.launches.Load())
}

func writeGiveUp(t *testing.T, stateDir, configPath, reason string, at time.Time) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	rec := laststop.LastStopFileRecord{Reason: reason, At: at.UTC(), EngineSHA256: laststop.HashEngineJSON(configPath)}
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	path := filepath.Join(stateDir, app.LastStopFile)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// After the supervisor gives up, a call in the next minute launches nothing
// and returns at once, using last-stop.json's at, never the file's mtime.
func TestEngineStarterHoldsOffAfterGiveUp(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	cfgPath := filepath.Join(filepath.Dir(r.exe), "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	now := time.Date(2026, 11, 21, 8, 0, 30, 0, time.UTC)
	at := now.Add(-30 * time.Second)
	record := writeGiveUp(t, r.cfg.StateDir, cfgPath, "the engine crashed 5 times within 10s; last: exit status 1", at)
	// A mismatched mtime must not change the hold-off.
	require.NoError(t, os.Chtimes(record, now.Add(2*time.Hour), now.Add(2*time.Hour)))

	d := r.deps(testEuid, nil)
	d.now = func() time.Time { return now }
	start, failure := newEngineStarter(d, cfgPath, r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	began := time.Now()
	err := start(context.Background())
	require.Less(t, time.Since(began), time.Second)
	require.ErrorContains(t, err, "the supervisor gave up at 2026-11-21T08:00:00Z")
	require.ErrorContains(t, err, "the engine crashed 5 times within 10s")
	require.ErrorContains(t, err, "the next try is at 2026-11-21T08:01:00Z")
	require.EqualValues(t, 0, r.launches.Load(), "a hold-off launches nothing")
	require.Empty(t, failure(), "hold-off is not ENGINE_START_FAILED")
}

// After the minute passes, the next call starts a supervisor again.
func TestEngineStarterTriesAgainAfterHoldOff(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	cfgPath := filepath.Join(filepath.Dir(r.exe), "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	now := time.Date(2026, 11, 21, 8, 2, 0, 0, time.UTC)
	writeGiveUp(t, r.cfg.StateDir, cfgPath, "the engine crashed 5 times within 10s; last: exit status 1", now.Add(-2*time.Minute))

	d := r.deps(testEuid, nil)
	d.now = func() time.Time { return now }
	start, _ := newEngineStarter(d, cfgPath, r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.NoError(t, start(context.Background()))
	require.EqualValues(t, 1, r.launches.Load())
}

// Editing engine.json during the hold-off starts a supervisor at once.
func TestEngineStarterHoldOffEndsWhenEngineJSONChanges(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	cfgPath := filepath.Join(filepath.Dir(r.exe), "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	now := time.Date(2026, 11, 21, 8, 0, 30, 0, time.UTC)
	writeGiveUp(t, r.cfg.StateDir, cfgPath, "the engine crashed 5 times within 10s; last: exit status 1", now.Add(-30*time.Second))
	require.NoError(t, os.WriteFile(cfgPath, []byte("v2\n"), 0o600))

	d := r.deps(testEuid, nil)
	d.now = func() time.Time { return now }
	start, _ := newEngineStarter(d, cfgPath, r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.NoError(t, start(context.Background()))
	require.EqualValues(t, 1, r.launches.Load())
}

// A supervisor already starting (or restarting) its engine holds
// supervise.lock before the engine lock is taken: basalt mcp launches
// nothing and waits for the socket.
func TestEngineStarterWaitsWhenSupervisorHoldsLock(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	require.NoError(t, os.MkdirAll(r.cfg.SocketDir, 0o700))
	release, err := config.LockFile(filepath.Join(r.cfg.SocketDir, superviseLock))
	require.NoError(t, err)
	t.Cleanup(release)
	go func() {
		time.Sleep(100 * time.Millisecond)
		ln, err := net.Listen("unix", r.socket())
		if err != nil {
			return
		}
		r.mu.Lock()
		r.listeners = append(r.listeners, ln)
		r.mu.Unlock()
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()
	start, failure := newEngineStarter(r.deps(testEuid, nil), "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))

	require.NoError(t, start(context.Background()))

	require.EqualValues(t, 0, r.launches.Load(), "a supervisor that already runs is not started again")
	require.Empty(t, failure())
}

// Once the supervisor is gone, the next call starts a fresh one.
func TestEngineStarterStartsAfterSupervisorLockIsReleased(t *testing.T) {
	t.Parallel()
	r := newStarterRig(t)
	require.NoError(t, os.MkdirAll(r.cfg.SocketDir, 0o700))
	release, err := config.LockFile(filepath.Join(r.cfg.SocketDir, superviseLock))
	require.NoError(t, err)
	d := r.deps(testEuid, nil)
	d.wait = 200 * time.Millisecond
	start, _ := newEngineStarter(d, "/x/engine.json", r.socket(), &r.cfg, testEuid, r.exe, slog.New(slog.DiscardHandler))
	require.ErrorContains(t, start(context.Background()), "did not answer on")
	require.EqualValues(t, 0, r.launches.Load())

	release()
	require.NoError(t, start(context.Background()))
	require.EqualValues(t, 1, r.launches.Load())
}
