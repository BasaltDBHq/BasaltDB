package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// Supervision timing (CONTRACT.md, Plugins, Protocol and Failure).
const (
	// HealthInterval is how often a running entry is asked for health.
	HealthInterval = 30 * time.Second
	// MinBackoff and MaxBackoff bound the wait before an entry that failed
	// is started again; the wait doubles from one to the other.
	MinBackoff = time.Second
	MaxBackoff = 60 * time.Second
	// StopWait bounds stopping one entry: draining its calls, shutdown, its
	// process's own exit and the kill. Every entry stops in parallel, so the
	// engine stops every plugin within StopWait.
	StopWait = 5 * time.Second
	// StartWait bounds starting one entry: its process, its socket and the
	// connection. initialize then has the entry's own timeout.
	StartWait = 30 * time.Second
)

// Parts of StopWait kept back for the steps after draining.
const (
	// shutdownReserve is left after draining for shutdown, the exit and
	// the kill.
	shutdownReserve = 2 * time.Second
	// killReserve is left after shutdown and the wait for the exit, for
	// the kill and the reap.
	killReserve = time.Second
)

// Clock is the time the supervisor waits on: the health interval and the
// restart backoff. Each call keeps its own deadline on the real clock.
type Clock interface {
	// After returns a channel that receives once d has passed.
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock is the clock of the running engine.
func RealClock() Clock { return realClock{} }

// DialFunc starts or connects to an entry's plugin and returns its
// transport. ctx bounds the start. Errors must hold no value a plugin or its
// config gave: the supervisor logs nothing, but the caller may.
type DialFunc func(ctx context.Context, e Entry) (Transport, error)

// Exiter is a transport to a local process: Exited is closed once the
// process has exited. The supervisor uses it to give a plugin that
// answered shutdown the time to exit before its process group is killed.
type Exiter interface {
	Exited() <-chan struct{}
}

// Supervisor runs entries on a Host: it starts each one, registers it
// (initialize), asks for health every HealthInterval, marks it UNAVAILABLE
// and starts it again with a backoff when it fails, and stops it with
// shutdown. Each entry runs on its own: one entry failing or stopping never
// waits on, or changes the state of, another.
type Supervisor struct {
	h     *Host
	dial  DialFunc
	clock Clock
	log   *slog.Logger

	mu   sync.Mutex
	runs map[EntryKey]*entryRun
}

// entryRun is one supervised entry.
type entryRun struct {
	entry  Entry
	cancel context.CancelFunc
	done   chan struct{}

	mu sync.Mutex
	// failure is why the entry is not running, "" when it is or before
	// its first start ended.
	failure FailureClass
}

// NewSupervisor returns a supervisor of entries on h, started with dial.
func NewSupervisor(h *Host, dial DialFunc, clock Clock) *Supervisor {
	if h == nil || dial == nil || clock == nil {
		panic("plugin: a supervisor needs a host, a dial function and a clock")
	}
	return &Supervisor{h: h, dial: dial, clock: clock, log: slog.New(slog.DiscardHandler), runs: map[EntryKey]*entryRun{}}
}

// WithLog logs each start and failure to log: the entry and the failure
// class, nothing a plugin sent. Call it before Run.
func (s *Supervisor) WithLog(log *slog.Logger) *Supervisor {
	s.log = log
	return s
}

// ErrDuplicateEntry: Run was given an entry key twice, or one already
// supervised.
var ErrDuplicateEntry = errors.New("plugin: entry is already supervised")

// Run supervises entries until ctx is done, then stops each one (drain,
// shutdown, close) and returns once all have stopped. An entry that cannot
// start is retried with the backoff; it never stops Run or another entry.
// Run returns an error, starting nothing, only when an entry key repeats.
func (s *Supervisor) Run(ctx context.Context, entries []Entry) error {
	runs := make([]*entryRun, 0, len(entries))
	s.mu.Lock()
	seen := map[EntryKey]bool{}
	for _, e := range entries {
		if seen[e.Key] || s.runs[e.Key] != nil {
			s.mu.Unlock()
			return fmt.Errorf("%w: %s", ErrDuplicateEntry, e.Key)
		}
		seen[e.Key] = true
	}
	for _, e := range entries {
		ectx, cancel := context.WithCancel(ctx)
		r := &entryRun{entry: e, cancel: cancel, done: make(chan struct{})}
		s.runs[e.Key] = r
		runs = append(runs, r)
		go func() {
			defer close(r.done)
			defer s.forget(r)
			defer cancel()
			s.supervise(ectx, r)
		}()
	}
	s.mu.Unlock()
	for _, r := range runs {
		<-r.done
	}
	return nil
}

// Stop stops one supervised entry (drain, shutdown, close) and returns once
// it has stopped; the others run on. An unknown or stopped entry is a
// no-op.
func (s *Supervisor) Stop(k EntryKey) {
	s.mu.Lock()
	r := s.runs[k]
	s.mu.Unlock()
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
}

// Failure is why entry k is not running: the failure class of its last
// start or health check, or "" when it is running or not supervised.
func (s *Supervisor) Failure(k EntryKey) FailureClass {
	s.mu.Lock()
	r := s.runs[k]
	s.mu.Unlock()
	if r == nil {
		return ""
	}
	return r.failureClass()
}

// forget drops a stopped run, so its key may be supervised again.
func (s *Supervisor) forget(r *entryRun) {
	s.mu.Lock()
	if s.runs[r.entry.Key] == r {
		delete(s.runs, r.entry.Key)
	}
	s.mu.Unlock()
}

func (r *entryRun) failureClass() FailureClass {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failure
}

func (r *entryRun) setFailure(c FailureClass) {
	r.mu.Lock()
	r.failure = c
	r.mu.Unlock()
}

// supervise starts r's entry until ctx is done, waiting the backoff
// between starts. The backoff starts again from MinBackoff once the entry
// passed a health check.
func (s *Supervisor) supervise(ctx context.Context, r *entryRun) {
	backoff := time.Duration(0)
	for {
		healthy := s.runOnce(ctx, r)
		if ctx.Err() != nil {
			return
		}
		backoff = nextBackoff(backoff, healthy)
		s.log.Warn("plugin is unavailable; starting it again", "plugin", r.entry.Key.String(), "class", string(r.failureClass()), "in", backoff)
		select {
		case <-s.clock.After(backoff):
		case <-ctx.Done():
			return
		}
	}
}

func nextBackoff(prev time.Duration, healthy bool) time.Duration {
	if healthy || prev == 0 {
		return MinBackoff
	}
	return min(prev*2, MaxBackoff)
}

// runOnce starts and registers the entry, then checks its health until it
// fails or ctx is done, and stops it. It reports whether the entry passed a
// health check.
func (s *Supervisor) runOnce(ctx context.Context, r *entryRun) bool {
	k := r.entry.Key
	t, err := s.start(ctx, r.entry)
	if err != nil {
		if ctx.Err() == nil {
			r.setFailure(classOf(err))
		}
		return false
	}
	s.log.Info("plugin started", "plugin", k.String())
	// A local process that exits is noticed at once, not at the next
	// health check; a remote transport has no process (nil never fires).
	var exited <-chan struct{}
	if ex, ok := t.(Exiter); ok {
		exited = ex.Exited()
	}
	healthy := false
	for {
		select {
		case <-s.clock.After(HealthInterval):
		case <-exited:
			r.setFailure(ClassExited)
			s.h.SetState(k, StateUnavailable)
			s.stopEntry(ctx, k, t)
			return healthy
		case <-s.h.Down(k):
			r.setFailure(ClassExited)
			s.stopEntry(ctx, k, t)
			return healthy
		case <-ctx.Done():
			s.stopEntry(ctx, k, t)
			return healthy
		}
		var resp protocol.HealthResponse
		err := s.h.Control(ctx, k, protocol.MethodHealth, protocol.HealthRequest{}, &resp)
		switch {
		case ctx.Err() != nil:
			s.stopEntry(ctx, k, t)
			return healthy
		case err != nil:
			r.setFailure(classOf(err))
			s.stopEntry(ctx, k, t)
			return healthy
		case resp.Status == protocol.HealthReady:
			healthy = true
			r.setFailure("")
			s.h.SetState(k, StateReady)
		default:
			// The process is up and says it is not ready: it takes no hook
			// call, and is asked again at the next interval rather than
			// started again.
			r.setFailure(ClassUnavailable)
			s.h.SetState(k, StateUnavailable)
		}
	}
}

// start dials and registers e. On error nothing is registered or left
// running.
func (s *Supervisor) start(ctx context.Context, e Entry) (Transport, error) {
	sctx, cancel := context.WithTimeout(ctx, StartWait)
	defer cancel()
	t, err := s.dial(sctx, e)
	if err != nil {
		return nil, err
	}
	if err := s.h.Register(sctx, e, t); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

// stopEntry stops a registered entry within StopWait, on a context of its
// own (ctx, the supervisor's, may be done; only its values are kept): it
// drains the entry's calls, sends
// shutdown, gives a local process the rest of the time to exit, then
// unregisters it, which closes the transport and kills the process group.
func (s *Supervisor) stopEntry(ctx context.Context, k EntryKey, t Transport) {
	base := context.WithoutCancel(ctx)
	deadline := time.Now().Add(StopWait)
	drainCtx, cancelDrain := context.WithDeadline(base, deadline.Add(-shutdownReserve))
	_ = s.h.Drain(drainCtx, k)
	cancelDrain()
	exitCtx, cancelExit := context.WithDeadline(base, deadline.Add(-killReserve))
	defer cancelExit()
	if err := s.h.Control(exitCtx, k, protocol.MethodShutdown, protocol.ShutdownRequest{}, nil); err == nil {
		if ex, ok := t.(Exiter); ok {
			select {
			case <-ex.Exited():
			case <-exitCtx.Done():
			}
		}
	}
	s.h.Unregister(k)
}

// classOf is err's failure class: a CallError's, a transport's, else
// UNAVAILABLE (a plugin that could not be started or reached).
func classOf(err error) FailureClass {
	var ce *CallError
	if errors.As(err, &ce) {
		return ce.Class
	}
	var c Classed
	if errors.As(err, &c) {
		return c.FailureClass()
	}
	return ClassUnavailable
}
