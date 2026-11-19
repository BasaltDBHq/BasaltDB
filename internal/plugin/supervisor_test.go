package plugin

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// fakeClock records every wait the supervisor asks for; a test fires them
// in order. Nothing waits on real time.
type fakeClock struct{ waits chan fakeWait }

type fakeWait struct {
	d    time.Duration
	fire chan time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{waits: make(chan fakeWait, 64)} }

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.waits <- fakeWait{d: d, fire: ch}
	return ch
}

// next is the next wait asked for; it must be d.
func (c *fakeClock) next(t *testing.T, d time.Duration) fakeWait {
	t.Helper()
	select {
	case w := <-c.waits:
		require.Equal(t, d, w.d)
		return w
	case <-time.After(5 * time.Second):
		t.Fatalf("no wait of %s asked for", d)
		return fakeWait{}
	}
}

// proc is a fake local plugin process behind a transport: it answers
// initialize from its manifest, health with its status and shutdown by
// exiting. Every call is logged in order, with "close" for Close.
type proc struct {
	m      Manifest
	exited chan struct{}
	once   sync.Once
	health atomic.Value // string
	// hook runs for a hook call; nil answers at once.
	hook func(ctx context.Context) error
	// hangShutdown never answers shutdown.
	hangShutdown bool
	// badInit answers initialize with other hooks.
	badInit bool

	mu  sync.Mutex
	log []string
}

func newProc(m Manifest) *proc {
	p := &proc{m: m, exited: make(chan struct{})}
	p.health.Store(protocol.HealthReady)
	return p
}

func (p *proc) record(s string) {
	p.mu.Lock()
	p.log = append(p.log, s)
	p.mu.Unlock()
}

func (p *proc) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.log...)
}

func (p *proc) kill() { p.once.Do(func() { close(p.exited) }) }

func (p *proc) dead() bool {
	select {
	case <-p.exited:
		return true
	default:
		return false
	}
}

func (p *proc) Call(ctx context.Context, method string, _, result any) error {
	if p.dead() {
		return Fail(ClassExited)
	}
	switch method {
	case protocol.MethodInitialize:
		r := goodInit(p.m)
		if p.badInit {
			r.Hooks = map[string]protocol.HookDecl{string(HookFeedObserve): {Contract: "feed/1"}}
		}
		*result.(*protocol.InitializeResponse) = *r
	case protocol.MethodHealth:
		*result.(*protocol.HealthResponse) = protocol.HealthResponse{Status: p.health.Load().(string)}
	case protocol.MethodShutdown:
		p.record(method)
		if p.hangShutdown {
			<-ctx.Done()
			return ctx.Err()
		}
		p.kill()
		return nil
	default:
		var err error
		if p.hook != nil {
			err = p.hook(ctx)
		}
		p.record(method)
		return err
	}
	p.record(method)
	return nil
}

func (p *proc) Close() error {
	p.record("close")
	p.kill()
	return nil
}

func (p *proc) Exited() <-chan struct{} { return p.exited }

// dialer hands out a new proc per start, or fails while failing is set.
type dialer struct {
	mu      sync.Mutex
	procs   map[EntryKey][]*proc
	failing atomic.Bool
	setup   func(k EntryKey, p *proc)
}

func newDialer() *dialer { return &dialer{procs: map[EntryKey][]*proc{}} }

func (d *dialer) dial(_ context.Context, e Entry) (Transport, error) {
	if d.failing.Load() {
		return nil, errors.New("its command could not be started")
	}
	p := newProc(e.Manifest)
	if d.setup != nil {
		d.setup(e.Key, p)
	}
	d.mu.Lock()
	d.procs[e.Key] = append(d.procs[e.Key], p)
	d.mu.Unlock()
	return p, nil
}

func (d *dialer) last(k EntryKey) *proc {
	d.mu.Lock()
	defer d.mu.Unlock()
	ps := d.procs[k]
	if len(ps) == 0 {
		return nil
	}
	return ps[len(ps)-1]
}

func (d *dialer) starts(k EntryKey) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.procs[k])
}

// runSupervisor runs entries until the test ends and returns a stop that
// ends Run and waits for it.
func runSupervisor(t *testing.T, h *Host, d *dialer, c Clock, entries ...Entry) (*Supervisor, func()) {
	t.Helper()
	s := NewSupervisor(h, d.dial, c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, entries) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			require.NoError(t, <-done)
		})
	}
	t.Cleanup(stop)
	return s, stop
}

func waitReady(t *testing.T, h *Host, k EntryKey) {
	t.Helper()
	require.Eventually(t, func() bool { return h.State(k) == StateReady }, 5*time.Second, time.Millisecond, "%s never READY", k)
}

// A killed plugin is UNAVAILABLE until it is started again, and the
// restarts back off from 1 s, doubling, to 60 s; a start that passed a
// health check resets the backoff.
func TestKilledPluginRestarts(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	e := entry("acme", "default", "a")
	s, _ := runSupervisor(t, h, d, c, e)

	c.next(t, HealthInterval)
	waitReady(t, h, e.Key)
	first := d.last(e.Key)

	d.failing.Store(true)
	first.kill()
	w := c.next(t, MinBackoff)
	require.Equal(t, StateUnavailable, h.State(e.Key), "UNAVAILABLE while it is down")
	require.Equal(t, ClassExited, s.Failure(e.Key))
	err := h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil)
	assertClass(t, err, ClassUnavailable)

	for _, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, MaxBackoff, MaxBackoff} {
		w.fire <- time.Now()
		w = c.next(t, want)
		require.Equal(t, StateUnavailable, h.State(e.Key))
		require.Equal(t, ClassUnavailable, s.Failure(e.Key), "a start that fails is UNAVAILABLE")
	}
	require.Equal(t, 1, d.starts(e.Key), "no process while the start fails")

	d.failing.Store(false)
	w.fire <- time.Now()
	w = c.next(t, HealthInterval)
	waitReady(t, h, e.Key)
	require.Equal(t, 2, d.starts(e.Key))
	second := d.last(e.Key)
	require.NotSame(t, first, second)

	w.fire <- time.Now()
	c.next(t, HealthInterval)
	require.Empty(t, s.Failure(e.Key))
	second.kill()
	c.next(t, MinBackoff)
	require.Equal(t, StateUnavailable, h.State(e.Key))
}

// A health answer of NOT_READY makes the entry UNAVAILABLE without a
// restart; READY again makes it READY.
func TestNotReadyIsUnavailable(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	e := entry("acme", "default", "a")
	runSupervisor(t, h, d, c, e)
	w := c.next(t, HealthInterval)
	p := d.last(e.Key)
	p.health.Store(protocol.HealthNotReady)
	w.fire <- time.Now()
	w = c.next(t, HealthInterval)
	require.Equal(t, StateUnavailable, h.State(e.Key))
	p.health.Store(protocol.HealthReady)
	w.fire <- time.Now()
	c.next(t, HealthInterval)
	require.Equal(t, StateReady, h.State(e.Key))
	require.Equal(t, 1, d.starts(e.Key))
}

// Two instances of one plugin share nothing: each has its own process, and
// stopping or killing client_x leaves default READY and untouched.
func TestSupervisedInstancesAreSeparate(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	def, cx := entry("acme", "default", "a"), entry("acme", "client_x", "b")
	s, _ := runSupervisor(t, h, d, c, def, cx)
	waitReady(t, h, def.Key)
	waitReady(t, h, cx.Key)
	pd, pc := d.last(def.Key), d.last(cx.Key)
	require.NotSame(t, pd, pc)

	pc.kill()
	require.Eventually(t, func() bool { return h.State(cx.Key) == StateUnavailable }, 5*time.Second, time.Millisecond)
	require.Equal(t, StateReady, h.State(def.Key))

	s.Stop(cx.Key)
	require.Equal(t, StateReady, h.State(def.Key))
	require.NoError(t, h.Call(context.Background(), def.Key, []string{"a"}, "detect", nil, nil))
	require.False(t, pd.dead(), "default's process runs on")
	require.NotContains(t, pd.calls(), protocol.MethodShutdown)
	err := h.Call(context.Background(), cx.Key, []string{"b"}, "detect", nil, nil)
	assertClass(t, err, ClassUnavailable)
	// Each instance serves only its own agents.
	require.ErrorIs(t, h.Call(context.Background(), def.Key, []string{"b"}, "detect", nil, nil), ErrAgentNotListed)
}

// Stopping drains first: a call in flight finishes, a new call is refused,
// then shutdown is sent, then the transport is closed.
func TestDrainBeforeUnregister(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	e := entry("acme", "default", "a")
	e.Timeout = 5 * time.Second
	started := make(chan struct{})
	release := make(chan struct{})
	d.setup = func(_ EntryKey, p *proc) {
		p.hook = func(context.Context) error {
			close(started)
			<-release
			return nil
		}
	}
	s, _ := runSupervisor(t, h, d, c, e)
	waitReady(t, h, e.Key)
	callErr := make(chan error, 1)
	go func() { callErr <- h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil) }()
	<-started

	stopped := make(chan struct{})
	go func() { s.Stop(e.Key); close(stopped) }()
	require.Eventually(t, func() bool { return h.State(e.Key) == StateUnavailable }, 5*time.Second, time.Millisecond)
	assertClass(t, h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil), ClassUnavailable)
	p := d.last(e.Key)
	require.NotContains(t, p.calls(), protocol.MethodShutdown, "no shutdown while a call is in flight")
	close(release)
	require.NoError(t, <-callErr, "the call in flight finished")
	<-stopped
	require.Equal(t, []string{protocol.MethodInitialize, "detect", protocol.MethodShutdown, "close"}, p.calls())
}

// The engine stops every plugin within 5 s, even with a call that would
// run for a minute and a plugin that never answers shutdown.
func TestShutdownWithin5s(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	busy, deaf, fine := entry("busy", "default", "a"), entry("deaf", "default", "a"), entry("fine", "default", "a")
	for _, e := range []*Entry{&busy, &deaf, &fine} {
		e.Timeout = MaxTimeout
	}
	d.setup = func(k EntryKey, p *proc) {
		switch k.Name {
		case "busy":
			// Runs until its deadline (a minute) or until the process is
			// killed, as a real transport's call does.
			p.hook = func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-p.exited:
					return Fail(ClassExited)
				}
			}
		case "deaf":
			p.hangShutdown = true
		}
	}
	_, stop := runSupervisor(t, h, d, c, busy, deaf, fine)
	for _, k := range []EntryKey{busy.Key, deaf.Key, fine.Key} {
		waitReady(t, h, k)
	}
	for range protocol.MaxInFlight {
		go func() { _ = h.Call(context.Background(), busy.Key, []string{"a"}, "detect", nil, nil) }()
	}
	require.Eventually(t, func() bool {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return len(h.entries[busy.Key].sem) == protocol.MaxInFlight
	}, 5*time.Second, time.Millisecond)

	start := time.Now()
	stop()
	require.Less(t, time.Since(start), StopWait, "every plugin stopped within 5 s")
	for _, k := range []EntryKey{busy.Key, deaf.Key, fine.Key} {
		p := d.last(k)
		require.True(t, p.dead(), "%s stopped", k)
		require.Contains(t, p.calls(), "close")
		require.Equal(t, StateUnavailable, h.State(k))
	}
	require.Equal(t, []string{protocol.MethodInitialize, protocol.MethodShutdown, "close"}, d.last(fine.Key).calls())
}

// holdHooks starts protocol.MaxInFlight hook calls on k that run until
// their deadline or the process is killed, and waits until all hold a slot.
func holdHooks(t *testing.T, h *Host, d *dialer, k EntryKey) {
	t.Helper()
	p := d.last(k)
	// Set before any hook call starts (the go statements below order it).
	p.hook = func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.exited:
			return Fail(ClassExited)
		}
	}
	for range protocol.MaxInFlight {
		go func() { _ = h.Call(context.Background(), k, []string{"a"}, "detect", nil, nil) }()
	}
	require.Eventually(t, func() bool {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return len(h.entries[k].sem) == protocol.MaxInFlight
	}, 5*time.Second, time.Millisecond)
}

// A plugin busy with four hook calls still passes its health check: it
// stays READY and is not started again.
func TestHealthGetsThroughFourHookCalls(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	e := entry("acme", "default", "a")
	e.Timeout = MaxTimeout
	s, _ := runSupervisor(t, h, d, c, e)
	w := c.next(t, HealthInterval)
	waitReady(t, h, e.Key)
	holdHooks(t, h, d, e.Key)

	w.fire <- time.Now()
	c.next(t, HealthInterval)
	require.Equal(t, StateReady, h.State(e.Key))
	require.Empty(t, s.Failure(e.Key))
	require.Equal(t, 1, d.starts(e.Key), "not started again")
	require.False(t, d.last(e.Key).dead())
}

// shutdown reaches a plugin whose four hook calls never finish, within the
// stop window, before its process is killed.
func TestShutdownGetsThroughFourHookCalls(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	e := entry("acme", "default", "a")
	e.Timeout = MaxTimeout
	_, stop := runSupervisor(t, h, d, c, e)
	waitReady(t, h, e.Key)
	holdHooks(t, h, d, e.Key)
	p := d.last(e.Key)

	start := time.Now()
	stop()
	require.Less(t, time.Since(start), StopWait)
	calls := p.calls()
	i := slices.Index(calls, protocol.MethodShutdown)
	require.GreaterOrEqual(t, i, 0, "shutdown was sent: %v", calls)
	require.Less(t, i, slices.Index(calls, "close"), "shutdown before the process was killed: %v", calls)
}

// A plugin whose initialize answers other hooks than its manifest's is
// refused: closed, UNAVAILABLE with BAD_RESPONSE, and tried again later.
func TestSupervisorRefusesInitializeHookMismatch(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	d.setup = func(_ EntryKey, p *proc) { p.badInit = true }
	e := entry("acme", "default", "a")
	s, _ := runSupervisor(t, h, d, c, e)
	w := c.next(t, MinBackoff)
	require.Equal(t, StateUnavailable, h.State(e.Key))
	require.Equal(t, ClassBadResponse, s.Failure(e.Key))
	p := d.last(e.Key)
	require.Equal(t, []string{protocol.MethodInitialize, "close"}, p.calls(), "refused and closed, nothing else sent")
	w.fire <- time.Now()
	c.next(t, 2*MinBackoff)
	require.Equal(t, 2, d.starts(e.Key))
}

func TestRunRefusesARepeatedEntry(t *testing.T) {
	t.Parallel()
	d := newDialer()
	s := NewSupervisor(NewHost(), d.dial, newFakeClock())
	e := entry("acme", "default", "a")
	require.ErrorIs(t, s.Run(context.Background(), []Entry{e, e}), ErrDuplicateEntry)
	require.Zero(t, d.starts(e.Key))
}

// An entry added while the supervisor runs is started and stopped like the
// ones it started with; a stopped key can be added again (a replaced
// entry), a supervised one cannot, and once Run's context ends Add starts
// nothing and Run waits for the added entries too.
func TestAddWhileRunning(t *testing.T) {
	t.Parallel()
	h, d, c := NewHost(), newDialer(), newFakeClock()
	def := entry("acme", "default", "a")
	s, stop := runSupervisor(t, h, d, c, def)
	waitReady(t, h, def.Key)

	cx := entry("acme", "client_x", "b")
	require.NoError(t, s.Add(cx))
	waitReady(t, h, cx.Key)
	require.ErrorIs(t, s.Add(cx), ErrDuplicateEntry)
	require.NoError(t, h.Call(context.Background(), cx.Key, []string{"b"}, "detect", nil, nil))

	first := d.last(cx.Key)
	s.Stop(cx.Key)
	require.True(t, first.dead() || slices.Contains(first.calls(), "close"))
	wider := entry("acme", "client_x", "b")
	wider.Agents = []string{"b", "c"}
	require.NoError(t, s.Add(wider), "a stopped key is added again with its new agents")
	waitReady(t, h, cx.Key)
	require.NoError(t, h.Call(context.Background(), cx.Key, []string{"c"}, "detect", nil, nil))
	require.ElementsMatch(t, []EntryKey{def.Key, cx.Key}, s.Supervised())

	added := d.last(cx.Key)
	stop()
	require.Contains(t, added.calls(), protocol.MethodShutdown, "Run stopped the added entry before it returned")
	require.ErrorIs(t, s.Add(entry("acme", "late", "a")), ErrNotRunning)
	require.Zero(t, d.starts(EntryKey{Name: "acme", Instance: "late"}))
}

func TestAddBeforeStartRefused(t *testing.T) {
	t.Parallel()
	s := NewSupervisor(NewHost(), newDialer().dial, newFakeClock())
	require.ErrorIs(t, s.Add(entry("acme", "default", "a")), ErrNotRunning)
	s.Wait()
}

func TestNextBackoff(t *testing.T) {
	t.Parallel()
	require.Equal(t, MinBackoff, nextBackoff(0, false))
	require.Equal(t, MaxBackoff, nextBackoff(MaxBackoff, false))
	require.Equal(t, MinBackoff, nextBackoff(MaxBackoff, true))
}
