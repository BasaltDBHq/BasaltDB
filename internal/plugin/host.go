package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// State is whether an entry can take calls.
type State string

// The states.
const (
	StateReady       State = "READY"
	StateUnavailable State = "UNAVAILABLE"
)

type slot struct {
	entry Entry
	t     Transport
	// sem caps the hook calls in flight (initialize included, which runs
	// before any hook call). health and shutdown each have a slot of their
	// own outside it, so a plugin busy with hook calls still gets its health
	// check and its shutdown.
	sem      chan struct{}
	health   chan struct{}
	shutdown chan struct{}
	// down is closed the first time a call finds the plugin gone (EXITED
	// or UNAVAILABLE), so the supervisor need not wait for its next health
	// check.
	down     chan struct{}
	downOnce sync.Once

	mu    sync.Mutex
	state State
	// draining: the entry takes no new call (Drain); inflight counts the
	// calls admitted before.
	draining bool
	inflight sync.WaitGroup
}

// Host is the registry of plugin entries and the single place calls go
// through. Entries share nothing: each has its own transport, slots and
// state.
type Host struct {
	mu      sync.RWMutex
	entries map[EntryKey]*slot
}

// NewHost returns an empty host.
func NewHost() *Host { return &Host{entries: map[EntryKey]*slot{}} }

// Register adds an entry over its transport and runs initialize on it,
// within ctx and the entry's timeout. The entry is READY only when the
// plugin answers a protocol the engine offered, with the manifest's name and
// version and exactly the manifest's hooks. On error nothing is registered
// and the caller still owns t.
func (h *Host) Register(ctx context.Context, e Entry, t Transport) error {
	e, err := normalize(e)
	if err != nil {
		return err
	}
	h.mu.RLock()
	_, dup := h.entries[e.Key]
	h.mu.RUnlock()
	if dup {
		return fmt.Errorf("plugin %s: already registered", e.Key)
	}

	req := protocol.InitializeRequest{
		Protocols: []string{protocol.Version1},
		Hooks:     hookNames(e.Manifest),
		Config:    protocol.RawObject(e.Config),
		Limits: protocol.Limits{
			MaxMessageBytes: protocol.MaxMessageBytes,
			MaxInFlight:     protocol.MaxInFlight,
			TimeoutMs:       int(e.Timeout / time.Millisecond),
		},
	}
	s := &slot{
		entry: e, t: t,
		sem:    make(chan struct{}, protocol.MaxInFlight),
		health: make(chan struct{}, 1), shutdown: make(chan struct{}, 1),
		down: make(chan struct{}), state: StateUnavailable,
	}
	var resp protocol.InitializeResponse
	if err := s.do(ctx, s.sem, protocol.MethodInitialize, req, &resp); err != nil {
		return err
	}
	if !initializeMatches(e, resp) {
		return &CallError{Entry: e.Key, Class: ClassBadResponse}
	}
	s.state = StateReady

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, dup := h.entries[e.Key]; dup {
		return fmt.Errorf("plugin %s: already registered", e.Key)
	}
	h.entries[e.Key] = s
	return nil
}

// Unregister removes an entry and closes its transport. Calls in flight fail;
// Drain first to let them finish.
func (h *Host) Unregister(k EntryKey) {
	h.mu.Lock()
	s := h.entries[k]
	delete(h.entries, k)
	h.mu.Unlock()
	if s != nil {
		_ = s.t.Close()
	}
}

// Call sends a hook call to an entry on behalf of the named agents. Every
// agent must be listed on the entry, or the call fails with ErrAgentNotListed
// before anything is sent; so does a call naming no agent. A lifecycle method
// (initialize, health, shutdown) goes through Register and Control instead, and
// is refused with a plain error before anything is sent. The entry's timeout is
// the deadline for the whole call, including the wait for a free slot (at most
// four hook calls are in flight per entry; health and shutdown are not counted).
// Other failures are *CallError or ErrAgentNotListed.
func (h *Host) Call(ctx context.Context, k EntryKey, agents []string, method string, params, result any) error {
	switch method {
	case protocol.MethodInitialize, protocol.MethodHealth, protocol.MethodShutdown:
		return fmt.Errorf("plugin %s: %q is a lifecycle method, not a hook call", k, method)
	}
	s := h.lookup(k)
	if s == nil {
		return &CallError{Entry: k, Class: ClassUnavailable}
	}
	if len(agents) == 0 {
		return ErrAgentNotListed
	}
	for _, a := range agents {
		if !s.lists(a) {
			return ErrAgentNotListed
		}
	}
	if !s.admit() {
		return &CallError{Entry: k, Class: ClassUnavailable}
	}
	defer s.inflight.Done()
	return s.do(ctx, s.sem, method, params, result)
}

// Drain stops an entry from taking new calls and marks it UNAVAILABLE, then
// waits until the calls already admitted have finished, or ctx is done. An
// unknown entry is drained at once. Lifecycle calls (Control) still work, so
// shutdown can follow.
func (h *Host) Drain(ctx context.Context, k EntryKey) error {
	s := h.lookup(k)
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.draining, s.state = true, StateUnavailable
	s.mu.Unlock()
	// No call is admitted once draining is set, so Wait never races an Add.
	idle := make(chan struct{})
	go func() { s.inflight.Wait(); close(idle) }()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Down is closed the first time a call to the entry finds the plugin gone.
// For an unknown entry it is closed already.
func (h *Host) Down(k EntryKey) <-chan struct{} {
	if s := h.lookup(k); s != nil {
		return s.down
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

// Control sends a lifecycle call (health, shutdown) to an entry. It names no
// agent and carries no hook data. It does not wait behind hook calls: each of
// the two methods has one slot of its own, outside the cap of four.
func (h *Host) Control(ctx context.Context, k EntryKey, method string, params, result any) error {
	s := h.lookup(k)
	if s == nil {
		return &CallError{Entry: k, Class: ClassUnavailable}
	}
	var sem chan struct{}
	switch method {
	case protocol.MethodHealth:
		sem = s.health
	case protocol.MethodShutdown:
		sem = s.shutdown
	default:
		return fmt.Errorf("plugin %s: %q is not a lifecycle method", k, method)
	}
	return s.do(ctx, sem, method, params, result)
}

// State reports whether the entry can take calls. An unknown entry is
// UNAVAILABLE.
func (h *Host) State(k EntryKey) State {
	if s := h.lookup(k); s != nil {
		return s.State()
	}
	return StateUnavailable
}

// SetState lets the supervisor mark an entry READY or UNAVAILABLE. A
// draining entry stays UNAVAILABLE.
func (h *Host) SetState(k EntryKey, st State) {
	if s := h.lookup(k); s != nil {
		s.setState(st)
	}
}

func (h *Host) lookup(k EntryKey) *slot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.entries[k]
}

func (s *slot) lists(agent string) bool {
	for _, a := range s.entry.Agents {
		if a == agent {
			return true
		}
	}
	return false
}

func (s *slot) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *slot) setState(st State) {
	s.mu.Lock()
	if !s.draining {
		s.state = st
	}
	s.mu.Unlock()
}

// admit counts a hook call in flight when the entry is READY and not
// draining. The check and the count are one step, so Drain never misses a
// call that passed it.
func (s *slot) admit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateReady || s.draining {
		return false
	}
	s.inflight.Add(1)
	return true
}

func (s *slot) markDown() {
	s.setState(StateUnavailable)
	s.downOnce.Do(func() { close(s.down) })
}

// do runs one call under the entry's deadline and a free slot of sem, and
// turns every failure into a CallError.
func (s *slot) do(ctx context.Context, sem chan struct{}, method string, params, result any) error {
	ctx, cancel := context.WithTimeout(ctx, s.entry.Timeout)
	defer cancel()

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return s.ctxErr(ctx)
	}
	if err := ctx.Err(); err != nil {
		return s.ctxErr(ctx)
	}

	err := s.t.Call(ctx, method, params, result)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return s.ctxErr(ctx)
	}
	class := ClassUnavailable
	var c Classed
	if errors.As(err, &c) {
		class = c.FailureClass()
	}
	if class == ClassExited || class == ClassUnavailable {
		s.markDown()
	}
	return &CallError{Entry: s.entry.Key, Class: class}
}

// ctxErr maps a finished context: the entry's deadline is TIMEOUT; a caller
// that gave up gets its own context error back, which holds no payload.
func (s *slot) ctxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &CallError{Entry: s.entry.Key, Class: ClassTimeout}
	}
	return ctx.Err()
}

func normalize(e Entry) (Entry, error) {
	if e.Key.Name == "" || e.Key.Instance == "" {
		return e, errors.New("plugin: entry needs a name and an instance")
	}
	if e.Manifest.Name != e.Key.Name {
		return e, fmt.Errorf("plugin %s: manifest names a different plugin", e.Key)
	}
	if len(e.Agents) == 0 {
		return e, fmt.Errorf("plugin %s: entry lists no agents", e.Key)
	}
	if len(e.Manifest.Hooks) == 0 {
		return e, fmt.Errorf("plugin %s: manifest declares no hooks", e.Key)
	}
	for h := range e.Manifest.Hooks {
		if !Hook(h).Allowed() {
			return e, fmt.Errorf("plugin %s: a hook the engine does not serve", e.Key)
		}
	}
	e.Agents = append([]string(nil), e.Agents...)
	e.Config = append([]byte(nil), e.Config...)
	if e.Timeout == 0 {
		e.Timeout = DefaultLocalTimeout
		if e.Manifest.Endpoint.IsRemote() {
			e.Timeout = DefaultRemoteTimeout
		}
	}
	if e.Timeout < MinTimeout || e.Timeout > MaxTimeout {
		return e, fmt.Errorf("plugin %s: timeout out of range", e.Key)
	}
	return e, nil
}

func hookNames(m Manifest) []string {
	out := make([]string, 0, len(m.Hooks))
	for h := range m.Hooks {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func initializeMatches(e Entry, r protocol.InitializeResponse) bool {
	if r.Protocol != protocol.Version1 || r.Name != e.Manifest.Name || r.Version != e.Manifest.Version {
		return false
	}
	if len(r.Hooks) != len(e.Manifest.Hooks) {
		return false
	}
	for h, want := range e.Manifest.Hooks {
		got, ok := r.Hooks[h]
		if !ok || got.Contract != want.Contract ||
			!sameSet(got.Roles, want.Roles) || !sameSet(got.EntityTypes, want.EntityTypes) {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		if m[s]--; m[s] < 0 {
			return false
		}
	}
	return true
}
