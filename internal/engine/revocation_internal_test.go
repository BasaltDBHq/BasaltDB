package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// fakeRecord answers the engine-record reads: its state, or an error.
// With hold set, each read waits for it (a slow database).
type fakeRecord struct {
	mu      sync.Mutex
	revoked bool
	err     error
	reads   int
	hold    chan struct{}
}

func (f *fakeRecord) set(revoked bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked, f.err = revoked, err
}

func (f *fakeRecord) read(ctx context.Context, id string) (*guard.RecordedEngine, error) {
	f.mu.Lock()
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return nil, f.err
	}
	r := &guard.RecordedEngine{ID: id, RecordedAt: time.Now()}
	if f.revoked {
		at := time.Now()
		r.RevokedAt = &at
	}
	return r, nil
}

func (f *fakeRecord) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// ends records the tokens unregistered, by how their sessions end.
type ends struct {
	mu       sync.Mutex
	refused  []channel.LinkToken
	revoked  []channel.LinkToken
	leftOnce int
}

func (e *ends) unregister(t channel.LinkToken) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refused = append(e.refused, t)
}

func (e *ends) endRevoked(t channel.LinkToken) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revoked = append(e.revoked, t)
}

func (e *ends) leave() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.leftOnce++
}

func (e *ends) snapshot() ([]channel.LinkToken, []channel.LinkToken, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]channel.LinkToken(nil), e.refused...), append([]channel.LinkToken(nil), e.revoked...), e.leftOnce
}

// revocationFixture is two agents' link stores behind relayLinks, watched
// by a revocation over fake records.
type revocationFixture struct {
	rev     *revocation
	relay   *relayLinks
	ends    *ends
	stores  map[string]*links.Secrets
	records map[string]*fakeRecord
}

func newRevocationFixture(t *testing.T, agents ...string) *revocationFixture {
	t.Helper()
	f := newRevocationAgents(t, agents...)
	f.rev.onLeave(f.ends.leave)
	return f
}

// newRevocationAgents is newRevocationFixture before the engine wires its
// leave: what the engine has while it starts its agents.
func newRevocationAgents(t *testing.T, agents ...string) *revocationFixture {
	t.Helper()
	f := &revocationFixture{
		rev: newRevocation("R68WFYxAcGgIjMENS5Oqrw", quietLog()), relay: newRelayLinks(quietLog()), ends: &ends{},
		stores: map[string]*links.Secrets{}, records: map[string]*fakeRecord{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.relay.watch(ctx, f.rev, f.ends.endRevoked)
	for _, name := range agents {
		s, rec := links.NewSecrets(time.Now, rand.Reader), &fakeRecord{}
		f.stores[name], f.records[name] = s, rec
		f.rev.add(name, rec.read, s)
		f.relay.add(name, s, f.ends.unregister)
	}
	return f
}

// issue gives agent a live relay link and returns its token.
func (f *revocationFixture) issue(t *testing.T, agent string) channel.LinkToken {
	t.Helper()
	_, token, err := f.stores[agent].IssueRelay(uuid.Must(uuid.NewV7()), time.Now().Add(time.Hour))
	require.NoError(t, err)
	return token
}

// A database that did not revoke the key changes nothing.
func TestRevocationNotRevoked(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "bot")
	token := f.issue(t, "bot")
	require.False(t, f.rev.check(context.Background(), "bot"))
	require.False(t, f.rev.isRevoked("bot"))
	_, ok := f.relay.Session(token)
	require.True(t, ok, "the session is served")
	require.Len(t, f.stores["bot"].Relay(), 1)
	refused, revoked, left := f.ends.snapshot()
	require.Empty(t, refused)
	require.Empty(t, revoked)
	require.Zero(t, left)
}

// The first read that finds the key revoked revokes the agent's relay
// links: their tokens are unregistered with ENGINE_REVOKED, the agent's
// sessions are refused, and the other agent keeps its own.
func TestRevocationEndsTheAgentsRelayLinks(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "bot", "helper")
	botToken, helperToken := f.issue(t, "bot"), f.issue(t, "helper")
	f.records["bot"].set(true, nil)

	require.True(t, f.rev.check(context.Background(), "bot"))
	require.True(t, f.rev.isRevoked("bot"))
	require.False(t, f.rev.isRevoked("helper"))
	require.Empty(t, f.stores["bot"].Relay(), "the revoked agent's links are revoked")
	require.Len(t, f.stores["helper"].Relay(), 1)
	refused, revoked, left := f.ends.snapshot()
	require.Equal(t, []channel.LinkToken{botToken}, revoked, "closed with ENGINE_REVOKED")
	require.Empty(t, refused)
	require.Zero(t, left, "another agent's database still records the key")

	_, ok := f.relay.Session(botToken)
	require.False(t, ok)
	_, ok = f.relay.Session(helperToken)
	require.True(t, ok)

	// Revoked stays revoked: no more reads for it, and a new link the store
	// issues is refused at its session too.
	reads := f.records["bot"].count()
	f.records["bot"].set(false, nil)
	require.True(t, f.rev.check(context.Background(), "bot"))
	require.Equal(t, reads, f.records["bot"].count())
	_, ok = f.relay.Session(f.issue(t, "bot"))
	require.False(t, ok)
}

// Each relay session reads the record again, in the background: the
// session itself is answered from the last read, and the revocation that
// read finds ends the agent's links (that session included) and refuses
// the next session.
func TestRevocationReadAtEachSession(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "bot")
	token := f.issue(t, "bot")
	_, ok := f.relay.Session(token)
	require.True(t, ok)
	f.records["bot"].set(true, nil)
	_, ok = f.relay.Session(token)
	require.True(t, ok, "answered from the last read")
	require.Eventually(t, func() bool { return f.rev.isRevoked("bot") }, 5*time.Second, 5*time.Millisecond, "the session's read finds it")
	_, revoked, _ := f.ends.snapshot()
	require.Equal(t, []channel.LinkToken{token}, revoked, "its links end with ENGINE_REVOKED")
	_, ok = f.relay.Session(f.issue(t, "bot"))
	require.False(t, ok, "the next session is refused at message 1")
}

// The session-time read never holds up the Vault socket's read loop: with
// one agent's database hanging, sessions of that agent and of another are
// answered at once, and only one read per agent runs.
func TestRevocationSlowDatabaseDoesNotStallSessions(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "slow", "other")
	slowToken, otherToken := f.issue(t, "slow"), f.issue(t, "other")
	release := make(chan struct{})
	f.records["slow"].mu.Lock()
	f.records["slow"].hold = release
	f.records["slow"].mu.Unlock()
	defer close(release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 5 {
			_, ok := f.relay.Session(slowToken)
			require.True(t, ok)
		}
		_, ok := f.relay.Session(otherToken)
		require.True(t, ok)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a slow database held up the sessions")
	}
	f.rev.mu.Lock()
	reading := f.rev.reading["slow"]
	f.rev.mu.Unlock()
	require.True(t, reading, "one read of the slow database is running")
}

// A revocation found while the engine starts its agents, before it wires
// its leave, still has it leave the Vault once that leave exists, and only
// when every agent is revoked.
func TestRevocationFoundAtStartLeavesOnceWired(t *testing.T) {
	t.Parallel()
	f := newRevocationAgents(t, "bot")
	f.records["bot"].set(true, nil)
	require.True(t, f.rev.check(context.Background(), "bot"))
	_, _, left := f.ends.snapshot()
	require.Zero(t, left, "nothing to leave yet")
	f.rev.onLeave(f.ends.leave)
	_, _, left = f.ends.snapshot()
	require.Equal(t, 1, left, "leaves as soon as the leave is wired")
	f.rev.check(context.Background(), "bot")
	_, _, left = f.ends.snapshot()
	require.Equal(t, 1, left, "once")

	// With another agent not revoked, wiring the leave changes nothing.
	g := newRevocationAgents(t, "bot", "helper")
	g.records["bot"].set(true, nil)
	g.rev.check(context.Background(), "bot")
	g.rev.onLeave(g.ends.leave)
	_, _, left = g.ends.snapshot()
	require.Zero(t, left)
	g.records["helper"].set(true, nil)
	g.rev.check(context.Background(), "helper")
	_, _, left = g.ends.snapshot()
	require.Equal(t, 1, left)
}

// A failed read keeps the last state.
func TestRevocationFailedReadKeepsTheLastState(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "bot")
	token := f.issue(t, "bot")
	f.records["bot"].set(false, errors.New("database unreachable"))
	require.False(t, f.rev.check(context.Background(), "bot"))
	_, ok := f.relay.Session(token)
	require.True(t, ok)
	require.Len(t, f.stores["bot"].Relay(), 1)
}

// When every agent's database revoked the key, the engine leaves the Vault,
// once.
func TestRevocationLeavesTheVaultWhenEveryDatabaseRevoked(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "bot", "helper")
	f.records["bot"].set(true, nil)
	f.records["helper"].set(true, nil)
	f.rev.check(context.Background(), "bot")
	_, _, left := f.ends.snapshot()
	require.Zero(t, left)
	f.rev.check(context.Background(), "helper")
	f.rev.check(context.Background(), "helper")
	_, _, left = f.ends.snapshot()
	require.Equal(t, 1, left)
}

// The heartbeat's gate reads the record first, then admits as before.
func TestRevocationGate(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t, "bot")
	f.records["bot"].set(true, nil)
	admitted := false
	require.NoError(t, f.rev.gate("bot", func(context.Context) error { admitted = true; return nil })(context.Background()))
	require.True(t, admitted)
	require.True(t, f.rev.isRevoked("bot"))

	// An engine without a Vault watches nothing.
	var none *revocation
	require.False(t, none.check(context.Background(), "bot"))
	require.False(t, none.isRevoked("bot"))
	require.NoError(t, none.gate("bot", func(context.Context) error { return nil })(context.Background()))
}

// fakeRelay is a connected relay that records registrations.
type fakeRelay struct{ registered int }

func (r *fakeRelay) Connected() bool { return true }

func (r *fakeRelay) Register(context.Context, channel.LinkToken, time.Time) error {
	r.registered++
	return nil
}

// A revoked agent's relay registers nothing: its links are long links.
func TestRevocableRelay(t *testing.T) {
	t.Parallel()
	next := &fakeRelay{}
	revoked := false
	r := revocableRelay{next: next, revoked: func() bool { return revoked }}
	require.True(t, r.Connected())
	require.NoError(t, r.Register(context.Background(), channel.LinkToken{}, time.Now()))
	revoked = true
	require.False(t, r.Connected())
	require.ErrorIs(t, r.Register(context.Background(), channel.LinkToken{}, time.Now()), errEngineRevoked)
	require.Equal(t, 1, next.registered)
}
