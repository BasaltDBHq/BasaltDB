package vault_test

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// otherEngine is an engine id that is not the one under test.
const otherEngine = "AAAAAAAAAAAAAAAAAAAAAA"

func newToken(t *testing.T) channel.LinkToken {
	t.Helper()
	var tok channel.LinkToken
	_, err := rand.Read(tok[:])
	require.NoError(t, err)
	return tok
}

// connected starts a client against v and waits for READY.
func connected(t *testing.T, opts vault.Options) *vault.Client {
	t.Helper()
	c := newClient(t, opts)
	run(t, c)
	require.Eventually(t, c.Connected, waitFor, tick)
	return c
}

func owner(v *vaulttest.Vault, tok channel.LinkToken) string {
	id, _ := v.LinkOwner(tok.Wire())
	return id
}

func TestRegisterAndUnregister(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	keys := newKeys(t)
	c := connected(t, fastOptions(v.URL(), keys))
	tok := newToken(t)

	require.NoError(t, c.Register(context.Background(), tok, time.Now().Add(time.Hour)))
	require.Equal(t, keys.EngineID(), owner(v, tok))

	c.Unregister(tok)
	require.Eventually(t, func() bool { return owner(v, tok) == "" }, waitFor, tick)
}

func TestRegisterWithNoSocket(t *testing.T) {
	t.Parallel()
	c := newClient(t, fastOptions("ws://127.0.0.1:1", newKeys(t)))
	require.False(t, c.Connected())
	require.ErrorIs(t, c.Register(context.Background(), newToken(t), time.Now().Add(time.Hour)), vault.ErrNotConnected)
	c.Unregister(newToken(t)) // nothing to do, and no panic
}

func TestRegisterTimesOut(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{OnRegister: func(string, vaulttest.RegisterLink) vaulttest.Verdict {
		return vaulttest.Verdict{Drop: true}
	}})
	t.Cleanup(v.Close)
	opts := fastOptions(v.URL(), newKeys(t))
	opts.RegisterTimeout = 100 * time.Millisecond
	c := connected(t, opts)

	start := time.Now()
	err := c.Register(context.Background(), newToken(t), time.Now().Add(time.Hour))
	require.ErrorIs(t, err, vault.ErrNoAnswer)
	require.GreaterOrEqual(t, time.Since(start), opts.RegisterTimeout)
}

func TestRegisterStopsWhenTheSocketEnds(t *testing.T) {
	t.Parallel()
	held := make(chan struct{})
	release := make(chan struct{})
	v := vaulttest.New(vaulttest.Options{OnRegister: func(string, vaulttest.RegisterLink) vaulttest.Verdict {
		close(held)
		<-release
		return vaulttest.Verdict{Drop: true}
	}})
	t.Cleanup(v.Close)
	t.Cleanup(func() { close(release) })
	keys := newKeys(t)
	opts := fastOptions(v.URL(), keys)
	opts.RegisterTimeout = time.Minute
	c := connected(t, opts)

	done := make(chan error, 1)
	go func() { done <- c.Register(context.Background(), newToken(t), time.Now().Add(time.Hour)) }()
	<-held
	v.DisconnectEngine(keys.EngineID(), websocket.StatusGoingAway)
	select {
	case err := <-done:
		require.ErrorIs(t, err, vault.ErrNotConnected)
	case <-time.After(waitFor):
		t.Fatal("Register still waits on a socket that ended")
	}
}

func TestRegisterConflict(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	c := connected(t, fastOptions(v.URL(), newKeys(t)))
	tok := newToken(t)
	v.Bind(tok.Wire(), otherEngine, time.Now().Add(time.Hour))

	err := c.Register(context.Background(), tok, time.Now().Add(time.Hour))
	require.True(t, vault.IsConflict(err), "got %v", err)
	require.Equal(t, otherEngine, owner(v, tok), "the binding stays the other engine's")

	c.Unregister(tok) // answered LINK_CONFLICT: logged, nothing else
	require.Never(t, func() bool { return owner(v, tok) != otherEngine }, 100*time.Millisecond, tick)
}

func TestRegisterRefused(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	c := connected(t, fastOptions(v.URL(), newKeys(t)))
	err := c.Register(context.Background(), newToken(t), time.Now().Add(48*time.Hour))
	var refused *vault.RefusedError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, vaulttest.ErrInvalidExpiry, refused.Code)
	require.False(t, vault.IsConflict(err))
}

// liveLinks is a fixed set of live links that records conflicts.
type liveLinks struct {
	links []vault.Link
	mu    sync.Mutex
	conf  []channel.LinkToken
}

func (l *liveLinks) Live() []vault.Link { return l.links }

func (l *liveLinks) Conflict(tok channel.LinkToken) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conf = append(l.conf, tok)
}

func (l *liveLinks) conflicts() []channel.LinkToken {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]channel.LinkToken(nil), l.conf...)
}

func TestEveryLiveLinkIsRegisteredAgainAfterReady(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	keys := newKeys(t)
	mine, theirs := newToken(t), newToken(t)
	v.Bind(theirs.Wire(), otherEngine, time.Now().Add(time.Hour))
	live := &liveLinks{links: []vault.Link{
		{Token: mine, ExpiresAt: time.Now().Add(time.Hour)},
		{Token: theirs, ExpiresAt: time.Now().Add(time.Hour)},
	}}
	opts := fastOptions(v.URL(), keys)
	opts.Links = live
	connected(t, opts)

	require.Eventually(t, func() bool { return owner(v, mine) == keys.EngineID() }, waitFor, tick)
	require.Eventually(t, func() bool { return len(live.conflicts()) == 1 }, waitFor, tick)
	require.Equal(t, []channel.LinkToken{theirs}, live.conflicts(), "VC-42: a token another engine holds is revoked")
	require.Equal(t, otherEngine, owner(v, theirs))

	// A Vault that lost its state recovers at the engine's next READY.
	v.LoseState()
	require.Empty(t, owner(v, mine))
	v.DisconnectEngine(keys.EngineID(), websocket.StatusGoingAway)
	require.Eventually(t, func() bool { return owner(v, mine) == keys.EngineID() }, waitFor, tick)
}

func TestAnAnswerToNoRequestIsIgnored(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	keys := newKeys(t)
	c := connected(t, fastOptions(v.URL(), keys))

	require.NoError(t, v.InjectControl(keys.EngineID(), vaulttest.OK{Type: vaulttest.TypeOK, Ref: 77}))
	require.NoError(t, v.InjectControl(keys.EngineID(), vaulttest.Error{Type: vaulttest.TypeError, Ref: 78, Code: vaulttest.ErrLinkConflict}))
	tok := newToken(t)
	require.NoError(t, c.Register(context.Background(), tok, time.Now().Add(time.Hour)), "the socket is still up")
	require.Equal(t, keys.EngineID(), owner(v, tok))
}
