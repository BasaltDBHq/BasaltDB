package engine

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// relayLinks registers every agent's live links again after READY, revokes
// the link of a LINK_CONFLICT, unregisters what rotation revokes, and prunes
// expired links on a timer.
func TestRelayLinksAcrossAgents(t *testing.T) {
	t.Parallel()
	const wait, tick = 5 * time.Second, 5 * time.Millisecond
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	relay := newRelayLinks(quietLog())
	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}
	ev := openVault(cfg, t.TempDir(), time.Now, quietLog(), relay, nil)
	require.NotNil(t, ev.client)
	engineID := ev.status().EngineID
	owner := func(tok channel.LinkToken) string {
		id, _ := v.LinkOwner(tok.Wire())
		return id
	}

	// Two agents' links, issued while the engine was not connected (as
	// before a restart).
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	bot, ops := links.NewSecrets(clock, rand.Reader), links.NewSecrets(clock, rand.Reader)
	relay.add("bot", bot, ev.client.Unregister)
	relay.add("ops", ops, ev.client.Unregister)
	_, a, err := bot.IssueRelay(uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	require.NoError(t, err)
	_, b, err := ops.IssueRelay(uuid.Must(uuid.NewV7()), now.Add(time.Minute))
	require.NoError(t, err)
	_, c, err := ops.IssueRelay(uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	require.NoError(t, err)
	v.Bind(c.Wire(), "AAAAAAAAAAAAAAAAAAAAAA", now.Add(time.Hour))
	require.Len(t, relay.Live(), 3)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	wg.Go(func() { _ = ev.client.Run(ctx) })
	wg.Go(func() { relay.pruneEvery(ctx, tick) })

	// After READY both agents' links are registered, and the one another
	// engine holds is revoked at this engine (VC-42).
	require.Eventually(t, func() bool { return owner(a) == engineID && owner(b) == engineID }, wait, tick)
	require.Eventually(t, func() bool { return len(ops.Relay()) == 1 }, wait, tick)
	require.Equal(t, b, ops.Relay()[0].Token)
	require.Equal(t, "AAAAAAAAAAAAAAAAAAAAAA", owner(c))

	// ops's link expires: the timer's prune unregisters it.
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	require.Eventually(t, func() bool { return owner(b) == "" }, wait, tick)
	require.Equal(t, engineID, owner(a))

	// Rotation revokes every relay link and unregisters it (VC-40).
	relay.RevokeAll()
	require.Empty(t, relay.Live())
	require.Eventually(t, func() bool { return owner(a) == "" }, wait, tick)
}

// Many LINK_CONFLICTs after READY revoke their links without sending an
// UNREGISTER_LINK from the socket's read loop, so reads go on: a Vault that
// would stall on any UNREGISTER_LINK still answers the next registration.
func TestManyConflictsDoNotStallReads(t *testing.T) {
	t.Parallel()
	const conflicts = 50
	stall := make(chan struct{})
	var unregisters atomic.Int64
	v := vaulttest.New(vaulttest.Options{OnUnregister: func(string, vaulttest.UnregisterLink) vaulttest.Verdict {
		unregisters.Add(1)
		<-stall
		return vaulttest.Verdict{}
	}})
	t.Cleanup(v.Close)
	t.Cleanup(func() { close(stall) })
	relay := newRelayLinks(quietLog())
	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}
	ev := openVault(cfg, t.TempDir(), time.Now, quietLog(), relay, nil)
	require.NotNil(t, ev.client)
	store := links.NewSecrets(time.Now, rand.Reader)
	relay.add("bot", store, ev.client.Unregister)
	for range conflicts {
		_, tok, err := store.IssueRelay(uuid.Must(uuid.NewV7()), time.Now().Add(time.Hour))
		require.NoError(t, err)
		v.Bind(tok.Wire(), "AAAAAAAAAAAAAAAAAAAAAA", time.Now().Add(time.Hour))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ev.client.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, func() bool { return len(store.Relay()) == 0 }, 5*time.Second, 5*time.Millisecond,
		"every conflicting link is revoked")

	start := time.Now()
	var fresh channel.LinkToken
	_, err := rand.Read(fresh[:])
	require.NoError(t, err)
	require.NoError(t, ev.client.Register(context.Background(), fresh, time.Now().Add(time.Hour)))
	require.Less(t, time.Since(start), time.Second, "the socket is read promptly")
	require.Zero(t, unregisters.Load(), "no UNREGISTER_LINK for a token another engine holds")
}
