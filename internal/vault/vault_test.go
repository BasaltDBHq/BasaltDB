package vault_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

const (
	waitFor = 5 * time.Second
	tick    = 5 * time.Millisecond
)

func newKeys(t *testing.T) *channel.EngineKeys {
	t.Helper()
	k, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	return k
}

// quiet drops the client's log lines.
func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fastOptions are short timings so reconnects take milliseconds.
func fastOptions(url string, keys vault.Keys) vault.Options {
	return vault.Options{
		URL:          url,
		Keys:         keys,
		Log:          quiet(),
		BackoffMin:   5 * time.Millisecond,
		BackoffMax:   40 * time.Millisecond,
		PingInterval: time.Hour,
		AuthTimeout:  2 * time.Second,
	}
}

func newClient(t *testing.T, opts vault.Options) *vault.Client {
	t.Helper()
	c, err := vault.New(opts)
	require.NoError(t, err)
	return c
}

// run runs c until the test ends; the returned stop ends it early and
// returns Run's result.
func run(t *testing.T, c *vault.Client) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	var once sync.Once
	var result error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(waitFor):
				result = errors.New("Run did not return")
			}
		})
		return result
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// countingVault is a fake Vault that counts the sockets it challenged.
func countingVault(t *testing.T) (*vaulttest.Vault, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	opts := vaulttest.Options{}
	opts.Challenge = func() [vaulttest.ChallengeLen]byte {
		n.Add(1)
		var c [vaulttest.ChallengeLen]byte
		_, _ = rand.Read(c[:])
		return c
	}
	v := vaulttest.New(opts)
	t.Cleanup(v.Close)
	return v, &n
}

func TestConnectAndReady(t *testing.T) {
	t.Parallel()
	v, challenges := countingVault(t)
	keys := newKeys(t)
	c := newClient(t, fastOptions(v.URL(), keys))

	require.Equal(t, vault.StateConnecting, c.Status().State)
	stop := run(t, c)
	require.Eventually(t, func() bool { return v.Connected(keys.EngineID()) }, waitFor, tick)
	require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)

	st := c.Status()
	require.Equal(t, keys.EngineID(), st.EngineID)
	require.Equal(t, keys.Fingerprint(), st.Fingerprint)
	require.Equal(t, int64(1), challenges.Load())

	require.NoError(t, stop())
	require.Eventually(t, func() bool { return !v.Connected(keys.EngineID()) }, waitFor, tick)
	require.NotEqual(t, vault.StateConnected, c.Status().State)
}

func TestUnreachableAfterThirtySecondsWithoutReady(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	opts := fastOptions("ws://127.0.0.1:1", newKeys(t)) // nothing listens there
	opts.Now = clock
	var j jitterLog
	opts.Jitter = j.jitter
	c := newClient(t, opts)
	run(t, c)
	// Run has started once its first dial failed.
	require.Eventually(t, func() bool { return len(j.get()) > 0 }, waitFor, tick)

	require.Equal(t, vault.StateConnecting, c.Status().State)
	advance(vault.UnreachableAfter - time.Second)
	require.Equal(t, vault.StateConnecting, c.Status().State)
	advance(time.Second)
	require.Equal(t, vault.StateUnreachable, c.Status().State)
}

// jitterLog records each backoff ceiling and waits a fixed short time.
type jitterLog struct {
	mu       sync.Mutex
	ceilings []time.Duration
}

func (j *jitterLog) jitter(ceiling time.Duration) time.Duration {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ceilings = append(j.ceilings, ceiling)
	return time.Millisecond
}

func (j *jitterLog) get() []time.Duration {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]time.Duration(nil), j.ceilings...)
}

func TestBackoffDoublesToTheCap(t *testing.T) {
	t.Parallel()
	var j jitterLog
	opts := fastOptions("ws://127.0.0.1:1", newKeys(t))
	opts.Jitter = j.jitter
	run(t, newClient(t, opts))

	require.Eventually(t, func() bool { return len(j.get()) >= 6 }, waitFor, tick)
	ms := time.Millisecond
	require.Equal(t, []time.Duration{5 * ms, 10 * ms, 20 * ms, 40 * ms, 40 * ms, 40 * ms}, j.get()[:6])
}

func TestBackoffResetsAfterReady(t *testing.T) {
	t.Parallel()
	v, challenges := countingVault(t)
	keys := newKeys(t)
	var j jitterLog
	opts := fastOptions(v.URL(), keys)
	opts.Jitter = j.jitter
	c := newClient(t, opts)
	run(t, c)

	for i := range 3 {
		require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
		v.DisconnectEngine(keys.EngineID(), vaulttest.CloseNormal)
		require.Eventually(t, func() bool { return challenges.Load() == int64(i+2) }, waitFor, tick)
	}
	require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
	// Every loss came after READY, so every wait starts from the minimum.
	for _, ceiling := range j.get() {
		require.Equal(t, opts.BackoffMin, ceiling)
	}
}

func TestReplacedDoesNotResetTheBackoff(t *testing.T) {
	t.Parallel()
	v, challenges := countingVault(t)
	keys := newKeys(t)
	var j jitterLog
	opts := fastOptions(v.URL(), keys)
	opts.Jitter = j.jitter
	c := newClient(t, opts)
	run(t, c)

	for i := range 3 {
		require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
		v.DisconnectEngine(keys.EngineID(), vaulttest.CloseReplaced)
		require.Eventually(t, func() bool { return challenges.Load() == int64(i+2) }, waitFor, tick)
	}
	// Each REPLACED socket waits longer than the last, READY or not.
	require.Equal(t, []time.Duration{opts.BackoffMin, 2 * opts.BackoffMin, 4 * opts.BackoffMin}, j.get())
}

func TestReconnectsAfterReplacedOrDropped(t *testing.T) {
	t.Parallel()
	for _, code := range []websocket.StatusCode{vaulttest.CloseReplaced, vaulttest.CloseProtocol, vaulttest.CloseNormal} {
		t.Run(vaulttest.CloseNames[int(code)], func(t *testing.T) {
			t.Parallel()
			v, challenges := countingVault(t)
			keys := newKeys(t)
			c := newClient(t, fastOptions(v.URL(), keys))
			run(t, c)
			require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
			v.DisconnectEngine(keys.EngineID(), code)
			require.Eventually(t, func() bool { return challenges.Load() == 2 && v.Connected(keys.EngineID()) }, waitFor, tick)
			require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
		})
	}
}

// otherSigner signs with another engine's key: the Vault must refuse its AUTH.
type otherSigner struct {
	*channel.EngineKeys
	other *channel.EngineKeys
}

func (o otherSigner) Sign(ctx channel.SigningContext, body []byte) ([]byte, error) {
	return o.other.Sign(ctx, body)
}

// otherKey presents another engine's key under this engine's id.
type otherKey struct {
	*channel.EngineKeys
	other *channel.EngineKeys
}

func (o otherKey) PublicKeySPKI() []byte { return o.other.PublicKeySPKI() }

func TestRefusedByTheVault(t *testing.T) {
	t.Parallel()
	cases := map[string]func(v *vaulttest.Vault, keys *channel.EngineKeys) vault.Options{
		"a signature by another key": func(v *vaulttest.Vault, keys *channel.EngineKeys) vault.Options {
			return fastOptions(v.URL(), otherSigner{keys, newKeys(t)})
		},
		"a key that is not the id's": func(v *vaulttest.Vault, keys *channel.EngineKeys) vault.Options {
			return fastOptions(v.URL(), otherKey{keys, newKeys(t)})
		},
		// The engine signs its own host (localhost:<port>); the Vault checks
		// its own (127.0.0.1:<port>). A signature for another host is refused.
		"a signature for another host": func(v *vaulttest.Vault, keys *channel.EngineKeys) vault.Options {
			return fastOptions(strings.Replace(v.URL(), "127.0.0.1", "localhost", 1), keys)
		},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, _ := countingVault(t)
			keys := newKeys(t)
			var j jitterLog
			o := opts(v, keys)
			o.Jitter = j.jitter
			c := newClient(t, o)
			run(t, c)
			// It keeps trying with backoff, and is never READY.
			require.Eventually(t, func() bool { return len(j.get()) >= 3 }, waitFor, tick)
			require.Equal(t, []time.Duration{o.BackoffMin, 2 * o.BackoffMin, 4 * o.BackoffMin}, j.get()[:3])
			require.False(t, v.Connected(keys.EngineID()))
			require.Equal(t, vault.StateConnecting, c.Status().State)
		})
	}
}

func TestOneConnectionUnderConcurrency(t *testing.T) {
	t.Parallel()
	v, challenges := countingVault(t)
	keys := newKeys(t)
	c := newClient(t, fastOptions(v.URL(), keys))

	ctx, cancel := context.WithCancel(context.Background())
	const callers = 16
	results := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(1)
	for range callers {
		go func() {
			start.Wait()
			results <- c.Run(ctx)
		}()
	}
	start.Done()
	refused := 0
	for range callers - 1 {
		err := <-results
		require.ErrorIs(t, err, vault.ErrRunning)
		refused++
	}
	require.Equal(t, callers-1, refused)
	require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
	// Concurrent status reads while connected.
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() { require.Equal(t, vault.StateConnected, c.Status().State) })
	}
	wg.Wait()
	require.Never(t, func() bool { return challenges.Load() > 1 }, 100*time.Millisecond, tick)

	cancel()
	require.NoError(t, <-results)
	// A stopped client may run again, still on one socket.
	stop := run(t, c)
	require.Eventually(t, func() bool { return challenges.Load() == 2 && v.Connected(keys.EngineID()) }, waitFor, tick)
	require.NoError(t, stop())
}

func TestRedialsWithoutPong(t *testing.T) {
	t.Parallel()
	v, challenges := countingVault(t)
	keys := newKeys(t)
	opts := fastOptions(v.URL(), keys)
	opts.PingInterval = 10 * time.Millisecond
	opts.PongTimeout = 50 * time.Millisecond
	c := newClient(t, opts)
	run(t, c)
	require.Eventually(t, func() bool { return v.Pings(keys.EngineID()) >= 2 }, waitFor, tick)
	require.Equal(t, int64(1), challenges.Load(), "pongs keep the socket")

	v.SuppressPongs(keys.EngineID(), true)
	require.Eventually(t, func() bool { return challenges.Load() >= 2 }, waitFor, tick)
	v.SuppressPongs(keys.EngineID(), false)
	require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
}

func TestForgedControlMessagesAreHarmless(t *testing.T) {
	t.Parallel()
	v, challenges := countingVault(t)
	keys := newKeys(t)
	c := newClient(t, fastOptions(v.URL(), keys))
	run(t, c)
	require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)

	id := keys.EngineID()
	require.NoError(t, v.InjectControl(id, vaulttest.OK{Type: vaulttest.TypeOK, Ref: 7}))
	require.NoError(t, v.InjectControl(id, vaulttest.Error{Type: vaulttest.TypeError, Code: vaulttest.ErrLinkConflict}))
	require.NoError(t, v.InjectControl(id, vaulttest.SessionClose{Type: vaulttest.TypeSessionClose, SID: vaulttest.SID{1}.String(), Code: 1000}))
	require.Never(t, func() bool { return challenges.Load() > 1 }, 100*time.Millisecond, tick)
	require.Equal(t, vault.StateConnected, c.Status().State)
}

func TestNewRefusesABadURL(t *testing.T) {
	t.Parallel()
	for _, u := range []string{
		"http://127.0.0.1:1", "ws://", "ws://h/path", "ws://h?q=1", "ws://u@h",
		// Plaintext only to a loopback Vault.
		"ws://relay.basaltvault.app", "ws://10.0.0.1:8787", "ws://127.0.0.2:8787", "ws://localhost.evil.io:1", "ws://0.0.0.0:1",
	} {
		_, err := vault.New(vault.Options{URL: u, Keys: newKeys(t)})
		require.Error(t, err, u)
	}
	for _, u := range []string{"", "wss://relay.basaltvault.app", "ws://127.0.0.1:1", "ws://[::1]:1", "ws://LocalHost:1/"} {
		_, err := vault.New(vault.Options{URL: u, Keys: newKeys(t)})
		require.NoError(t, err, u)
	}
	require.Panics(t, func() { _, _ = vault.New(vault.Options{}) })
}

func TestOffAndKeyErrorStatus(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	require.Equal(t, vault.Status{State: vault.StateOff, EngineID: keys.EngineID(), Fingerprint: keys.Fingerprint()}, vault.OffStatus(keys))
	require.Equal(t, vault.Status{State: vault.StateKeyError}, vault.KeyErrorStatus())
}
