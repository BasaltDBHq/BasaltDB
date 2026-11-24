package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/vaulttest"
)

// Portal short links over the Vault (VC1-6), against the Go fake Vault.

const (
	relayWait = 5 * time.Second
	relayTick = 5 * time.Millisecond
	// rivalEngine is another engine's id at the Vault.
	rivalEngine = "AAAAAAAAAAAAAAAAAAAAAA"
)

// secretRecorder is the links store's randomness: it records every secret it
// hands out, so a test can look for each one in what the Vault received.
type secretRecorder struct {
	r   io.Reader
	mu  sync.Mutex
	got [][]byte
}

func (s *secretRecorder) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, bytes.Clone(p[:n]))
	return n, err
}

func (s *secretRecorder) secrets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.got))
	for _, b := range s.got {
		out = append(out, base64.RawURLEncoding.EncodeToString(b))
	}
	return out
}

// frameLog is every message the engine sent the Vault.
type frameLog struct {
	mu     sync.Mutex
	frames [][]byte
}

func (f *frameLog) add(_ string, _ websocket.MessageType, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, bytes.Clone(data))
}

func (f *frameLog) all() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.frames...)
}

// count is how many frames hold s.
func (f *frameLog) count(s string) int {
	n := 0
	for _, fr := range f.all() {
		if bytes.Contains(fr, []byte(s)) {
			n++
		}
	}
	return n
}

// testClock is a clock a test moves.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type deliveryRelayEnv struct {
	v       *vaulttest.Vault
	client  *vault.Client
	keys    *channel.EngineKeys
	svc     *Service
	clock   *testClock
	rnd     *secretRecorder
	frames  *frameLog
	timeout time.Duration
}

// newDeliveryRelayEnv is an agent service on a portal engine whose Vault socket runs
// against a fake Vault (started when connect is set), wired as the engine
// wires it: dropped links are unregistered.
func newDeliveryRelayEnv(t *testing.T, opts vaulttest.Options, rnd io.Reader, connect bool) *deliveryRelayEnv {
	t.Helper()
	e := &deliveryRelayEnv{
		clock:   &testClock{now: time.Now()},
		rnd:     &secretRecorder{r: rnd},
		frames:  &frameLog{},
		timeout: 200 * time.Millisecond,
	}
	opts.OnEngineMessage = e.frames.add
	e.v = vaulttest.New(opts)
	t.Cleanup(e.v.Close)
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	e.keys = keys
	e.client, err = vault.New(vault.Options{
		URL: e.v.URL(), Keys: keys, Log: slog.New(slog.DiscardHandler),
		BackoffMin: 5 * time.Millisecond, BackoffMax: 40 * time.Millisecond, PingInterval: time.Hour,
		RegisterTimeout: e.timeout,
	})
	require.NoError(t, err)

	store := links.NewSecrets(e.clock.Now, e.rnd)
	store.OnDrop(e.client.Unregister)
	d := deps()
	setApprovals(&d, catalogApprovals{})
	setReverts(&d, catalogReverts{})
	d.Core.PagesBase = links.Portal
	d.Delivery.Links = store
	d.Delivery.Relay = e.client
	d.Core.Now = e.clock.Now
	e.svc = NewService(d)

	if connect {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = e.client.Run(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		require.Eventually(t, e.client.Connected, relayWait, relayTick)
	}
	t.Cleanup(func() { e.requireNoSecretSent(t) })
	return e
}

// notice holds a write for approval and returns what the agent hands over.
func (e *deliveryRelayEnv) notice(t *testing.T) linksvc.HeldAnswer {
	t.Helper()
	n, err := e.svc.approval.ApprovalNotice(context.Background(), uuid.MustParse(caseApproval), uuid.MustParse(caseRunID), linksvc.SizedRequest{Binding: noticeBinding, Lines: bigLines(3)},
		e.clock.Now().Add(time.Hour), linksvc.IssueLink)
	require.NoError(t, err)
	stepcatalogtest.RequirePersonMessage(t, n.PersonMessage, n.Links)
	return n
}

func (e *deliveryRelayEnv) owner(tok channel.LinkToken) string {
	id, _ := e.v.LinkOwner(tok.Wire())
	return id
}

// requireNoSecretSent checks every message the engine sent the Vault for
// every secret the links store made: not the secret, its bytes, its hash or
// its psk, in any encoding the engine uses.
func (e *deliveryRelayEnv) requireNoSecretSent(t *testing.T) {
	t.Helper()
	frames := e.frames.all()
	for _, secret := range e.rnd.secrets() {
		keys, err := channel.DeriveLink(secret)
		require.NoError(t, err)
		raw, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)
		hash := sha256.Sum256([]byte(secret))
		forbidden := [][]byte{
			[]byte(secret), raw,
			hash[:], []byte(hex.EncodeToString(hash[:])),
			keys.PSK[:], []byte(base64.RawURLEncoding.EncodeToString(keys.PSK[:])),
			[]byte(base64.StdEncoding.EncodeToString(keys.PSK[:])), []byte(hex.EncodeToString(keys.PSK[:])),
		}
		for i, fr := range frames {
			for _, f := range forbidden {
				require.False(t, bytes.Contains(fr, f), "frame %d to the Vault holds a link secret or psk: %q", i, fr)
			}
		}
	}
}

func shortSecret(t *testing.T, url string) (string, channel.LinkKeys) {
	t.Helper()
	secret := linkstest.SecretOf(url)
	require.NotEmpty(t, secret, "a short link: %s", url)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	return secret, keys
}

func TestRelayHandsOverTheRegisteredPortalShortLink(t *testing.T) {
	t.Parallel()
	e := newDeliveryRelayEnv(t, vaulttest.Options{}, rand.Reader, true)
	n := e.notice(t)

	require.True(t, strings.HasPrefix(n.ApprovalURL, links.Portal+"/approvals/"+caseApproval+"#s="), n.ApprovalURL)
	require.Equal(t, n.ApprovalURL, n.ShortURL)
	require.Contains(t, n.PersonMessage, "\n\n"+n.ApprovalURL+"\n\n")
	secret, keys := shortSecret(t, n.ApprovalURL)
	require.Equal(t, e.keys.EngineID(), e.owner(keys.Token), "registered before it was handed over")
	require.True(t, e.svc.deps.Delivery.Links.Check(uuid.MustParse(caseApproval), secret))
	require.Equal(t, 1, e.frames.count(`"type":"REGISTER_LINK"`))
	require.Equal(t, 1, e.frames.count(keys.Token.Wire()), "the token is what the Vault sees")

	// A revert's link goes the same way.
	id := uuid.Must(uuid.NewV7())
	link, err := e.svc.delivery.ShortLink(context.Background(), links.Revert, id, e.clock.Now().Add(time.Hour), linksvc.IssueLink)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(link, links.Portal+"/reverts/"+id.String()+"#s="), link)
	_, rkeys := shortSecret(t, link)
	require.Equal(t, e.keys.EngineID(), e.owner(rkeys.Token))
}

func TestRelayDownHandsOverTheLongLink(t *testing.T) {
	t.Parallel()
	e := newDeliveryRelayEnv(t, vaulttest.Options{}, rand.Reader, false)
	n := e.notice(t)

	require.Empty(t, n.ShortURL)
	require.Equal(t, n.LongURL, n.ApprovalURL)
	require.True(t, strings.HasPrefix(n.ApprovalURL, links.Portal+"/approvals/"+caseApproval+"#2."), n.ApprovalURL)
	require.LessOrEqual(t, len(n.ApprovalURL), links.DefaultBudget, "the fallback stays within the link budget")
	require.Empty(t, e.svc.deps.Delivery.Links.Relay(), "no secret is issued while the socket is down")
	require.Empty(t, e.frames.all())
}

func TestRelayTimeoutFallsBackToTheLongLink(t *testing.T) {
	t.Parallel()
	e := newDeliveryRelayEnv(t, vaulttest.Options{OnRegister: func(string, vaulttest.RegisterLink) vaulttest.Verdict {
		return vaulttest.Verdict{Drop: true}
	}}, rand.Reader, true)
	start := time.Now()
	n := e.notice(t)

	require.GreaterOrEqual(t, time.Since(start), e.timeout, "it waited for the answer")
	require.Empty(t, n.ShortURL)
	require.Equal(t, n.LongURL, n.ApprovalURL)
	require.Empty(t, e.svc.deps.Delivery.Links.Relay(), "the unregistered link is revoked, never handed over")
	secrets := e.rnd.secrets()
	require.Len(t, secrets, 1)
	require.False(t, e.svc.deps.Delivery.Links.Check(uuid.MustParse(caseApproval), secrets[0]))
	_, keys := shortSecret(t, links.WithSecret(links.Portal, secrets[0]))
	require.Eventually(t, func() bool { return e.frames.count(`"type":"UNREGISTER_LINK"`) == 1 }, relayWait, relayTick,
		"a registration that may have landed late is taken back")
	require.Equal(t, 2, e.frames.count(keys.Token.Wire()))
}

func TestRelayRefusedFallsBackToTheLongLink(t *testing.T) {
	t.Parallel()
	e := newDeliveryRelayEnv(t, vaulttest.Options{OnRegister: func(string, vaulttest.RegisterLink) vaulttest.Verdict {
		return vaulttest.Verdict{Code: vaulttest.ErrLinkLimit}
	}}, rand.Reader, true)
	n := e.notice(t)
	require.Empty(t, n.ShortURL)
	require.Equal(t, n.LongURL, n.ApprovalURL)
	require.Empty(t, e.svc.deps.Delivery.Links.Relay())
}

// fixedReader hands out the same bytes on every read, so a test knows the
// next secret before the engine issues it.
type fixedReader struct{ b byte }

func (f fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.b
	}
	return len(p), nil
}

func TestRelayConflictRevokesTheLink(t *testing.T) {
	t.Parallel()
	rnd := fixedReader{b: 7}
	e := newDeliveryRelayEnv(t, vaulttest.Options{}, rnd, true)
	next := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{rnd.b}, links.SecretBytes))
	keys, err := channel.DeriveLink(next)
	require.NoError(t, err)
	// Someone who saw a link registered its token with their own engine first (VC-42).
	e.v.Bind(keys.Token.Wire(), rivalEngine, time.Now().Add(time.Hour))

	n := e.notice(t)
	require.Empty(t, n.ShortURL)
	require.Equal(t, n.LongURL, n.ApprovalURL, "the long link instead")
	require.False(t, e.svc.deps.Delivery.Links.Check(uuid.MustParse(caseApproval), next), "the link is revoked")
	require.Empty(t, e.svc.deps.Delivery.Links.Relay())
	require.Equal(t, rivalEngine, e.owner(keys.Token), "the Vault keeps the rival's binding")
}

func TestRelayUnregistersOnReissueAndExpiry(t *testing.T) {
	t.Parallel()
	e := newDeliveryRelayEnv(t, vaulttest.Options{}, rand.Reader, true)
	first := e.notice(t)
	_, firstKeys := shortSecret(t, first.ApprovalURL)

	// A reissue revokes the earlier link and unregisters its token.
	second := e.notice(t)
	_, secondKeys := shortSecret(t, second.ApprovalURL)
	require.NotEqual(t, firstKeys.Token, secondKeys.Token)
	require.Eventually(t, func() bool { return e.owner(firstKeys.Token) == "" }, relayWait, relayTick)
	require.Equal(t, e.keys.EngineID(), e.owner(secondKeys.Token))

	// The item expires: the engine's next prune unregisters the token (the
	// fake Vault's own clock has not reached the expiry).
	e.clock.advance(time.Hour)
	e.svc.deps.Delivery.Links.Prune()
	require.Eventually(t, func() bool { return e.owner(secondKeys.Token) == "" }, relayWait, relayTick)
	require.Equal(t, 2, e.frames.count(`"type":"UNREGISTER_LINK"`))
}
