//go:build unix

package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
)

// fastDeliver is the delivery's timing in tests: four tries, shrunk.
var fastDeliver = deliverTiming{
	tries:   []time.Duration{0, 40 * time.Millisecond, 80 * time.Millisecond, 120 * time.Millisecond},
	install: 2 * time.Second,
	keep:    deliverDropKeep,
}

func deliverSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		return regexp.Compile(ecmaEscape.ReplaceAllString(s, `\x{$1}`))
	})
	for name, id := range map[string]string{
		// deliver.schema.json refers to the feed's definitions by file name.
		"feed.schema.json":    "https://basaltvault.app/schemas/plugin/protocol/feed.schema.json",
		"deliver.schema.json": "https://basaltvault.app/schemas/plugin/protocol/deliver.v1.json",
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "api", "plugin", "protocol", name))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(id, doc))
	}
	sch, err := c.Compile("https://basaltvault.app/schemas/plugin/protocol/deliver.v1.json#/$defs/request")
	require.NoError(t, err)
	return sch
}

// gotNotice is one approval.deliver call a test plugin received.
type gotNotice struct {
	Agent string `json:"agent"`
	Event struct {
		ID, Source, Type, Time, Subject string
		Data                            map[string]any
	} `json:"event"`
	raw []byte
}

// deliverPlugin is an approval.deliver plugin in the test's process: a
// Transport on a real host, so every call goes through the host's
// agent check, cap and timeout. It keeps the bytes of every call and checks
// them against deliver.schema.json.
type deliverPlugin struct {
	key    pluginmodel.EntryKey
	m      pluginmodel.Manifest
	schema *jsonschema.Schema

	mu      sync.Mutex
	mode    string
	calls   []gotNotice
	invalid []string
	// gate, when set, holds every call until it is closed.
	gate chan struct{}
}

func (p *deliverPlugin) setMode(m string) {
	p.mu.Lock()
	p.mode = m
	p.mu.Unlock()
}

func (p *deliverPlugin) Call(ctx context.Context, method string, params, result any) error {
	if method == pluginproto.MethodInitialize {
		*result.(*pluginproto.InitializeResponse) = pluginproto.InitializeResponse{Protocol: pluginproto.Version1, Name: p.m.Name, Version: p.m.Version, Hooks: p.m.Hooks}
		return nil
	}
	if method != pluginproto.MethodApprovalDeliver {
		return nil
	}
	raw, err := pluginproto.Marshal(params)
	if err != nil {
		return err
	}
	got := gotNotice{raw: raw}
	inst, ierr := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	p.mu.Lock()
	if ierr != nil || json.Unmarshal(raw, &got) != nil {
		p.invalid = append(p.invalid, string(raw))
	} else if err := p.schema.Validate(inst); err != nil {
		p.invalid = append(p.invalid, err.Error()+": "+string(raw))
	}
	p.calls = append(p.calls, got)
	mode, gate := p.mode, p.gate
	p.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	switch mode {
	case crashMode:
		return pluginmodel.Fail(pluginmodel.ClassBadResponse)
	case hangMode:
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (p *deliverPlugin) Close() error { return nil }

func (p *deliverPlugin) received() []gotNotice {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

// deliverEnv is a host with approval.deliver test plugins and the delivery
// over them, with a clock the test moves and an install id it controls.
type deliverEnv struct {
	t       *testing.T
	host    *Host
	senders *pluginSenders
	d       *pluginDelivery
	logs    *syncBuffer
	install uuid.UUID
	// offset is added to the real time: the engine's clock.
	offset atomic.Int64

	mu      sync.Mutex
	entries []pluginmodel.Entry
}

func (e *deliverEnv) now() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) }

func newDeliverEnv(t *testing.T) *deliverEnv {
	t.Helper()
	e := &deliverEnv{t: t, host: NewHost(), logs: &syncBuffer{}, install: uuid.Must(uuid.NewV7())}
	log := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.senders = newPluginSenders(e.host, e.now)
	e.d = newPluginDelivery(e.host, e.served, e.senders, e.now, RealClock(), log)
	e.d.timing = fastDeliver
	e.d.readInstall = func(context.Context, string) (uuid.UUID, error) { return e.install, nil }
	return e
}

func (e *deliverEnv) served() []pluginmodel.Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.entries)
}

// start runs the delivery until the end of the test.
func (e *deliverEnv) start() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.d.run(ctx, nil); close(done) }()
	e.t.Cleanup(func() {
		cancel()
		e.senders.stop()
		<-done
	})
}

// serve registers an approval.deliver entry served to agents, with its
// sender, as the engine keeps them.
func (e *deliverEnv) serve(name string, agents ...string) *deliverPlugin {
	e.t.Helper()
	k := pluginmodel.EntryKey{Name: name, Instance: "default"}
	m := feedManifest(name)
	m.Hooks = map[string]pluginproto.HookDecl{string(HookApprovalDeliver): {Contract: "deliver/1"}}
	p := &deliverPlugin{key: k, m: m, schema: deliverSchema(e.t)}
	en := pluginmodel.Entry{Key: k, Manifest: m, Agents: agents, Timeout: time.Second}
	require.NoError(e.t, e.host.Register(context.Background(), en, p))
	e.mu.Lock()
	e.entries = append(e.entries, en)
	keys := make([]pluginmodel.EntryKey, 0, len(e.entries))
	for _, x := range e.entries {
		keys = append(keys, x.Key)
	}
	e.mu.Unlock()
	e.senders.sync(keys)
	e.t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		require.Empty(e.t, p.invalid, "every notice the engine sent validates against deliver.schema.json")
	})
	return p
}

const (
	testApproval = "0193a1b3-1111-7000-8000-000000000001"
	testRevert   = "0193a1b3-2222-7000-8000-000000000001"
	localShort   = "http://localhost:8787/approvals/" + testApproval + "#s=q3Jv8sLk2mT0xYp1aBcD9w"
	portalLong   = "https://portal.basaltvault.app/reverts/" + testRevert + "#2.eJyrVkrLz1eyUkpKLFKqBQAc9wQ8"
)

// heldNotice is a held write's notice with link, expiring in an hour of
// the engine's clock.
func (e *deliverEnv) heldNotice(link string) linksvc.LinkNotice {
	return linksvc.LinkNotice{
		Kind: linksvc.NoticeApprovalRequested, ApprovalID: uuid.MustParse(testApproval), Headline: "Update 27 rows in public·leads",
		ExpiresAt: e.now().Add(time.Hour), Link: link,
	}
}

func waitNotices(t *testing.T, p *deliverPlugin, n int) []gotNotice {
	t.Helper()
	require.Eventually(t, func() bool { return len(p.received()) >= n }, 10*time.Second, 5*time.Millisecond)
	return p.received()
}

// The notice a plugin gets is the CloudEvent of the contract, built once:
// the agent's link byte for byte, the item, the headline, the expiry, and
// nothing else.
func TestNoticeIsTheContractsEvent(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	e.start()
	n := e.heldNotice(localShort)
	e.d.forAgent("product_a").DeliverLink(n)

	got := waitNotices(t, p, 1)[0]
	require.Equal(t, "agent:product_a", got.Agent)
	require.Equal(t, "dev.basaltdb.approval.requested", got.Event.Type)
	require.Equal(t, "urn:uuid:"+e.install.String(), got.Event.Source)
	require.Equal(t, "agent:product_a", got.Event.Subject)
	id, err := uuid.Parse(got.Event.ID)
	require.NoError(t, err)
	require.Equal(t, uuid.Version(7), id.Version())
	require.Equal(t, map[string]any{
		"kind": "APPROVAL_REQUESTED", "agent": "agent:product_a", "approvalId": testApproval, "headline": "Update 27 rows in public·leads",
		"expiresAt": n.ExpiresAt.UTC().Format(feedTimeLayout), "link": localShort, "linkOpens": "ENGINE_COMPUTER",
		"instruction": "Open the link on the computer Basalt runs on to review the held write and approve it with your passkey.",
	}, got.Event.Data)
	require.Contains(t, string(got.raw), `"link":"`+localShort+`"`, "the link's bytes, unescaped")
}

// TestNoticeSaysWhereItsLinkOpens: a portal link opens anywhere, a local
// one only on the engine's computer, and the instruction follows; each
// kind has its event type.
func TestNoticeSaysWhereItsLinkOpens(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	e.start()
	revertNotice := linksvc.LinkNotice{
		Kind: linksvc.NoticeRevertRequested, RevertID: uuid.MustParse(testRevert), ExpiresAt: e.now().Add(time.Hour), Link: portalLong,
		Headline: "Revert of run 0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b: 27 rows to restore, 0 left as they are (changed after the agent).",
	}
	e.d.forAgent("product_a").DeliverLink(revertNotice)
	got := waitNotices(t, p, 1)[0]
	require.Equal(t, "dev.basaltdb.revert.requested", got.Event.Type)
	require.Equal(t, "ANYWHERE", got.Event.Data["linkOpens"])
	require.Equal(t, portalLong, got.Event.Data["link"])
	require.Equal(t, testRevert, got.Event.Data["revertId"])
	require.NotContains(t, got.Event.Data, "approvalId")
	require.Equal(t, "Open the link to review the revert and sign it with your passkey.", got.Event.Data["instruction"])

	replaced := e.heldNotice(localShort)
	replaced.Kind = linksvc.NoticeLinkReplaced
	e.d.forAgent("product_a").DeliverLink(replaced)
	got = waitNotices(t, p, 2)[1]
	require.Equal(t, "dev.basaltdb.link.replaced", got.Event.Type)
	require.Equal(t, "LINK_REPLACED", got.Event.Data["kind"])
	require.Equal(t, "ENGINE_COMPUTER", got.Event.Data["linkOpens"])
}

// A notice with no link says to ask the agent. A link that is not one a
// notice may carry (a hash link, a page address, another item's link,
// another origin) is never sent: the engine does not rewrite it either.
func TestNoticeWithoutALinkSaysToAskTheAgent(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	e.start()
	links := []string{
		"",
		"http://localhost:8787/approvals/" + testApproval + "#h=abcdef",
		"http://localhost:8787/approvals/" + testApproval,
		"http://localhost:8787/approvals/" + testRevert + "#s=q3Jv8sLk2mT0xYp1aBcD9w",
		"http://localhost:8787/reverts/" + testApproval + "#s=q3Jv8sLk2mT0xYp1aBcD9w",
		"https://evil.example/approvals/" + testApproval + "#s=q3Jv8sLk2mT0xYp1aBcD9w",
	}
	for _, l := range links {
		e.d.forAgent("product_a").DeliverLink(e.heldNotice(l))
	}
	for _, got := range waitNotices(t, p, len(links)) {
		require.NotContains(t, got.Event.Data, "link", string(got.raw))
		require.NotContains(t, got.Event.Data, "linkOpens")
		require.Equal(t, "Ask the agent for the link to review the held write and approve it with your passkey.", got.Event.Data["instruction"])
		require.NotContains(t, string(got.raw), "evil.example")
	}
}

// DeliverLink is what runs on the agent's call. It returns while the plugin
// holds every call, while the database holds the install id read, while
// nothing takes notices at all, and when its buffer is full: the agent's
// answer never waits on a plugin, a database or the delivery.
func TestDeliverLinkNeverBlocks(t *testing.T) {
	t.Parallel()
	returns := func(t *testing.T, e *deliverEnv, n int) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			for range n {
				e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("DeliverLink waited")
		}
	}
	t.Run("the plugin holds every call", func(t *testing.T) {
		t.Parallel()
		e := newDeliverEnv(t)
		p := e.serve("acme-notify", "product_a")
		p.gate = make(chan struct{})
		e.start()
		returns(t, e, 1)
		waitNotices(t, p, 1) // the call is open, unanswered
		returns(t, e, 500)
		close(p.gate)
	})
	t.Run("the database holds the install id", func(t *testing.T) {
		t.Parallel()
		e := newDeliverEnv(t)
		p := e.serve("acme-notify", "product_a")
		release := make(chan struct{})
		reading := make(chan struct{}, 1000)
		e.d.readInstall = func(ctx context.Context, _ string) (uuid.UUID, error) {
			reading <- struct{}{}
			select {
			case <-release:
				return e.install, nil
			case <-ctx.Done():
				return uuid.Nil, ctx.Err()
			}
		}
		e.start()
		returns(t, e, 1)
		<-reading
		returns(t, e, 500)
		require.Empty(t, p.received(), "nothing left without the install id")
		require.Len(t, reading, 0, "one read of an agent's install id at a time")
		close(release)
	})
	t.Run("nothing takes notices", func(t *testing.T) {
		t.Parallel()
		e := newDeliverEnv(t)
		e.serve("acme-notify", "product_a")
		// The delivery is never started: the buffer fills, the rest drop.
		returns(t, e, deliverIntake+500)
		require.Len(t, e.d.intake, deliverIntake)
	})
}

// A plugin that hangs, fails or is gone gets each notice four times at
// most, then the notice is dropped and counted; one that answers gets it
// once, and every try carries the same bytes.
func TestNoticeIsTriedFourTimesThenDropped(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	p.setMode(crashMode)
	e.start()
	e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	require.Eventually(t, func() bool { return len(e.d.dropped("product_a")) == 1 }, 10*time.Second, 5*time.Millisecond)
	got := p.received()
	require.Len(t, got, 4, "at once and three more times")
	for _, g := range got {
		require.Equal(t, got[0].raw, g.raw, "the same id, time and bytes on every try")
	}
	require.Equal(t, []droppedNotices{{key: p.key, count: 1}}, e.d.dropped("product_a"))
	require.Empty(t, e.d.dropped("client_x"))

	p.setMode(answerAll)
	e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	waitNotices(t, p, 5)
	time.Sleep(3 * fastDeliver.tries[3])
	require.Len(t, p.received(), 5, "answered once: not tried again")
	require.Equal(t, 1, e.d.dropped("product_a")[0].count)
	require.NotContains(t, e.logs.String(), localShort, "no log line holds a link")
	require.NotContains(t, e.logs.String(), "public·leads")
}

// TestExpiredNoticeIsNeverSent: a notice at or past its expiry is dropped,
// not sent: when it is made, between tries, and while it waits for a
// worker behind calls that hang.
func TestExpiredNoticeIsNeverSent(t *testing.T) {
	t.Parallel()
	t.Run("expired when made", func(t *testing.T) {
		t.Parallel()
		e := newDeliverEnv(t)
		p := e.serve("acme-notify", "product_a")
		e.start()
		n := e.heldNotice(localShort)
		n.ExpiresAt = e.now()
		e.d.forAgent("product_a").DeliverLink(n)
		require.Eventually(t, func() bool { return len(e.d.dropped("product_a")) == 1 }, 10*time.Second, 5*time.Millisecond)
		require.Empty(t, p.received())
	})
	t.Run("expired between tries", func(t *testing.T) {
		t.Parallel()
		e := newDeliverEnv(t)
		e.d.timing.tries = []time.Duration{0, 300 * time.Millisecond, 600 * time.Millisecond, 900 * time.Millisecond}
		p := e.serve("acme-notify", "product_a")
		p.setMode(crashMode)
		e.start()
		e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
		waitNotices(t, p, 1)
		e.offset.Add(int64(2 * time.Hour)) // the engine's clock passes the expiry
		require.Eventually(t, func() bool { return len(e.d.dropped("product_a")) == 1 }, 10*time.Second, 5*time.Millisecond)
		require.Len(t, p.received(), 1, "never sent after its expiry")
	})
	t.Run("expired while it waits for a worker", func(t *testing.T) {
		t.Parallel()
		e := newDeliverEnv(t)
		p := e.serve("acme-notify", "product_a")
		gate := make(chan struct{})
		p.gate = gate
		e.start()
		// Four notices hold the entry's four workers.
		for range pluginproto.MaxInFlight {
			e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
		}
		waitNotices(t, p, pluginproto.MaxInFlight)
		short := e.heldNotice(localShort)
		short.ApprovalID = uuid.MustParse(testRevert)
		short.Link = ""
		short.ExpiresAt = e.now().Add(time.Minute)
		e.d.forAgent("product_a").DeliverLink(short)
		require.Eventually(t, func() bool { return len(e.senders.sender(p.key).notices) == 1 }, 10*time.Second, 5*time.Millisecond)
		e.offset.Add(int64(2 * time.Minute))
		close(gate)
		require.Eventually(t, func() bool { return len(e.d.dropped("product_a")) > 0 }, 10*time.Second, 5*time.Millisecond)
		for _, g := range p.received() {
			require.Equal(t, testApproval, g.Event.Data["approvalId"], "the expired one never left")
		}
	})
}

// Feed batches never starve a notice: with the feed's queue full and every
// shared worker held by a feed call that hangs, a notice still leaves.
func TestFeedNeverStarvesANotice(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	e.start()
	s := e.senders.sender(p.key)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	var held atomic.Int64
	feedCall := pluginCall{run: func(ctx context.Context, _ *Host, _ pluginmodel.EntryKey) error {
		held.Add(1)
		select {
		case <-hold:
		case <-ctx.Done():
		}
		return nil
	}}
	for s.Send(context.Background(), feedCall) == nil {
	}
	require.ErrorIs(t, s.Send(context.Background(), feedCall), errSenderFull)
	require.Eventually(t, func() bool { return held.Load() == pluginproto.MaxInFlight-1 }, 10*time.Second, 5*time.Millisecond,
		"feed calls hold every worker they may")

	e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	waitNotices(t, p, 1)
	require.Empty(t, e.d.dropped("product_a"))
}

// At most 100 notices wait per entry: one made while 100 wait is dropped.
func TestNoticeBeyondTheHundredWaitingIsDropped(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	gate := make(chan struct{})
	p.gate = gate
	e.start()
	for range deliverWaiting + 7 {
		e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	}
	require.Eventually(t, func() bool {
		d := e.d.dropped("product_a")
		return len(d) == 1 && d[0].count == 7
	}, 10*time.Second, 5*time.Millisecond)
	close(gate)
	waitNotices(t, p, deliverWaiting)
}

// TestOnlyListedAgentsGetANotice: an entry gets the notices of the agents
// it is served to and nothing of any other: no call, no name, and no
// dropped count for an agent it does not serve.
func TestOnlyListedAgentsGetANotice(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	one := e.serve("acme-one", "product_a")
	both := e.serve("acme-both", "product_a", "client_x")
	feedOnly := e.serve("acme-feed", "product_a", "client_x")
	// An entry that declares feed.observe only gets no notice.
	e.mu.Lock()
	e.entries[2].Manifest = feedManifest("acme-feed")
	e.mu.Unlock()
	e.start()

	e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	e.d.forAgent("client_x").DeliverLink(e.heldNotice(localShort))
	e.d.forAgent("unlisted").DeliverLink(e.heldNotice(localShort))
	waitNotices(t, one, 1)
	waitNotices(t, both, 2)
	time.Sleep(3 * fastDeliver.tries[3])
	require.Len(t, one.received(), 1)
	require.Equal(t, "agent:product_a", one.received()[0].Agent)
	require.NotContains(t, string(one.received()[0].raw), "client_x")
	require.Len(t, both.received(), 2)
	for _, g := range both.received() {
		require.Equal(t, g.Agent, g.Event.Subject)
		require.Equal(t, g.Agent, g.Event.Data["agent"])
	}
	require.Empty(t, feedOnly.received())
	for _, a := range []string{"product_a", "client_x", "unlisted"} {
		require.Empty(t, e.d.dropped(a), "an entry not served to an agent drops nothing of it")
	}

	// The host itself refuses a notice naming an agent the entry does not
	// list, whoever asks.
	raw, err := (madeNotice{id: uuid.Must(uuid.NewV7()), at: e.now(), agent: "client_x", n: e.heldNotice(localShort)}).event(e.install)
	require.NoError(t, err)
	require.ErrorIs(t, e.host.DeliverApproval(context.Background(), one.key, "client_x", raw), pluginmodel.ErrAgentNotListed)
	require.Len(t, one.received(), 1)
}

// An agent whose guard reports no install id gets no notice: each counts as
// dropped. A database that does not answer fails the try, not the agent.
func TestNoticeNeedsAnInstallID(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	var fail atomic.Bool
	e.d.readInstall = func(context.Context, string) (uuid.UUID, error) {
		if fail.Load() {
			return uuid.Nil, errors.New("connection refused: " + marker)
		}
		return uuid.Nil, guardmodel.ErrNoInstall
	}
	e.start()
	e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	require.Eventually(t, func() bool { return len(e.d.dropped("product_a")) == 1 }, 10*time.Second, 5*time.Millisecond)
	fail.Store(true)
	e.d.forAgent("product_a").DeliverLink(e.heldNotice(localShort))
	require.Eventually(t, func() bool { return e.d.dropped("product_a")[0].count == 2 }, 10*time.Second, 5*time.Millisecond)
	require.Empty(t, p.received())
	require.NotContains(t, e.logs.String(), marker, "a database's text is never logged")
}

// TestDroppedNoticeShowsInStatus: a dropped notice shows as
// PLUGIN_NOTICES_DROPPED in the status of its agent only, naming the entry
// and the count and nothing the notice was about, and goes away 24 hours
// after the last drop.
func TestDroppedNoticeShowsInStatus(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", "jsonrpc-stdio", "product_a", "client_x")
	var offset atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	ep := f.pluginsWith(Options{Ports: testPorts, Dialer: dial.Dialer{}, euid: os.Geteuid(), now: now}, slog.New(slog.DiscardHandler))
	require.NotNil(t, ep)
	dropped := func(name string) []pluginProblem {
		var out []pluginProblem
		for _, pr := range ep.pluginProblems(name) {
			if pr.Code == problemPluginNoticesDropped {
				out = append(out, pr)
			}
		}
		return out
	}
	require.Empty(t, dropped("product_a"))

	ep.delivery.drop("product_a", p.Key(), "every try failed")
	ep.delivery.drop("product_a", p.Key(), "every try failed")
	got := dropped("product_a")
	require.Len(t, got, 1)
	require.Equal(t, "acme-ner", got[0].Name)
	require.Equal(t, "default", got[0].Instance)
	require.Contains(t, got[0].Message, "plugin acme-ner/default did not get 2 approval notices of this agent in the last 24 hours")
	require.Empty(t, dropped("client_x"), "another agent of the same entry sees nothing")

	offset.Add(int64(23 * time.Hour))
	ep.delivery.drop("product_a", p.Key(), "every try failed")
	require.Contains(t, dropped("product_a")[0].Message, "3 approval notices")
	offset.Add(int64(2 * time.Hour))
	require.Contains(t, dropped("product_a")[0].Message, "1 approval notice of", "the two older than 24 hours no longer count")
	offset.Add(int64(23 * time.Hour))
	require.Empty(t, dropped("product_a"), "gone 24 hours after the last drop")
}

// The words a dropped notice leaves in status are fixed: no link, headline
// or id of the notice.
func TestDroppedNoticeMessageHoldsNothingOfTheNotice(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	p := e.serve("acme-notify", "product_a")
	p.setMode(crashMode)
	e.start()
	n := e.heldNotice(localShort)
	n.Headline = "Update 1 row in " + marker
	e.d.forAgent("product_a").DeliverLink(n)
	require.Eventually(t, func() bool { return len(e.d.dropped("product_a")) == 1 }, 10*time.Second, 5*time.Millisecond)
	logs := e.logs.String()
	for _, secret := range []string{marker, localShort, testApproval, "q3Jv8sLk2mT0xYp1aBcD9w"} {
		require.False(t, strings.Contains(logs, secret), "the log holds %q", secret)
	}
}

// TestListHealthFollowsTheEngine: PLUGIN_LIST's health of an entry is what
// the running engine knows of it: NOT_STARTED while the engine does not run
// it, READY while its plugin answers, UNAVAILABLE while the engine runs it
// or keeps trying to start it and it does not answer.
func TestListHealthFollowsTheEngine(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	k := pluginmodel.EntryKey{Name: "slack-notify", Instance: "default"}
	failing := pluginmodel.EntryKey{Name: "never-starts", Instance: "default"}
	ep := &Plugins{host: e.host, keptKeys: map[pluginmodel.EntryKey]bool{k: true, failing: true}}
	ep.sup = NewSupervisor(e.host, func(context.Context, pluginmodel.Entry) (pluginmodel.Transport, error) {
		return nil, errors.New("the plugin does not start")
	}, RealClock())
	require.Equal(t, HealthNotStarted, ep.healthOf(k, true))

	e.serve(k.Name, "product_a")
	require.Equal(t, HealthReady, ep.healthOf(k, true))
	require.Equal(t, HealthNotStarted, ep.healthOf(k, false),
		"an entry of engine.json with the name of the engine-kept one that runs is not the one running")
	e.host.SetState(k, StateUnavailable)
	require.Equal(t, HealthUnavailable, ep.healthOf(k, true))

	// An entry whose start fails is never registered: the engine keeps
	// trying, and until it answers it is UNAVAILABLE, as status says.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ep.sup.Wait()
	})
	m := feedManifest(failing.Name)
	require.NoError(t, ep.sup.Start(ctx, []pluginmodel.Entry{{Key: failing, Manifest: m, Agents: []string{"product_a"}, Timeout: time.Second}}))
	require.Equal(t, HealthUnavailable, ep.healthOf(failing, true))

	var none *Plugins
	require.Equal(t, HealthNotStarted, none.healthOf(k, true), "an engine that runs no plugin")
}
