//go:build unix

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// fastFeed is the feed's timing in tests: the contract's numbers, shrunk.
var fastFeed = feedTiming{
	poll: 40 * time.Millisecond, minBackoff: 100 * time.Millisecond, maxBackoff: 400 * time.Millisecond,
	follow: 20 * time.Millisecond, read: 5 * time.Second,
}

// feedSchema is feed.schema.json's request, as the contract fixes it.
func feedSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	const id = "https://basaltvault.app/schemas/plugin/protocol/feed.v1.json"
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "plugin", "protocol", "feed.schema.json"))
	require.NoError(t, err)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	// The schema's patterns use ECMA-262 \uXXXX escapes, which Go's regexp
	// spells \x{XXXX} (as api/plugin's contract test reads them).
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		return regexp.Compile(ecmaEscape.ReplaceAllString(s, `\x{$1}`))
	})
	require.NoError(t, c.AddResource(id, doc))
	sch, err := c.Compile(id + "#/$defs/request")
	require.NoError(t, err)
	return sch
}

// The test plugin's modes.
const (
	answerAll   = "answer"       // answers the last seq of each batch
	answerFirst = "answer-first" // answers the first seq of each batch
	answerBad   = "answer-bad"   // answers a seq that is not in the batch
	hangMode    = "hang"         // never answers; the call runs to its timeout
	crashMode   = "crash"        // its process exits on the call
)

// gotEvent is one event a test plugin received.
type gotEvent struct {
	ID, Source, Type, Time, Subject string
	Data                            map[string]any
}

func (g gotEvent) seq() int64 { return int64(g.Data["seq"].(float64)) }

// gotCall is one feed.observe call a test plugin received, as its bytes.
type gotCall struct {
	at     time.Time
	mode   string
	agent  string
	raw    []byte
	events []gotEvent
}

// feedPlugin is a feed.observe plugin in the test's process: a
// plugin.Transport registered on a real host, so every call goes through
// the host's cap, timeout and agent check. It checks every request it gets
// against feed.schema.json and keeps its bytes.
type feedPlugin struct {
	key    plugin.EntryKey
	m      plugin.Manifest
	schema *jsonschema.Schema

	mu      sync.Mutex
	mode    string
	calls   []gotCall
	invalid []string
}

func (p *feedPlugin) setMode(m string) {
	p.mu.Lock()
	p.mode = m
	p.mu.Unlock()
}

func (p *feedPlugin) Call(ctx context.Context, method string, params, result any) error {
	if method == protocol.MethodInitialize {
		*result.(*protocol.InitializeResponse) = protocol.InitializeResponse{Protocol: protocol.Version1, Name: p.m.Name, Version: p.m.Version, Hooks: p.m.Hooks}
		return nil
	}
	if method != protocol.MethodFeedObserve {
		return nil
	}
	raw, err := protocol.Marshal(params) // the bytes the transports send
	if err != nil {
		return err
	}
	c := gotCall{at: time.Now(), raw: raw}
	var req struct {
		Agent  string     `json:"agent"`
		Events []gotEvent `json:"events"`
	}
	inst, ierr := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	p.mu.Lock()
	if ierr != nil || p.schema.Validate(inst) != nil || json.Unmarshal(raw, &req) != nil {
		p.invalid = append(p.invalid, string(raw))
	}
	mode := p.mode
	c.agent, c.events, c.mode = req.Agent, req.Events, mode
	p.calls = append(p.calls, c)
	p.mu.Unlock()

	var last int64
	switch mode {
	case crashMode:
		return plugin.Fail(plugin.ClassExited)
	case hangMode:
		<-ctx.Done()
		return ctx.Err()
	case answerFirst:
		last = c.events[0].seq()
	case answerBad:
		last = c.events[len(c.events)-1].seq() + 1000
	default:
		last = c.events[len(c.events)-1].seq()
	}
	return json.Unmarshal(fmt.Appendf(nil, `{"lastSeq":%d}`, last), result)
}

func (p *feedPlugin) Close() error { return nil }

// received are the calls so far.
func (p *feedPlugin) received() []gotCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

// seqsFor are the seqs of every event received for agent, in order, with
// repeats.
func (p *feedPlugin) seqsFor(agent string) []int64 {
	var out []int64
	for _, c := range p.received() {
		if c.agent != agent {
			continue
		}
		for _, e := range c.events {
			out = append(out, e.seq())
		}
	}
	return out
}

// feedEnv is a guard with the fixture's two agents, each read through a
// pool of its own as the engine holds them, a host with test plugins, and
// the feed over them.
type feedEnv struct {
	t        *testing.T
	l        pluginLedgers
	pools    map[string]pluginLedger
	host     *plugin.Host
	stateDir string
	schema   *jsonschema.Schema
	logs     *syncBuffer
	log      *slog.Logger

	mu      sync.Mutex
	entries []plugin.Entry

	stop func()
	// feed is the feed last started.
	feed *pluginFeed
}

func newFeedEnv(t *testing.T) *feedEnv {
	t.Helper()
	f := newPluginFixture(t)
	l := newPluginLedgers(t, f)
	logs := &syncBuffer{}
	e := &feedEnv{
		t: t, l: l, pools: l.pools(t), host: plugin.NewHost(), stateDir: t.TempDir(), schema: feedSchema(t),
		logs: logs, log: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	t.Cleanup(func() {
		if e.stop != nil {
			e.stop()
		}
	})
	return e
}

func feedManifest(name string) plugin.Manifest {
	return plugin.Manifest{
		ManifestVersion: 1, Name: name, Version: "1.0.0", Publisher: "t", Protocol: []string{protocol.Version1},
		Hooks:    map[string]protocol.HookDecl{string(plugin.HookFeedObserve): {Contract: "feed/1"}},
		Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: "jsonrpc-stdio", Command: "bin/p"}},
	}
}

// serve registers a feed.observe entry of plugin name served to agents, as
// the supervisor does, and makes the engine serve it.
func (e *feedEnv) serve(name string, agents ...string) *feedPlugin {
	e.t.Helper()
	k := plugin.EntryKey{Name: name, Instance: "default"}
	p := &feedPlugin{key: k, m: feedManifest(name), schema: e.schema, mode: answerAll}
	e.t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		require.Empty(e.t, p.invalid, "every request the engine sent validates against feed.schema.json")
	})
	e.serveAgain(p, agents...)
	return p
}

// serveAgain registers p again, a new registration, served to agents.
func (e *feedEnv) serveAgain(p *feedPlugin, agents ...string) {
	e.t.Helper()
	en := plugin.Entry{Key: p.key, Manifest: p.m, Agents: agents, Timeout: 2 * time.Second}
	require.NoError(e.t, e.host.Register(context.Background(), en, p))
	e.mu.Lock()
	e.entries = append(e.entries, en)
	e.mu.Unlock()
}

// unserve stops serving entry k: the engine no longer runs it.
func (e *feedEnv) unserve(k plugin.EntryKey) {
	e.mu.Lock()
	e.entries = slices.DeleteFunc(e.entries, func(en plugin.Entry) bool { return en.Key == k })
	e.mu.Unlock()
	e.host.Unregister(k)
}

func (e *feedEnv) served() []plugin.Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.entries)
}

// start runs a feed until stop or the end of the test. A second start after
// stop is an engine restart.
func (e *feedEnv) start() {
	e.t.Helper()
	e.startWith(e.pools)
}

func (e *feedEnv) startWith(ledgers map[string]pluginLedger) {
	e.t.Helper()
	f := newPluginFeed(e.host, e.served, ledgers, e.stateDir, newPluginSenders(e.host, time.Now), plugin.RealClock(), e.log)
	f.timing = fastFeed
	e.feed = f
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.run(ctx); close(done) }()
	stopped := false
	e.stop = func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
			require.Empty(e.t, f.readers, "every reader stopped before the feed returned")
		}
	}
}

// cursor is entry k's cursor for agent, false while there is none.
func (e *feedEnv) cursor(k plugin.EntryKey, agent string) (feedCursor, bool) {
	raw, err := os.ReadFile(filepath.Join(e.stateDir, pluginCursorsDirName, k.Name, k.Instance, agent+".json"))
	if err != nil {
		return feedCursor{}, false
	}
	var c feedCursor
	return c, json.Unmarshal(raw, &c) == nil
}

// started waits until entry k's cursor for agent is written, and returns it.
func (e *feedEnv) started(k plugin.EntryKey, agent string) feedCursor {
	e.t.Helper()
	var c feedCursor
	require.Eventually(e.t, func() bool {
		var ok bool
		c, ok = e.cursor(k, agent)
		return ok
	}, 10*time.Second, 10*time.Millisecond, "the cursor of %s for %s", k, agent)
	return c
}

// waitCursor waits until entry k's cursor for agent is written at seq.
func (e *feedEnv) waitCursor(k plugin.EntryKey, agent string, seq int64) feedCursor {
	e.t.Helper()
	var c feedCursor
	require.Eventually(e.t, func() bool {
		var ok bool
		c, ok = e.cursor(k, agent)
		return ok && c.Seq == seq
	}, 10*time.Second, 10*time.Millisecond, "the cursor of %s for %s to reach %d", k, agent, seq)
	return c
}

// appendRow appends a ledger row for agent as _append does for the guard's
// own functions, and returns its seq.
func (e *feedEnv) appendRow(agent, kind string, op any, changeID any, detail map[string]any) int64 {
	e.t.Helper()
	raw, err := json.Marshal(detail)
	require.NoError(e.t, err)
	var seq int64
	// Plain SQL: the guard's own append, called as the admin to write each
	// kind exactly as its function writes it.
	require.NoError(e.t, e.l.d.Admin.QueryRow(context.Background(),
		`SELECT basalt_meta._append($1::name, $2::uuid, $3, NULL, $4, NULL, NULL, NULL, NULL, $5::jsonb)`,
		e.l.roles[agent], changeID, kind, op, string(raw)).Scan(&seq))
	return seq
}

// applied appends a write's CHANGE row for agent and returns its seq.
func (e *feedEnv) applied(agent string) int64 {
	e.t.Helper()
	return e.appendRow(agent, guard.KindChange, "UPDATE", uuid.Must(uuid.NewV7()), map[string]any{
		"runId": uuid.Must(uuid.NewV7()), "taskId": nil, "intent": "set the score", "statement": "UPDATE public.leads SET score = 1",
		"table": "public.leads", "rows": 1, "cascadedRows": 0, "durationMs": 3, "status": "APPLIED",
	})
}

// head is the chain head.
func (e *feedEnv) head() int64 {
	e.t.Helper()
	h, err := guard.ChainHeadSeq(context.Background(), e.l.d.Admin)
	require.NoError(e.t, err)
	return h
}

func (e *feedEnv) installID() uuid.UUID {
	e.t.Helper()
	id, err := guard.InstallID(context.Background(), e.l.d.Admin)
	require.NoError(e.t, err)
	return id
}

// waitSeqs waits until p received exactly want for agent, in order.
func waitSeqs(t *testing.T, p *feedPlugin, agent string, want ...int64) {
	t.Helper()
	if !assert.Eventually(t, func() bool { return slices.Equal(p.seqsFor(agent), want) }, 10*time.Second, 10*time.Millisecond) {
		require.Equal(t, want, p.seqsFor(agent), "for %s", agent)
	}
}

func (g gotEvent) afterSeq() (int64, bool) {
	v, ok := g.Data["afterSeq"].(float64)
	return int64(v), ok
}

// skippedAfter is the first skipped-ahead marker received for agent whose
// afterSeq is after, and the call that carried it.
func (p *feedPlugin) skippedAfter(agent string, after int64) (gotCall, gotEvent, bool) {
	for _, c := range p.received() {
		if c.agent != agent {
			continue
		}
		for _, e := range c.events {
			if e.Type != feedTypeSkipped {
				continue
			}
			if got, ok := e.afterSeq(); ok && got == after {
				return c, e, true
			}
		}
	}
	return gotCall{}, gotEvent{}, false
}

// waitSkipped waits until p received a skipped-ahead marker for agent after
// the given cursor, and returns the call that carried it and the marker.
func waitSkipped(t *testing.T, p *feedPlugin, agent string, after int64) (gotCall, gotEvent) {
	t.Helper()
	var call gotCall
	var ev gotEvent
	if !assert.Eventually(t, func() bool {
		var ok bool
		call, ev, ok = p.skippedAfter(agent, after)
		return ok
	}, 10*time.Second, 10*time.Millisecond) {
		require.Failf(t, "no skipped marker", "after %d for %s (seqs %v)", after, agent, p.seqsFor(agent))
	}
	return call, ev
}

// assertNoLaterSeqBefore asserts that no event delivered to agent before
// marker has a seq later than marker's.
func assertNoLaterSeqBefore(t *testing.T, p *feedPlugin, agent string, marker gotEvent) {
	t.Helper()
	for _, c := range p.received() {
		if c.agent != agent {
			continue
		}
		for _, e := range c.events {
			if e.ID == marker.ID {
				return
			}
			require.LessOrEqual(t, e.seq(), marker.seq(), "no event with a later seq arrived before the skipped marker")
		}
	}
	require.Fail(t, "skipped marker not among received events")
}

// settle lets several polls pass.
func settle() { time.Sleep(10 * fastFeed.poll) }

// Events reach the plugin in chain order, each once, as CloudEvents built
// from the install id and seq; more than 100 travel in batches of at most
// 100, and the cursor follows the answers.
func TestFeedDeliversInOrder(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.start()
	e.started(p.key, "product_a")
	a := e.applied("product_a")
	waitSeqs(t, p, "product_a", a)

	// While the engine is stopped, 130 more: a batch of 100, then 30.
	e.stop()
	want := make([]int64, 0, 131)
	want = append(want, a)
	for range 130 {
		want = append(want, e.applied("product_a"))
	}
	e.start()
	waitSeqs(t, p, "product_a", want...)
	install := e.installID()
	for i, c := range p.received() {
		require.LessOrEqual(t, len(c.events), protocol.MaxFeedEvents, "call %d", i)
		for _, ev := range c.events {
			require.Equal(t, fmt.Sprintf("%s:%d", install, ev.seq()), ev.ID)
			require.Equal(t, "urn:uuid:"+install.String(), ev.Source)
			require.Equal(t, "dev.basaltdb.write.applied", ev.Type)
			require.Equal(t, "product_a", ev.Subject)
			require.Equal(t, "product_a", ev.Data["agent"])
		}
	}
	calls := p.received()
	require.Len(t, calls, 3)
	require.Len(t, calls[1].events, protocol.MaxFeedEvents)
	require.Len(t, calls[2].events, 30)
	c, _ := e.cursor(p.key, "product_a")
	require.Equal(t, feedCursor{InstallID: install, Seq: want[len(want)-1]}, c)
	settle()
	require.Len(t, p.received(), 3, "nothing again")
}

// A plugin that was down gets every event it missed, once each, in order;
// one that handled only the first events of a batch gets the rest; an
// engine restart resumes from the cursor file.
func TestFeedResumesFromCursor(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.start()
	start := e.started(p.key, "product_a")

	p.setMode(answerBad)
	e.stop()
	a := []int64{e.applied("product_a"), e.applied("product_a"), e.applied("product_a")}
	e.start()
	require.Eventually(t, func() bool { return len(p.received()) >= 2 }, 10*time.Second, 10*time.Millisecond)
	c, _ := e.cursor(p.key, "product_a")
	require.Equal(t, start, c, "a bad answer moves nothing")

	p.setMode(answerFirst)
	require.Eventually(t, func() bool {
		c, _ := e.cursor(p.key, "product_a")
		return c.Seq == a[2]
	}, 10*time.Second, 10*time.Millisecond)
	// Refused: the same three each time. Then one at a time: the rest again.
	var after []int64
	for _, call := range p.received() {
		var seqs []int64
		for _, ev := range call.events {
			seqs = append(seqs, ev.seq())
		}
		if call.mode == answerBad {
			require.Equal(t, a, seqs)
			continue
		}
		after = append(after, seqs...)
	}
	require.Equal(t, []int64{a[0], a[1], a[2], a[1], a[2], a[2]}, after)

	// Restart: the cursor file holds; only what came after is sent.
	e.stop()
	p.setMode(answerAll)
	b := []int64{e.applied("product_a"), e.applied("product_a")}
	before := len(p.received())
	e.start()
	require.Eventually(t, func() bool {
		c, _ := e.cursor(p.key, "product_a")
		return c.Seq == b[1]
	}, 10*time.Second, 10*time.Millisecond)
	var resumed []int64
	for _, call := range p.received()[before:] {
		for _, ev := range call.events {
			resumed = append(resumed, ev.seq())
		}
	}
	require.Equal(t, b, resumed)
}

// When retention deleted rows after the cursor before they were delivered,
// the next call starts with the skipped marker; acknowledging it moves the
// cursor. A cursor of 0 is the chain's start: no marker.
func TestFeedSaysWhenItSkipped(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.applied("client_x") // the cursor starts past 0, the chain's start
	e.start()
	start := e.started(p.key, "product_a")
	require.Positive(t, start.Seq)
	e.stop()

	e.applied("product_a")
	e.applied("client_x")
	// A year and a day later: every row so far is past retention.
	e.l.d.Exec(t, `SELECT basalt_meta._prune(now() + interval '366 days')`)
	e.applied("client_x")
	next := e.applied("product_a")
	e.start()
	waitSeqs(t, p, "product_a", next-1, next)
	// The plugin records a call before the engine writes the cursor, and
	// the first delivery may be one call or several under load. Wait for
	// the marker and the cursor, not a call count or a cursor read right
	// after the call is seen.
	_, ev := waitSkipped(t, p, "product_a", start.Seq)
	assertNoLaterSeqBefore(t, p, "product_a", ev)
	install := e.installID()
	require.Equal(t, feedTypeSkipped, ev.Type)
	require.Equal(t, fmt.Sprintf("%s:skipped:%d:%d", install, start.Seq, next-1), ev.ID)
	require.Empty(t, ev.Time)
	e.waitCursor(p.key, "product_a", next)

	// No row of the agent left after the cursor: the marker names the head.
	e.stop()
	e.applied("product_a")
	e.l.d.Exec(t, `SELECT basalt_meta._prune(now() + interval '366 days')`)
	e.start()
	call, ev := waitSkipped(t, p, "product_a", next)
	require.Equal(t, feedTypeSkipped, ev.Type)
	require.Len(t, call.events, 1)
	require.Equal(t, e.head(), ev.seq(), "the head; the PRUNED row is the admin's")

	// A cursor at 0 is no gap.
	retired, err := guard.SeqRetired(context.Background(), e.l.d.Admin, 0)
	require.NoError(t, err)
	require.False(t, retired)
}

// No cursor: the feed starts at the chain head, with no history; a cursor
// file that cannot be read is replaced the same way.
func TestNewCursorStartsAtHead(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.applied("product_a")
	e.applied("product_a")
	head := e.head()
	e.start()
	c := e.started(p.key, "product_a")
	require.Equal(t, feedCursor{InstallID: e.installID(), Seq: head}, c)
	settle()
	require.Empty(t, p.received(), "no history")
	a := e.applied("product_a")
	waitSeqs(t, p, "product_a", a)

	e.stop()
	path := filepath.Join(e.stateDir, pluginCursorsDirName, "acme-feed", "default", "product_a.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	e.applied("product_a")
	head = e.head()
	e.start()
	require.Eventually(t, func() bool {
		c, ok := e.cursor(p.key, "product_a")
		return ok && c.Seq == head
	}, 10*time.Second, 10*time.Millisecond)
	settle()
	waitSeqs(t, p, "product_a", a)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// recordServed writes the record that begins serving entry k to product_a, as
// the engine writes it before it serves the entry, and returns its seq.
func (e *feedEnv) recordServed(k plugin.EntryKey, kind guard.PluginEventKind, egress ...string) int64 {
	e.t.Helper()
	if egress == nil {
		egress = []string{}
	}
	d := guard.PluginDetail{
		Name: k.Name, Instance: k.Instance, Version: "1.0.0", ManifestSHA256: strings.Repeat("ab", 32),
		SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Hooks: []string{"feed.observe"}, Egress: egress,
		Endpoint:  guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
		Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
	}
	require.NoError(e.t, guard.RecordPluginEntryEvent(context.Background(), e.l.dbs["product_a"].db, kind, d))
	return e.head()
}

// An entry that begins to be served to an agent again starts at the record
// that began it: nothing from the time it was not served reaches it. A
// PLUGIN_CHANGED that adds an egress host counts as a new start; one that
// changes nothing it may reach does not.
func TestServedAgainStartsAtHead(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.recordServed(p.key, guard.PluginEnabled)
	e.start()
	e.started(p.key, "product_a")
	a := e.applied("product_a")
	waitSeqs(t, p, "product_a", a)

	e.unserve(p.key)
	settle()
	e.recordServed(p.key, guard.PluginDisabled)
	e.applied("product_a") // while not served
	e.recordServed(p.key, guard.PluginEnabled)
	b := e.applied("product_a")
	e.serveAgain(p, "product_a")
	waitSeqs(t, p, "product_a", a, b)

	// A change that adds no host: what came before it still arrives.
	e.unserve(p.key)
	settle()
	c := e.applied("product_a")
	e.recordServed(p.key, guard.PluginChanged)
	d := e.applied("product_a")
	e.serveAgain(p, "product_a")
	waitSeqs(t, p, "product_a", a, b, c, d)

	// A change that adds an egress host is a new consent: a new start.
	e.unserve(p.key)
	settle()
	e.applied("product_a")
	e.recordServed(p.key, guard.PluginChanged, "hooks.example:443")
	f := e.applied("product_a")
	e.serveAgain(p, "product_a")
	waitSeqs(t, p, "product_a", a, b, c, d, f)
}

// A cursor of another install (the guard installed afresh, seqs begun
// again) starts at the record that serves the entry in the new ledger, or
// at the head when there is none.
func TestNewInstallStartsAtHead(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	q := e.serve("other-feed", "product_a")
	dir := filepath.Join(e.stateDir, pluginCursorsDirName)
	old, err := json.Marshal(feedCursor{InstallID: uuid.Must(uuid.NewV7()), Seq: 1})
	require.NoError(t, err)
	for _, k := range []plugin.EntryKey{p.key, q.key} {
		require.NoError(t, writeFileAtomic(filepath.Join(dir, k.Name, k.Instance), "product_a.json", old))
	}
	e.applied("product_a")
	enabled := e.recordServed(p.key, guard.PluginEnabled)
	a := e.applied("product_a")
	head := e.head()
	e.start()

	waitSeqs(t, p, "product_a", a)
	require.Eventually(t, func() bool {
		c, _ := e.cursor(q.key, "product_a")
		return c.InstallID == e.installID()
	}, 10*time.Second, 10*time.Millisecond, "the other entry started again too")
	b := e.applied("product_a")
	waitSeqs(t, p, "product_a", a, b)
	waitSeqs(t, q, "product_a", b)
	cp, _ := e.cursor(p.key, "product_a")
	require.Equal(t, feedCursor{InstallID: e.installID(), Seq: b}, cp)
	require.Less(t, enabled, head)
}

// feedKindCase is one ledger row and what feed/1 makes of it.
type feedKindCase struct {
	kind   string
	op     any
	change bool
	detail map[string]any
	// typ is the event's type, "" when the row is no event.
	typ string
	// data is the event's data besides installId, seq and agent.
	data map[string]any
}

// feedKindCases are one row per ledger kind the guard writes, each written
// as its function writes it: what is an event, and what is not.
func feedKindCases(run, task, approvalID, revertID uuid.UUID) []feedKindCase {
	held := map[string]any{
		"approvalId": approvalID, "runId": run, "taskId": task, "intent": "free text", "statement": "DELETE FROM x",
		"rows": 3, "rowsHash": "ab", "expiresAt": "2026-11-20T06:03:02.123456+00:00",
	}
	return []feedKindCase{
		{
			kind: "CHANGE", op: "DELETE", change: true, typ: "dev.basaltdb.write.applied",
			detail: map[string]any{"runId": run, "taskId": task, "intent": "i", "statement": "s", "table": "public.leads", "rows": 3, "cascadedRows": 2, "durationMs": 1, "status": "APPLIED"},
			data:   map[string]any{"runId": run.String(), "taskId": task.String(), "op": "DELETE", "table": "public.leads", "rows": float64(3), "cascadedRows": float64(2)},
		},
		{kind: "CHANGE", op: "UPDATE", change: true, detail: map[string]any{"runId": run, "status": "PREVIEW", "rows": 1}},
		{
			kind: "REFUSED", op: "UPDATE", change: true, typ: "dev.basaltdb.write.refused",
			detail: map[string]any{"runId": run, "taskId": nil, "intent": "i", "statement": "s", "code": "ROW_LIMIT_EXCEEDED", "reason": "too many"},
			data:   map[string]any{"runId": run.String(), "op": "UPDATE", "reasonCode": "ROW_LIMIT_EXCEEDED"},
		},
		{
			kind: "REFUSED", op: "OTHER", change: true, typ: "dev.basaltdb.write.refused",
			detail: map[string]any{"runId": nil, "code": "NOT_A_CONTRACT_CODE", "reason": "r"},
			data:   map[string]any{"op": "OTHER"},
		},
		{kind: "REFUSED", op: "SELECT", change: true, detail: map[string]any{"runId": run, "code": "QUERY_TIMEOUT"}},
		{
			kind: "APPROVAL_PENDING", op: "DELETE", change: true, typ: "dev.basaltdb.write.held", detail: held,
			data: map[string]any{"approvalId": approvalID.String(), "runId": run.String(), "taskId": task.String(), "op": "DELETE", "rows": float64(3), "expiresAt": "2026-11-20T06:03:02.123456Z"},
		},
		{
			kind: "APPROVED", change: true, typ: "dev.basaltdb.approval.signed",
			detail: map[string]any{"approvalId": approvalID, "credentialId": "abcd", "relayedBy": "basalt_agent_client_x"},
			data:   map[string]any{"approvalId": approvalID.String()},
		},
		{
			kind: "REVERT_PENDING", typ: "dev.basaltdb.revert.prepared",
			detail: map[string]any{"revertId": revertID, "select": map[string]any{"scope": "RUN"}, "rows": 4},
			data:   map[string]any{"revertId": revertID.String()},
		},
		{
			kind: "REVERT_SIGNED", op: "REVERT", change: true, typ: "dev.basaltdb.revert.signed",
			detail: map[string]any{"revertId": revertID, "credentialId": "abcd", "skipped": []any{"x"}},
			data:   map[string]any{"revertId": revertID.String()},
		},
		{
			kind: "REVERTED", op: "REVERT", change: true, typ: "dev.basaltdb.revert.applied",
			detail: map[string]any{"revertId": revertID, "rows": 4},
			data:   map[string]any{"revertId": revertID.String()},
		},
		{
			kind: "REVERT_REJECTED", typ: "dev.basaltdb.revert.rejected",
			detail: map[string]any{"revertId": revertID, "note": "no", "via": "LINK_OR_AGENT"},
			data:   map[string]any{"revertId": revertID.String()},
		},
		{kind: "REVERT_BATCH", op: "REVERT", change: true, detail: map[string]any{"revertId": revertID}},
		{kind: "REVERT_RESCOPED", detail: map[string]any{"revertId": revertID}},
		{kind: "REVERT_RESET", detail: map[string]any{"revertId": revertID}},
		{kind: "READ", op: "SELECT", change: true, detail: map[string]any{"runId": run}},
		{kind: "ROW_CHANGE", op: "UPDATE", change: true, detail: map[string]any{"xmin": "1"}},
		{kind: "RUN_STARTED", detail: map[string]any{"runId": run}},
		{kind: "PRUNED", detail: map[string]any{"rowsDeleted": 1}},
		{kind: "HEARTBEAT", detail: map[string]any{"runId": nil}},
		{kind: "DEAD_MAN", detail: map[string]any{"runId": nil}},
		{kind: "UNCOVERED_TABLES", detail: map[string]any{"runId": nil}},
		{kind: "AGENT_POLICY_ADDED", detail: map[string]any{}},
		{kind: "AGENT_SETUP", detail: map[string]any{}},
		{kind: "ENGINE_RECORDED", detail: map[string]any{}},
		{kind: "ENGINE_REVOKED", detail: map[string]any{}},
		{kind: "PIN_SET_ASIDE", detail: map[string]any{}},
		{kind: "TRUST_PIN_RECORDED", detail: map[string]any{"host": "db.example.com", "port": 5432}},
		{kind: "PASSKEY_REVOKED", detail: map[string]any{}},
		{kind: "ROWS_REVEALED", detail: map[string]any{}},
		{kind: "PLUGIN_ENABLED", detail: map[string]any{"name": "zz-other", "instance": "default"}},
		{kind: "PLUGIN_DISABLED", detail: map[string]any{"name": "zz-other", "instance": "default"}},
		{kind: "PLUGIN_CHANGED", detail: map[string]any{"name": "zz-other", "instance": "default"}},
		{kind: "PLUGIN_TRUST_ADDED", detail: map[string]any{"signerKeyId": "x"}},
		{kind: "PLUGIN_TRUST_REMOVED", detail: map[string]any{"signerKeyId": "x"}},
		{kind: "PLUGIN_APPROVAL_PENDING", detail: map[string]any{}},
		{kind: "PLUGIN_APPROVED", detail: map[string]any{}},
	}
}

// What guardLedgerKinds reads in the guard's SQL.
var (
	appendKind = regexp.MustCompile(`_append\(\s*[^,()]+,\s*[^,()]+,\s*'([A-Z_]+)'`)
	kindList   = regexp.MustCompile(`p_kind NOT IN \(([^)]*)\)`)
	quoted     = regexp.MustCompile(`'([A-Z_]+)'`)
	ecmaEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

// setupKinds are the kinds of a setup (basalt_meta.setups), which a
// function checks with the same words as a ledger kind: not ledger kinds.
var setupKinds = []string{"INSTALL", "AGENT", "UPGRADE"}

// guardLedgerKinds are the ledger kinds the guard's functions write: each
// literal kind passed to _append, and the kinds a function takes as an
// argument and checks against a fixed list.
func guardLedgerKinds(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "guard", "schema", "*.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	var out []string
	add := func(k string) {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, m := range appendKind.FindAllStringSubmatch(string(raw), -1) {
			add(m[1])
		}
		for _, m := range kindList.FindAllStringSubmatch(string(raw), -1) {
			for _, k := range quoted.FindAllStringSubmatch(m[1], -1) {
				add(k[1])
			}
		}
	}
	return out
}

// Every ledger kind is either an event of the type the contract names, with
// exactly the fields it fixes, or not sent at all. A kind the guard writes
// that this test does not know fails it: a new kind is not an event until
// the contract says so.
func TestOnlyEventKindsAreSent(t *testing.T) {
	t.Parallel()
	run, task := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	approvalID, revertID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	cases := feedKindCases(run, task, approvalID, revertID)
	known := map[string]bool{}
	for _, c := range cases {
		known[c.kind] = true
	}
	for _, k := range guardLedgerKinds(t) {
		if slices.Contains(setupKinds, k) {
			continue
		}
		require.True(t, known[k], "ledger kind %s: decide whether it is an event (CONTRACT.md, Which ledger rows are events)", k)
	}

	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.start()
	e.started(p.key, "product_a")
	install := e.installID()
	type want struct {
		seq  int64
		typ  string
		data map[string]any
	}
	var wants []want
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			var change any
			id := uuid.Must(uuid.NewV7())
			if c.change {
				change = id
			}
			seq := e.appendRow("product_a", c.kind, c.op, change, c.detail)
			if c.typ == "" {
				return
			}
			data := map[string]any{"installId": install.String(), "seq": float64(seq), "agent": "product_a"}
			for k, v := range c.data {
				data[k] = v
			}
			if c.change {
				data["changeId"] = id.String()
			}
			wants = append(wants, want{seq: seq, typ: c.typ, data: data})
		})
	}
	seqs := make([]int64, 0, len(wants))
	for _, w := range wants {
		seqs = append(seqs, w.seq)
	}
	waitSeqs(t, p, "product_a", seqs...)
	var got []gotEvent
	for _, c := range p.received() {
		got = append(got, c.events...)
	}
	for i, w := range wants {
		require.Equal(t, w.typ, got[i].Type, "seq %d", w.seq)
		require.Equal(t, w.data, got[i].Data, "seq %d", w.seq)
		require.NotEmpty(t, got[i].Time)
	}
	settle()
	require.Len(t, p.seqsFor("product_a"), len(wants), "nothing else")
}

// Two entries, one listing product_a, one listing both agents: each gets
// only the events of the agents it is served to, each call names one agent
// and holds only its events. An agent an entry lists but is not served to
// produces nothing for it.
func TestOnlyListedAgentsReachAnEntry(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	one := e.serve("acme-one", "product_a")
	both := e.serve("acme-both", "product_a", "client_x")
	e.start()
	e.started(one.key, "product_a")
	e.started(both.key, "product_a")
	e.started(both.key, "client_x")

	a1, x1, a2, x2 := e.applied("product_a"), e.applied("client_x"), e.applied("product_a"), e.applied("client_x")
	waitSeqs(t, one, "product_a", a1, a2)
	waitSeqs(t, both, "product_a", a1, a2)
	waitSeqs(t, both, "client_x", x1, x2)
	settle()
	require.Empty(t, one.seqsFor("client_x"))
	for _, p := range []*feedPlugin{one, both} {
		for _, c := range p.received() {
			for _, ev := range c.events {
				require.Equal(t, c.agent, ev.Subject)
				require.Equal(t, c.agent, ev.Data["agent"])
			}
			require.NotContains(t, string(c.raw), e.l.roles["client_x"], "never a role name")
			if c.agent == "product_a" {
				require.NotContains(t, string(c.raw), "client_x")
			}
		}
	}
	_, ok := e.cursor(one.key, "client_x")
	require.False(t, ok, "no reader for an agent the entry is not served to")

	// Served to product_a only now (the engine withholds client_x): nothing
	// more of client_x reaches it.
	e.unserve(both.key)
	e.serveAgain(both, "product_a")
	settle()
	e.applied("client_x")
	a3 := e.applied("product_a")
	waitSeqs(t, both, "product_a", a1, a2, a3)
	settle()
	require.Equal(t, []int64{x1, x2}, both.seqsFor("client_x"))
}

// A plugin that answers wrongly (or is down, slow) gets a call after 5 s, then 10, 20, up to 60 (here
// shrunk); an answer sets it back to the poll. A database that does not
// answer moves nothing and backs off too.
func TestFeedBacksOffWhenPluginDown(t *testing.T) {
	t.Parallel()
	e := newFeedEnv(t)
	p := e.serve("acme-feed", "product_a")
	e.start()
	start := e.started(p.key, "product_a")
	p.setMode(answerBad)
	a := e.applied("product_a")
	require.Eventually(t, func() bool { return len(p.received()) >= 5 }, 10*time.Second, 10*time.Millisecond)
	calls := p.received()
	gaps := make([]time.Duration, 0, len(calls))
	for i := 1; i < len(calls); i++ {
		gaps = append(gaps, calls[i].at.Sub(calls[i-1].at))
	}
	slack := fastFeed.minBackoff / 2
	require.GreaterOrEqual(t, gaps[0], fastFeed.minBackoff-slack)
	require.GreaterOrEqual(t, gaps[1], 2*fastFeed.minBackoff-slack)
	require.GreaterOrEqual(t, gaps[2], 4*fastFeed.minBackoff-slack)
	require.GreaterOrEqual(t, gaps[3], fastFeed.maxBackoff-slack, "capped")
	require.Less(t, gaps[3], 4*fastFeed.maxBackoff, "capped, not doubled again")
	c, _ := e.cursor(p.key, "product_a")
	require.Equal(t, start, c)
	for _, call := range calls {
		require.Len(t, call.events, 1, "events wait in the ledger: the same one each time")
	}

	p.setMode(answerAll)
	require.Eventually(t, func() bool {
		c, _ := e.cursor(p.key, "product_a")
		return c.Seq == a
	}, 10*time.Second, 10*time.Millisecond)
	b := e.applied("product_a")
	sent := time.Now()
	require.Eventually(t, func() bool { return slices.Contains(p.seqsFor("product_a"), b) }, 10*time.Second, 5*time.Millisecond)
	require.Less(t, time.Since(sent), 5*time.Second, "back to the poll after an answer")

	// A database that does not answer: nothing is read, nothing moves.
	e.stop()
	dead, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none?connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(dead.Close)
	before := len(p.received())
	e.startWith(map[string]pluginLedger{"product_a": {db: dead}})
	e.applied("product_a")
	settle()
	require.Len(t, p.received(), before)
	c, _ = e.cursor(p.key, "product_a")
	require.Equal(t, b, c.Seq)
	require.Contains(t, e.logs.String(), "plugin feed paused")
}

// An agent's write takes no longer with a dead, hanging or crashing feed
// plugin than with none: the feed holds no connection of the agent's pool
// while it calls a plugin, so even a pool of one connection is free.
func TestFeedNeverSlowsAnAgentCall(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"dead", hangMode, crashMode} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			e := newFeedEnv(t)
			cfg, err := pgxpool.ParseConfig(e.l.urls["product_a"])
			require.NoError(t, err)
			cfg.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			p := e.serve("acme-feed", "product_a")
			e.startWith(map[string]pluginLedger{"product_a": {db: pool}})
			e.started(p.key, "product_a")
			switch mode {
			case "dead":
				e.host.Unregister(p.key)
			default:
				p.setMode(mode)
			}

			in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "raise the score"}
			require.NoError(t, guard.StartRun(context.Background(), pool, in))
			e.applied("product_a")
			if mode == hangMode {
				require.Eventually(t, func() bool { return len(p.received()) == 1 }, 10*time.Second, 5*time.Millisecond)
			}
			for i := range 20 {
				if mode == hangMode && i == 0 {
					require.Zero(t, pool.Stat().AcquiredConns(), "the feed holds no connection while it calls the plugin")
				}
				begun := time.Now()
				err := pool.AcquireFunc(context.Background(), func(c *pgxpool.Conn) error {
					return guardedWrite(context.Background(), c.Conn(), in, fmt.Sprintf("UPDATE public.leads SET score = %d WHERE id = 1", i))
				})
				require.NoError(t, err)
				require.Less(t, time.Since(begun), time.Second, "write %d", i)
				if mode == crashMode {
					// The supervisor would start it again: it crashes again.
					e.host.SetState(p.key, plugin.StateReady)
				}
				time.Sleep(fastFeed.poll / 4)
			}
		})
	}
}

// guardedWrite is one write as the engine runs it (guardtest.Guarded,
// without its test dependency on t).
func guardedWrite(ctx context.Context, c *pgx.Conn, in guard.Intent, stmt string) error {
	return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(ctx, tx, in, 5*time.Second); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return err
		}
		_, err := guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: stmt})
		return err
	})
}
