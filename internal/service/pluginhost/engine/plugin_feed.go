package engine

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// Feed timing (CONTRACT.md, Plugins, Notifier messages, Limits and numbers).
const (
	// feedPoll is how often a served agent's ledger is read for an entry.
	feedPoll = 5 * time.Second
	// After a failed round the next waits feedMinBackoff, doubling up to
	// feedMaxBackoff; an answer sets it back.
	feedMinBackoff = 5 * time.Second
	feedMaxBackoff = 60 * time.Second
	// feedFollow is how often the feed follows the entries the engine
	// serves: a reader starts for an agent an entry begins to be served to,
	// and stops for one it no longer is.
	feedFollow = time.Second
	// feedReadTimeout bounds one read of an agent's ledger.
	feedReadTimeout = 5 * time.Second
)

// pluginCursorsDirName is the directory under the engine's state directory
// that holds the feed cursors: <name>/<instance>/<agent>.json.
const pluginCursorsDirName = "plugin-cursors"

// feedTiming are the feed's intervals; tests shorten them.
type feedTiming struct {
	poll, minBackoff, maxBackoff, follow, read time.Duration
}

var defaultFeedTiming = feedTiming{poll: feedPoll, minBackoff: feedMinBackoff, maxBackoff: feedMaxBackoff, follow: feedFollow, read: feedReadTimeout}

// pluginFeed feeds feed.observe entries (CONTRACT.md, Notifier messages):
// for each entry the engine serves that declares the hook, and each agent
// it is served to, a reader reads that agent's ledger after the entry's
// cursor, through that agent's own access, and sends what it finds through
// the entry's sender. It follows the entries served now (served), not a
// list read at start, and keeps the senders of every entry that declares a
// notifier hook. It holds no event in memory between rounds: events wait in
// the ledger. Nothing an agent does waits on it.
type pluginFeed struct {
	host    *pluginhost.Host
	served  func() []pluginhost.Entry
	ledgers map[string]AgentLedger
	// dir is <stateDir>/plugin-cursors.
	dir     string
	senders *pluginSenders
	clock   pluginhost.Clock
	log     *slog.Logger
	timing  feedTiming

	// reads lets one feed read run per agent at a time, so the feed takes
	// at most one connection of an agent's pool.
	reads   map[string]chan struct{}
	readers map[feedPair]*feedReader
}

// feedPair is one entry and one agent it is served to.
type feedPair struct {
	key   pluginhost.EntryKey
	agent string
}

// newPluginFeed feeds the entries served returns, with the agents' ledgers,
// keeping cursors under stateDir; with no stateDir it feeds nothing and
// only keeps the senders.
func newPluginFeed(host *pluginhost.Host, served func() []pluginhost.Entry, ledgers map[string]AgentLedger, stateDir string,
	senders *pluginSenders, clock pluginhost.Clock, log *slog.Logger,
) *pluginFeed {
	if host == nil || served == nil || senders == nil || clock == nil || log == nil {
		panic("engine: the plugin feed needs a host, the served entries, senders, a clock and a log")
	}
	dir := ""
	if stateDir != "" {
		dir = filepath.Join(stateDir, pluginCursorsDirName)
	}
	reads := make(map[string]chan struct{}, len(ledgers))
	for name := range ledgers {
		reads[name] = make(chan struct{}, 1)
	}
	return &pluginFeed{
		host: host, served: served, ledgers: ledgers, dir: dir,
		senders: senders, clock: clock, log: log, timing: defaultFeedTiming,
		reads: reads, readers: map[feedPair]*feedReader{},
	}
}

// run follows the served entries until ctx is done, then stops every reader
// and sender before it returns.
func (f *pluginFeed) run(ctx context.Context) {
	defer f.senders.stop()
	// The readers running when ctx ends, not those of the start.
	defer func() { f.stopReaders(slices.Collect(maps.Keys(f.readers))) }()
	for {
		f.follow(ctx)
		select {
		case <-ctx.Done():
			return
		case <-f.clock.After(f.timing.follow):
		}
	}
}

// follow starts a reader for each entry and agent served now and stops the
// others, and keeps a sender for each served entry that declares a
// notifier hook.
func (f *pluginFeed) follow(ctx context.Context) {
	var notifiers []pluginhost.EntryKey
	want := map[feedPair]bool{}
	for _, e := range f.served() {
		_, feeds := e.Manifest.Hooks[string(pluginhost.HookFeedObserve)]
		_, delivers := e.Manifest.Hooks[string(pluginhost.HookApprovalDeliver)]
		if feeds || delivers {
			notifiers = append(notifiers, e.Key)
		}
		if !feeds || f.dir == "" {
			// No state directory: no cursor can be kept, so nothing is fed.
			continue
		}
		for _, a := range e.Agents {
			if _, ok := f.ledgers[a]; ok {
				want[feedPair{key: e.Key, agent: a}] = true
			}
		}
	}
	var stop []feedPair
	for p := range f.readers {
		if !want[p] {
			stop = append(stop, p)
		}
	}
	f.stopReaders(stop)
	f.senders.sync(notifiers)
	for p := range want {
		if f.readers[p] == nil && ctx.Err() == nil {
			f.readers[p] = f.startReader(ctx, p)
		}
	}
}

func (f *pluginFeed) stopReaders(pairs []feedPair) {
	for _, p := range pairs {
		f.readers[p].cancel()
	}
	for _, p := range pairs {
		<-f.readers[p].done
		delete(f.readers, p)
	}
}

func (f *pluginFeed) startReader(ctx context.Context, p feedPair) *feedReader {
	ctx, cancel := context.WithCancel(ctx)
	r := &feedReader{
		f: f, pair: p, ledger: f.ledgers[p.agent], cancel: cancel, done: make(chan struct{}),
		log: f.log.With("plugin", p.key.String(), "agent", p.agent),
	}
	go func() {
		defer close(r.done)
		r.run(ctx)
	}()
	return r
}

// feedReader feeds one entry the ledger of one agent it is served to.
type feedReader struct {
	f      *pluginFeed
	pair   feedPair
	ledger AgentLedger
	log    *slog.Logger
	cancel context.CancelFunc
	done   chan struct{}

	// cur is the cursor, loaded from its file at the first read; nil until
	// then, or while there is none.
	cur *feedCursor
	// floor is the chain head of the last read that found no event after
	// the cursor: the next read starts after it. In memory only: the cursor
	// moves only on an answer.
	floor int64
	// failing: the last round failed (logged once per run of failures).
	failing bool
}

// feedCursor is the cursor file's content.
type feedCursor struct {
	InstallID uuid.UUID `json:"installId"`
	Seq       int64     `json:"seq"`
}

// roundResult is what a round asks of the next.
type roundResult int

const (
	roundIdle   roundResult = iota // wait feedPoll
	roundMore                      // read again at once
	roundFailed                    // back off
)

func (r *feedReader) run(ctx context.Context) {
	var backoff time.Duration
	for {
		wait := r.f.timing.poll
		switch r.round(ctx) {
		case roundMore:
			backoff, wait = 0, 0
		case roundFailed:
			backoff = nextFeedBackoff(backoff, r.f.timing)
			wait = backoff
		default:
			backoff = 0
		}
		if ctx.Err() != nil {
			return
		}
		if wait == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-r.f.clock.After(wait):
		}
	}
}

func nextFeedBackoff(prev time.Duration, t feedTiming) time.Duration {
	if prev == 0 {
		return t.minBackoff
	}
	return min(2*prev, t.maxBackoff)
}

// round reads what waits for the entry after the cursor and sends it. A
// round that cannot reach the entry or the agent's database, or gets a bad
// answer, fails and moves nothing.
func (r *feedReader) round(ctx context.Context) roundResult {
	k := r.pair.key
	reg, ok := r.f.host.Registration(k)
	if !ok || r.f.host.State(k) != pluginhost.StateReady {
		// Not logged: status shows the entry PLUGIN_UNAVAILABLE.
		r.failing = true
		return roundFailed
	}
	b, err := r.read(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return roundIdle
		}
		return r.failed("the agent's ledger could not be read", dbFailure(err))
	}
	if len(b.events) == 0 {
		return r.ok(roundIdle)
	}
	return r.send(ctx, reg, b)
}

// send sends batch b on registration reg and moves the cursor to the
// answer.
func (r *feedReader) send(ctx context.Context, reg pluginhost.Registration, b feedRead) roundResult {
	k := r.pair.key
	raw, seqs, err := feedBatch(b.events)
	if err != nil {
		return r.failed("the events could not be encoded", nil)
	}
	s := r.f.senders.sender(k)
	if s == nil {
		return r.failed("the plugin is not served", nil)
	}
	var last int64
	outcome := make(chan error, 1)
	agent := r.pair.agent
	err = s.Send(ctx, pluginCall{
		run: func(ctx context.Context, h *pluginhost.Host, k pluginhost.EntryKey) error {
			var err error
			last, err = h.ObserveFeedOn(ctx, k, reg, agent, raw)
			return err
		},
		done: func(err error) { outcome <- err },
	})
	if err != nil {
		if ctx.Err() != nil {
			return roundIdle
		}
		return r.failed("the plugin's queue is full", nil)
	}
	select {
	case <-ctx.Done():
		return roundIdle
	case err = <-outcome:
	}
	if err != nil {
		return r.failed("the call failed", callFailure(err))
	}
	r.moveTo(b.install, last)
	if last != seqs[len(seqs)-1] || len(seqs) == pluginproto.MaxFeedEvents {
		return r.ok(roundMore)
	}
	return r.ok(roundIdle)
}

func (r *feedReader) ok(res roundResult) roundResult {
	if r.failing {
		r.log.Info("plugin feed delivers again")
	}
	r.failing = false
	return res
}

// failed logs a failed round once per run of failures: the entry, the agent
// and why, in fixed words and a failure class, never a database's or a
// plugin's text.
func (r *feedReader) failed(why string, class *string) roundResult {
	if !r.failing {
		args := []any{"why", why}
		if class != nil {
			args = append(args, "class", *class)
		}
		r.log.Warn("plugin feed paused; it backs off and resumes from its cursor", args...)
	}
	r.failing = true
	return roundFailed
}

// callFailure is a failed call's class.
func callFailure(err error) *string {
	c := ""
	var ce *pluginhost.CallError
	switch {
	case errors.As(err, &ce):
		c = string(ce.Class)
	case errors.Is(err, pluginhost.ErrAgentNotListed):
		c = "NOT_LISTED"
	case errors.Is(err, errSenderStopped):
		c = "STOPPED"
	default:
		c = string(pluginhost.ClassUnavailable)
	}
	return &c
}

// dbFailure is a failed read's class: whether the database answered, and
// its SQLSTATE when it did. Never its message, which can quote a value.
func dbFailure(err error) *string {
	c := "NO_ANSWER"
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		c = "SQLSTATE " + pg.Code
	} else if !transientErr(err) {
		c = "UNREADABLE"
	}
	return &c
}

// feedRead is what one read found: the install id it read under and the
// events to send, in seq order.
type feedRead struct {
	install uuid.UUID
	events  []feedEvent
}

// errNoInstallID: the agent's guard reports no install id, so it gets no
// event.
var errNoInstallID = errors.New("the agent's guard reports no install id")

// read reads, in one snapshot of the agent's database, where the cursor
// stands and the events after it (CONTRACT.md, Notifier messages, The
// cursor). It holds the connection for the read only, never while a plugin
// is called, and at most one feed read runs per agent.
func (r *feedReader) read(ctx context.Context) (feedRead, error) {
	sem := r.f.reads[r.pair.agent]
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return feedRead{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, r.f.timing.read)
	defer cancel()
	if r.ledger.admit != nil {
		if err := r.ledger.admit(ctx); err != nil {
			return feedRead{}, err
		}
	}
	var out feedRead
	err := r.ledger.ports.Guard.ReadSnapshot(ctx, r.ledger.db, func(tx guardmodel.FeedSnapshot) error {
		var err error
		out, err = r.readIn(ctx, tx)
		return err
	})
	if errors.Is(err, errNoInstallID) {
		return feedRead{}, nil
	}
	return out, err
}

// readIn is read within the snapshot tx.
func (r *feedReader) readIn(ctx context.Context, tx guardmodel.FeedSnapshot) (feedRead, error) {
	install, err := tx.InstallID(ctx)
	if errors.Is(err, guardmodel.ErrNoInstall) {
		return feedRead{}, errNoInstallID
	}
	if err != nil {
		return feedRead{}, err
	}
	head, err := tx.ChainHeadSeq(ctx)
	if err != nil {
		return feedRead{}, err
	}
	if r.cur == nil {
		r.load()
	}
	out := feedRead{install: install}
	k := r.pair.key
	switch {
	case r.cur == nil:
		// No cursor, or one that cannot be read: the chain head, with no
		// history.
		r.startAt(install, head)
		return out, nil
	case r.cur.InstallID != install:
		// The guard was installed afresh and seqs began again: the record
		// that serves the entry in the new ledger, else the head.
		from, ok, err := tx.ServedFrom(ctx, k.Name, k.Instance, 0)
		if err != nil {
			return out, err
		}
		if !ok || from > head {
			from = head
		}
		r.startAt(install, from)
	default:
		// Served again since the cursor: the record that began it.
		from, ok, err := tx.ServedFrom(ctx, k.Name, k.Instance, r.cur.Seq)
		if err != nil {
			return out, err
		}
		if ok {
			r.startAt(install, from)
			break
		}
		gone, err := tx.SeqRetired(ctx, r.cur.Seq)
		if err != nil {
			return out, err
		}
		if gone {
			marker, err := r.skipped(ctx, tx, install, head)
			if err != nil {
				return out, err
			}
			out.events = append(out.events, marker)
		}
	}
	after := r.cur.Seq
	if len(out.events) > 0 {
		after = out.events[0].Data.Seq
	}
	rows, err := tx.ReadFeedRows(ctx, max(after, r.floor), pluginproto.MaxFeedEvents-len(out.events))
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		// A row the schema cannot carry is not sent (feedEventOf); the
		// next answer moves the cursor past it.
		if e, ok := feedEventOf(install, r.pair.agent, row); ok {
			out.events = append(out.events, e)
		}
	}
	switch {
	case len(rows) == 0 && len(out.events) == 0:
		r.floor = head
	case len(out.events) == 0:
		// Every row read was one the schema cannot carry: read past them.
		r.floor = rows[len(rows)-1].Seq
	}
	return out, nil
}

// skipped is the skipped-ahead marker after the cursor: its seq is the one
// just before the agent's oldest row after the cursor that remains, or the
// chain head when none remains.
func (r *feedReader) skipped(ctx context.Context, tx guardmodel.FeedSnapshot, install uuid.UUID, head int64) (feedEvent, error) {
	seq := head
	oldest, ok, err := tx.OldestSeqAfter(ctx, r.cur.Seq)
	if err != nil {
		return feedEvent{}, err
	}
	if ok {
		seq = oldest - 1
	}
	return skippedEvent(install, r.pair.agent, r.cur.Seq, seq), nil
}

// startAt starts the cursor at seq of install, and writes it at once, so a
// restart before the first answer starts there too.
func (r *feedReader) startAt(install uuid.UUID, seq int64) {
	r.floor = 0
	r.moveTo(install, seq)
}

// moveTo moves the cursor and writes it. A cursor that cannot be written
// stays in memory: after a restart the events since the last write come
// again, which at least once allows.
func (r *feedReader) moveTo(install uuid.UUID, seq int64) {
	r.cur = &feedCursor{InstallID: install, Seq: seq}
	raw, err := json.Marshal(r.cur)
	if err == nil {
		err = writeFileAtomic(r.cursorDir(), r.pair.agent+".json", raw)
	}
	if err != nil {
		r.log.Warn("plugin feed cursor not written; after a restart the events since its last write come again", "err", err)
	}
}

// load reads the cursor file; a missing or unreadable one leaves no cursor.
func (r *feedReader) load() {
	raw, err := os.ReadFile(filepath.Join(r.cursorDir(), r.pair.agent+".json"))
	if err != nil {
		return
	}
	var c feedCursor
	if json.Unmarshal(raw, &c) != nil || c.InstallID == uuid.Nil || c.Seq < 0 {
		return
	}
	r.cur = &c
}

func (r *feedReader) cursorDir() string {
	return filepath.Join(r.f.dir, r.pair.key.Name, r.pair.key.Instance)
}
