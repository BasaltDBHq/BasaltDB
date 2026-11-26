//go:build unix

package plugin

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The plugin feed reads an agent's ledger only through the Guard port
// (ReadSnapshot and the FeedSnapshot it hands over). These tests run the
// feed on a ledger held in memory, with no database: what they prove holds
// for any store whose adapter keeps the FeedSnapshot contract.

// errFakeLedgerDown is the fake store not answering.
var errFakeLedgerDown = errors.New("the fake store did not answer")

// fakeRow is one row of the fake ledger: the feed's fields, and the two
// facts a store keeps that decide whether the row is an event.
type fakeRow struct {
	guardmodel.FeedRow
	unapplied   bool // a CHANGE whose status is not APPLIED
	refusedRead bool // a REFUSED read
}

// fakeLedger is one agent's ledger in memory, as a store's adapter would
// read it: the install id, the chain head (which moves with other agents'
// rows too), the agent's own rows in seq order, and the anchor retention
// leaves behind.
type fakeLedger struct {
	mu      sync.Mutex
	install uuid.UUID
	head    int64
	rows    []fakeRow
	// anchor is the last seq retention deleted: every row up to it is gone.
	anchor int64
	// down is how many reads fail before the store answers again.
	down int
	// reads counts the snapshots read; filters are the filters asked for.
	reads   int
	filters []guardmodel.FeedFilter
}

func newFakeLedger() *fakeLedger { return &fakeLedger{install: uuid.Must(uuid.NewV7())} }

// other moves the chain head by n rows of other agents, which this agent's
// ledger does not show.
func (l *fakeLedger) other(n int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.head += n
}

// add appends r as the agent's next row and returns its seq.
func (l *fakeLedger) add(r fakeRow) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.head++
	r.Seq, r.At = l.head, time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC).Add(time.Duration(l.head)*time.Second)
	l.rows = append(l.rows, r)
	return r.Seq
}

// applied appends an applied write of resource and returns its seq.
func (l *fakeLedger) applied(resource string) int64 {
	return l.add(fakeRow{FeedRow: fakeWrite(guardmodel.KindChange, resource)})
}

// retireThrough deletes every row up to seq, as retention does.
func (l *fakeLedger) retireThrough(seq int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows = slices.DeleteFunc(l.rows, func(r fakeRow) bool { return r.Seq <= seq })
	l.anchor = seq
}

// reinstall is a fresh guard install: a new id and seqs that begin again.
func (l *fakeLedger) reinstall() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.install, l.head, l.rows, l.anchor = uuid.Must(uuid.NewV7()), 0, nil, 0
}

func (l *fakeLedger) fail(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.down = n
}

func (l *fakeLedger) readCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reads
}

func (l *fakeLedger) askedFilters() []guardmodel.FeedFilter {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.filters)
}

func fakeWrite(kind, resource string) guardmodel.FeedRow {
	s := func(v string) *string { return &v }
	return guardmodel.FeedRow{
		Kind: kind, ChangeID: uuid.NullUUID{UUID: uuid.Must(uuid.NewV7()), Valid: true},
		Op: s("UPDATE"), Verb: s("UPDATE"), RunID: s(uuid.Must(uuid.NewV7()).String()),
		Resource: s(resource), Rows: s("1"), CascadedRows: s("0"),
	}
}

// fakeGuard is the Guard port over a fakeLedger. The feed calls only
// ReadSnapshot, Kind and NoAnswer; any other method panics on the nil
// embedded Guard.
type fakeGuard struct {
	Guard
	l *fakeLedger
}

// ReadSnapshot runs fn with the ledger held still, as a repeatable-read
// snapshot holds it. q is the agent's handle, which the fake has none of.
func (g fakeGuard) ReadSnapshot(_ context.Context, q Querier, fn func(guardmodel.FeedSnapshot) error) error {
	if q != nil {
		return errors.New("the fake store takes no handle")
	}
	g.l.mu.Lock()
	defer g.l.mu.Unlock()
	g.l.reads++
	if g.l.down > 0 {
		g.l.down--
		return errFakeLedgerDown
	}
	return fn(fakeSnapshot{g.l})
}

// Kind is the store the events name. feed.schema.json fixes store.kind to
// POSTGRES today, and the test plugin checks every request against it.
func (fakeGuard) Kind() action.StoreKind { return action.StorePostgres }

func (fakeGuard) NoAnswer(err error) bool { return errors.Is(err, errFakeLedgerDown) }

// fakeSnapshot reads a fakeLedger whose lock its ReadSnapshot holds.
type fakeSnapshot struct{ l *fakeLedger }

func (s fakeSnapshot) InstallID(context.Context) (uuid.UUID, error) { return s.l.install, nil }

func (s fakeSnapshot) ChainHeadSeq(context.Context) (int64, error) { return s.l.head, nil }

func (fakeSnapshot) PluginEntryEvents(context.Context, string, string) ([]guardmodel.PluginEntryEvent, error) {
	return nil, nil
}

// SeqRetired is true for a seq before the anchor: the anchor itself is the
// last row deleted, after which nothing is missing.
func (s fakeSnapshot) SeqRetired(_ context.Context, seq int64) (bool, error) {
	return seq > 0 && seq < s.l.anchor, nil
}

func (s fakeSnapshot) ReadFeedRows(_ context.Context, after int64, limit int, f guardmodel.FeedFilter) ([]guardmodel.FeedRow, error) {
	s.l.filters = append(s.l.filters, f)
	var out []guardmodel.FeedRow
	for _, r := range s.l.rows {
		switch {
		case len(out) >= limit:
			return out, nil
		case r.Seq <= after, !slices.Contains(f.Kinds, r.Kind),
			r.unapplied && !f.IncludeUnappliedChanges, r.refusedRead && !f.IncludeRefusedReads:
			continue
		}
		out = append(out, r.FeedRow)
	}
	return out, nil
}

func (s fakeSnapshot) OldestSeqAfter(_ context.Context, after int64) (int64, bool, error) {
	for _, r := range s.l.rows {
		if r.Seq > after {
			return r.Seq, true, nil
		}
	}
	return 0, false, nil
}

// newFakeFeedEnv is a feedEnv with no database: product_a's ledger is l.
func newFakeFeedEnv(t *testing.T, l *fakeLedger) *feedEnv {
	t.Helper()
	logs := &syncBuffer{}
	e := &feedEnv{
		t: t, host: NewHost(), stateDir: t.TempDir(), schema: feedSchema(t), logs: logs,
		log:   slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		pools: map[string]AgentLedger{"product_a": {ports: Ports{Guard: fakeGuard{l: l}}}},
	}
	t.Cleanup(func() {
		if e.stop != nil {
			e.stop()
		}
	})
	return e
}

// On a store held in memory the feed starts at the head with no history,
// sends only the rows that are events, in seq order, with the store's
// resource name, moves the cursor to each answer, and after a restart goes
// on from the cursor without sending anything twice.
func TestFeedOnAFakeStore(t *testing.T) {
	t.Parallel()
	l := newFakeLedger()
	l.applied("invoices/2026")
	l.other(2)
	e := newFakeFeedEnv(t, l)
	p := e.serve("acme-feed", "product_a")
	e.start()
	c := e.started(p.key, "product_a")
	require.Equal(t, feedCursor{InstallID: l.install, Seq: 3}, c, "a new cursor starts at the chain head")

	first := l.applied("invoices/2026")
	l.add(fakeRow{FeedRow: fakeWrite(guardmodel.KindChange, "invoices/draft"), unapplied: true})
	l.other(1)
	held := l.add(fakeRow{FeedRow: func() guardmodel.FeedRow {
		r := fakeWrite(guardmodel.KindApprovalPending, "invoices/2026")
		approvalID, expires := uuid.Must(uuid.NewV7()).String(), "2026-11-27T09:00:00Z"
		r.ApprovalID, r.ExpiresAt, r.Resource, r.CascadedRows = &approvalID, &expires, nil, nil
		return r
	}()})
	refused := l.add(fakeRow{FeedRow: func() guardmodel.FeedRow {
		r := fakeWrite(guardmodel.KindRefused, "invoices/2026")
		op, verb := "READ", "SELECT"
		r.Op, r.Verb = &op, &verb
		return r
	}(), refusedRead: true})
	last := l.applied("receipts/7")
	waitSeqs(t, p, "product_a", first, held, last)
	e.waitCursor(p.key, last)
	require.NotContains(t, p.seqsFor("product_a"), refused, "a refused read is not an event")

	var resources []string
	for _, call := range p.received() {
		for _, ev := range call.events {
			if ev.Type == feedTypePrefix+"write.applied" {
				resources = append(resources, ev.Data["resource"].(string))
				require.Equal(t, map[string]any{"kind": "POSTGRES", "verb": "UPDATE"}, ev.Data["store"])
			}
		}
	}
	require.Equal(t, []string{"invoices/2026", "receipts/7"}, resources)
	for _, f := range l.askedFilters() {
		require.Equal(t, feedFilter, f, "the feed asks the store for event rows only")
	}

	e.stop()
	after := l.applied("receipts/8")
	e.start()
	waitSeqs(t, p, "product_a", first, held, last, after)
	e.waitCursor(p.key, after)
}

// When retention deleted rows after the cursor, the fake store's next read
// sends the skipped-ahead marker before the rows that remain.
func TestFeedOnAFakeStoreSaysWhenItSkipped(t *testing.T) {
	t.Parallel()
	l := newFakeLedger()
	e := newFakeFeedEnv(t, l)
	p := e.serve("acme-feed", "product_a")
	e.start()
	require.Zero(t, e.started(p.key, "product_a").Seq, "an empty ledger starts at 0")
	seen := l.applied("invoices/1")
	waitSeqs(t, p, "product_a", seen)
	e.waitCursor(p.key, seen)

	e.stop()
	l.applied("invoices/2")
	l.applied("invoices/3")
	kept := l.applied("invoices/4")
	l.retireThrough(kept - 1)
	e.start()
	_, marker := waitSkipped(t, p, "product_a", seen)
	require.Equal(t, kept-1, marker.seq(), "the marker stands just before the oldest row that remains")
	waitSeqs(t, p, "product_a", seen, kept-1, kept)
	e.waitCursor(p.key, kept)
}

// A fresh install of the fake store (a new id, seqs from 1 again) starts
// the cursor at its head: nothing of the old install is sent again.
func TestFeedOnAFakeStoreFollowsANewInstall(t *testing.T) {
	t.Parallel()
	l := newFakeLedger()
	e := newFakeFeedEnv(t, l)
	p := e.serve("acme-feed", "product_a")
	e.start()
	e.started(p.key, "product_a")
	seen := l.applied("invoices/1")
	waitSeqs(t, p, "product_a", seen)

	e.stop()
	l.reinstall()
	l.other(5)
	e.start()
	require.Eventually(t, func() bool {
		c, ok := e.cursor(p.key, "product_a")
		return ok && c == feedCursor{InstallID: l.install, Seq: 5}
	}, 10*time.Second, 10*time.Millisecond, "the cursor moves to the new install's head")
	next := l.applied("invoices/1")
	waitSeqs(t, p, "product_a", seen, next)
}

// A fake store that does not answer pauses the feed, logged once with its
// class and no store text; the cursor stays; when it answers again the feed
// resumes from the cursor and says so.
func TestFeedOnAFakeStoreBacksOff(t *testing.T) {
	t.Parallel()
	l := newFakeLedger()
	e := newFakeFeedEnv(t, l)
	p := e.serve("acme-feed", "product_a")
	e.start()
	at := e.started(p.key, "product_a")

	l.fail(3)
	reads := l.readCount()
	seq := l.applied("invoices/1")
	waitSeqs(t, p, "product_a", seq)
	require.GreaterOrEqual(t, l.readCount()-reads, 4, "three failed reads, then the one that answered")
	e.waitCursor(p.key, seq)
	require.Equal(t, at.InstallID, l.install)

	logs := e.logs.String()
	require.Equal(t, 1, strings.Count(logs, "plugin feed paused"), logs)
	require.Contains(t, logs, `"class":"NO_ANSWER"`)
	require.Contains(t, logs, "plugin feed delivers again")
	require.NotContains(t, logs, errFakeLedgerDown.Error())
}
