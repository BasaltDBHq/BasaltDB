package pii

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// fakeClasses is a class store in memory. Refs are "<resource>#<field>",
// as a document store might write them.
type fakeClasses struct {
	mu     sync.Mutex
	snap   piistore.Snapshot
	unclas []piistore.Unclassified
	err    error
	// gate, when set, holds every Snapshot until it is closed.
	gate    chan struct{}
	private bool
	reads   atomic.Int64
	entered chan struct{}
}

func newFakeClasses(fields ...piistore.FieldClass) *fakeClasses {
	return &fakeClasses{snap: piistore.Snapshot{Fields: fields}, entered: make(chan struct{}, 64)}
}

func fakeField(resource, field, class string) piistore.FieldClass {
	return piistore.FieldClass{
		Ref:       agentstore.FieldRef(resource + "#" + field),
		Resource:  agentstore.ResourceRef(resource),
		Namespace: "db", ResourceName: resource, Field: field, Class: class,
	}
}

func (f *fakeClasses) Snapshot(ctx context.Context) (piistore.Snapshot, error) {
	f.reads.Add(1)
	f.entered <- struct{}{}
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return piistore.Snapshot{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap, f.err
}

func (f *fakeClasses) Marks(context.Context) (piistore.Marks, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap.Marks, f.err
}

func (f *fakeClasses) Unclassified(context.Context) ([]piistore.Unclassified, error) {
	return f.unclas, f.err
}

func (f *fakeClasses) ResourceOf(ref agentstore.FieldRef) agentstore.ResourceRef {
	res, _, _ := strings.Cut(string(ref), "#")
	return agentstore.ResourceRef(res)
}

func (f *fakeClasses) Shared() bool { return !f.private }

func (f *fakeClasses) set(fields ...piistore.FieldClass) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.Fields = fields
}

// Concurrent loads through a shared store run as one flight.
func TestConcurrentSharedLoadsAreOneFlight(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeClasses(fakeField("users", "email", guardmodel.ClassIdentifier))
	store.gate = make(chan struct{})
	m := NewMap(slog.New(slog.DiscardHandler))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := m.Resolve(ctx, store, []agentstore.FieldRef{"users#email"})
			errs <- err
		})
	}
	<-store.entered
	time.Sleep(50 * time.Millisecond) // let the others join the flight
	close(store.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, store.reads.Load(), "one read for every waiter")
	require.EqualValues(t, 1, m.loads.Load())
}

// A private store (a write's transaction) reads alone: it never waits on the
// shared flight, which may be waiting for the connection it holds.
func TestPrivateLoadNeverJoinsTheFlight(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := newFakeClasses(fakeField("users", "email", guardmodel.ClassIdentifier))
	pool.gate = make(chan struct{})
	m := NewMap(slog.New(slog.DiscardHandler))
	poolDone := make(chan error, 1)
	go func() {
		_, err := m.Resolve(ctx, pool, []agentstore.FieldRef{"users#email"})
		poolDone <- err
	}()
	<-pool.entered

	tx := newFakeClasses(fakeField("users", "email", guardmodel.ClassIdentifier))
	tx.private = true
	got, err := m.Resolve(ctx, tx, []agentstore.FieldRef{"users#email"})
	require.NoError(t, err, "the private load does not wait for the stuck flight")
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class)
	require.EqualValues(t, 1, tx.reads.Load())

	close(pool.gate)
	require.NoError(t, <-poolDone)
}

// An unknown resource reloads the map at most once per tick; the next tick
// lets it reload once more. An empty ref has no class and never reloads.
func TestUnknownResourceReloadsOncePerTick(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log, out := newLog()
	store := newFakeClasses(fakeField("users", "email", guardmodel.ClassIdentifier))
	m := NewMap(log)
	require.NoError(t, m.Load(ctx, store))
	require.EqualValues(t, 1, m.loads.Load())

	// A collection classified after the load: the first field from it
	// reloads, and the map then knows its class.
	store.set(fakeField("users", "email", guardmodel.ClassIdentifier),
		fakeField("orders", "contact.email", guardmodel.ClassIdentifier))
	got, err := m.Resolve(ctx, store, []agentstore.FieldRef{"orders#contact.email"})
	require.NoError(t, err)
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class)
	require.EqualValues(t, 2, m.loads.Load(), "an unknown resource reloads the map")

	// A resource with no classes reloads once per tick, not on every read.
	for range 5 {
		got, err = m.Resolve(ctx, store, []agentstore.FieldRef{"plain#label"})
		require.NoError(t, err)
		require.Equal(t, Unclassified, got[0])
	}
	require.EqualValues(t, 3, m.loads.Load(), "at most once per resource per tick")
	require.Equal(t, 1, strings.Count(out.String(), "UNCLASSIFIED"), out.String())
	require.Contains(t, out.String(), "field=plain#label", "the warning names the field's ref")

	reloaded, err := m.Tick(ctx, store)
	require.NoError(t, err)
	require.False(t, reloaded, "the marks did not move")
	for range 2 {
		_, err = m.Resolve(ctx, store, []agentstore.FieldRef{"plain#label"})
		require.NoError(t, err)
	}
	require.EqualValues(t, 4, m.loads.Load(), "the next tick lets it reload once more")
	require.Equal(t, 2, strings.Count(out.String(), "UNCLASSIFIED"), "warned again on the next tick")

	// A computed value has no source: no reload, no class.
	got, err = m.Resolve(ctx, store, []agentstore.FieldRef{""})
	require.NoError(t, err)
	require.Equal(t, Class{}, got[0])
	require.EqualValues(t, 4, m.loads.Load())
}

// The tick reloads when the marks move, and a failed reload leaves the
// resource to be tried again.
func TestTickReloadsWhenTheMarksMove(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeClasses()
	m := NewMap(slog.New(slog.DiscardHandler))
	reloaded, err := m.Tick(ctx, store)
	require.NoError(t, err)
	require.True(t, reloaded, "the first tick loads")
	reloaded, err = m.Tick(ctx, store)
	require.NoError(t, err)
	require.False(t, reloaded)

	at := time.Now()
	store.mu.Lock()
	store.snap.Marks = piistore.Marks{CatalogPrint: []byte{1}, ClassifiedAt: &at}
	store.mu.Unlock()
	reloaded, err = m.Tick(ctx, store)
	require.NoError(t, err)
	require.True(t, reloaded)
	fp, err := m.CatalogFingerprint(ctx, store)
	require.NoError(t, err)
	require.Equal(t, "01", fp)

	store.err = errors.New("store down")
	_, err = m.Resolve(ctx, store, []agentstore.FieldRef{"gone#x"})
	require.ErrorIs(t, err, store.err)
	m.mu.Lock()
	require.Empty(t, m.tried, "a failed reload is tried again")
	m.mu.Unlock()
}

// Secrets and identifiers keep the store's order.
func TestSecretsAndIdentifiersKeepTheStoreOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeClasses(
		fakeField("b", "token", guardmodel.ClassSecret),
		fakeField("a", "email", guardmodel.ClassIdentifier),
		fakeField("a", "pin", guardmodel.ClassSecret),
		fakeField("a", "note", guardmodel.ClassPublic),
		fakeField("b", "phone", guardmodel.ClassIdentifier),
	)
	m := NewMap(slog.New(slog.DiscardHandler))
	secrets, err := m.Secrets(ctx, store)
	require.NoError(t, err)
	require.Equal(t, []agentstore.FieldRef{"b#token", "a#pin"}, secrets)
	ids, err := m.Identifiers(ctx, store)
	require.NoError(t, err)
	require.Len(t, ids, 2)
	require.Equal(t, []any{agentstore.FieldRef("a#email"), agentstore.ResourceRef("a"), "db.a.email"},
		[]any{ids[0].Ref, ids[0].Resource, ids[0].Class.Name()})
	require.Equal(t, agentstore.FieldRef("b#phone"), ids[1].Ref)
}

// More unknown resources than the bound, in one result: one reload covers
// them, and the per-tick sets stop at their bounds.
func TestMapBoundsReloadsAndWarnings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeClasses(fakeField("users", "email", guardmodel.ClassIdentifier))
	m := NewMap(slog.New(slog.DiscardHandler))
	require.NoError(t, m.Load(ctx, store))

	refs := make([]agentstore.FieldRef, 0, maxReloadResources+100)
	for i := range maxReloadResources + 100 {
		refs = append(refs, agentstore.FieldRef("r"+strconv.Itoa(i)+"#x"))
	}
	_, err := m.Resolve(ctx, store, refs)
	require.NoError(t, err)
	require.EqualValues(t, 2, m.loads.Load())
	m.mu.Lock()
	require.Len(t, m.tried, maxReloadResources)
	require.Len(t, m.warned, maxWarnedFields)
	m.mu.Unlock()

	// More unknown resources past the bound: no reload until the next tick.
	_, err = m.Resolve(ctx, store, []agentstore.FieldRef{"later#x"})
	require.NoError(t, err)
	require.EqualValues(t, 2, m.loads.Load())
}

// The hourly check logs the fields the store reports, by name.
func TestWatchLogsTheStoresUnclassifiedFields(t *testing.T) {
	t.Parallel()
	log, out := newLog()
	store := newFakeClasses()
	store.unclas = []piistore.Unclassified{
		{Name: "db.users.contact.email", DataType: "string"},
		{Name: "db.users.age", DataType: "int", Changed: true},
	}
	require.NoError(t, NewWatch("bot", NewMap(log), store, log).Tick(context.Background()))
	require.Contains(t, out.String(), "pii: 1 columns unclassified: db.users.contact.email")
	require.Contains(t, out.String(), "pii: 1 columns changed type since they were labeled: db.users.age")
	require.Contains(t, out.String(), "pii: classification loaded")
}
