package pii

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// Bounds of the per-tick bookkeeping, so an agent that reads many resources
// with no classes cannot grow the engine's memory or its reload count
// without limit. Past them a missing field is still UNCLASSIFIED, only no
// longer reloaded for or warned about again until the next tick.
const (
	// maxReloadResources is how many unknown resources may each cause one
	// reload per hourly tick.
	maxReloadResources = 4096
	// maxWarnedFields is how many unclassified fields are warned about per
	// hourly tick.
	maxWarnedFields = 4096
)

// Classes is the store's classification of one agent's fields, read on the
// agent's credential.
type Classes interface {
	// Snapshot reads the marks and the classes in one consistent read,
	// begun after the call: the marks first, then the classes.
	Snapshot(ctx context.Context) (piistore.Snapshot, error)
	// Marks reads the marks alone.
	Marks(ctx context.Context) (piistore.Marks, error)
	// Unclassified lists the fields the agent can read that need a person.
	Unclassified(ctx context.Context) ([]piistore.Unclassified, error)
	// ResourceOf is the resource that holds ref, for a ref the map does not
	// know. ref is never empty.
	ResourceOf(ref action.FieldRef) action.ResourceRef
	// Shared is true for a source others may share a load with (a pool),
	// false inside a caller's transaction (a write's RETURNING), which
	// reads alone, on its own connection.
	Shared() bool
}

// Class is one field's class.
type Class struct {
	Namespace, Resource, Field string
	Class                      string
	// EntityType is set exactly when Class is IDENTIFIER.
	EntityType string
	// PhoneRegion is the region a PHONE field's values are parsed in, or "".
	PhoneRegion string
}

// Unclassified is the class of a field missing from the map: UNCLASSIFIED,
// warned in M5.1 and refused from M5.2 (CONTRACT.md, PII classification).
var Unclassified = Class{Class: guardmodel.ClassUnclassified}

// Name is namespace.resource.field (names are not PII).
func (c Class) Name() string { return c.Namespace + "." + c.Resource + "." + c.Field }

// marksEqual reports whether two loads saw the same marks.
func marksEqual(m, o piistore.Marks) bool {
	if !bytes.Equal(m.Fingerprint, o.Fingerprint) || !bytes.Equal(m.CatalogPrint, o.CatalogPrint) {
		return false
	}
	if m.ClassifiedAt == nil || o.ClassifiedAt == nil {
		return m.ClassifiedAt == nil && o.ClassifiedAt == nil
	}
	return m.ClassifiedAt.Equal(*o.ClassifiedAt)
}

// fieldClass is one field of a snapshot.
type fieldClass struct {
	ref      action.FieldRef
	resource action.ResourceRef
	class    Class
}

// snapshot is one load of the map; it is never changed after the load.
type snapshot struct {
	cols      map[action.FieldRef]Class
	resources map[action.ResourceRef]struct{}
	// fields are the classes in the store's order.
	fields []fieldClass
	marks  piistore.Marks
}

// newSnapshot keys a store's snapshot by field and resource.
func newSnapshot(s piistore.Snapshot) *snapshot {
	out := &snapshot{
		cols:      make(map[action.FieldRef]Class, len(s.Fields)),
		resources: map[action.ResourceRef]struct{}{},
		fields:    make([]fieldClass, 0, len(s.Fields)),
		marks:     s.Marks,
	}
	for _, f := range s.Fields {
		c := Class{
			Namespace: f.Namespace, Resource: f.ResourceName, Field: f.Field,
			Class: f.Class, EntityType: f.EntityType, PhoneRegion: f.PhoneRegion,
		}
		out.fields = append(out.fields, fieldClass{ref: f.Ref, resource: f.Resource, class: c})
		out.cols[f.Ref] = c
		out.resources[f.Resource] = struct{}{}
	}
	return out
}

// Map is one agent's classification map (CONTRACT.md, PII classification,
// Engine): the store's classes keyed by field, with the marks read with
// them. Lookups take no lock. No lock is ever held while waiting for the
// store: a load through a shared source (the agent's pool) runs as one
// flight that others wait on with their own context, and a load from a
// private one (a write's RETURNING, inside its transaction) reads alone on
// that connection, so a full pool cannot wedge it. Safe for concurrent use.
type Map struct {
	log  *slog.Logger
	snap atomic.Pointer[snapshot]
	// loads counts loads (tests).
	loads atomic.Int64
	// joins counts loads that waited on a running flight (tests).
	joins atomic.Int64

	mu        sync.Mutex // guards the fields below; never held during I/O
	tried     map[action.ResourceRef]struct{}
	warned    map[action.FieldRef]struct{}
	flight    *flight // the shared load running now, or nil
	nextSeq   uint64  // the sequence number of the next load
	storedSeq uint64  // the sequence number of the stored snapshot
}

// flight is one load through a shared source, which others may wait on.
type flight struct {
	seq  uint64
	done chan struct{}
	err  error
}

// NewMap returns an empty map; it loads on first use. It panics on a nil
// logger.
func NewMap(log *slog.Logger) *Map {
	if log == nil {
		panic("piidict: logger required")
	}
	return &Map{
		log: log, tried: map[action.ResourceRef]struct{}{}, warned: map[action.FieldRef]struct{}{},
		nextSeq: 1,
	}
}

// Load reads the classes and their marks in one snapshot, begun after this
// call, and replaces the map.
func (m *Map) Load(ctx context.Context, c Classes) error {
	return m.load(ctx, c, true)
}

// load loads a snapshot. fresh asks for a load begun after this call (an
// unknown resource, a moved catalog); otherwise a load already running will
// do.
func (m *Map) load(ctx context.Context, c Classes, fresh bool) error {
	if !c.Shared() {
		// Inside the caller's transaction: read on its own connection.
		m.mu.Lock()
		seq := m.nextSeq
		m.nextSeq++
		m.mu.Unlock()
		s, err := c.Snapshot(ctx)
		if err != nil {
			return fmt.Errorf("load the pii classification: %w", err)
		}
		m.store(seq, newSnapshot(s))
		return nil
	}
	f, lead, err := m.joinFlight(ctx, fresh)
	if err != nil {
		return err
	}
	if !lead {
		return waitFlight(ctx, f)
	}
	s, err := c.Snapshot(ctx)
	if err != nil {
		f.err = fmt.Errorf("load the pii classification: %w", err)
	} else {
		m.store(f.seq, newSnapshot(s))
	}
	m.mu.Lock()
	m.flight = nil
	m.mu.Unlock()
	close(f.done)
	return f.err
}

// joinFlight returns the flight to wait on, or a new one the caller leads
// (lead). A fresh request first waits out a flight begun before it.
func (m *Map) joinFlight(ctx context.Context, fresh bool) (f *flight, lead bool, err error) {
	m.mu.Lock()
	need := uint64(0)
	if fresh {
		need = m.nextSeq
	}
	for m.flight != nil && m.flight.seq < need {
		old := m.flight
		m.mu.Unlock()
		if err := waitFlight(ctx, old); err != nil && ctx.Err() != nil {
			return nil, false, err
		}
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	if m.flight != nil {
		m.joins.Add(1)
		return m.flight, false, nil
	}
	m.flight = &flight{seq: m.nextSeq, done: make(chan struct{})}
	m.nextSeq++
	return m.flight, true, nil
}

// waitFlight waits for f, or for ctx.
func waitFlight(ctx context.Context, f *flight) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return fmt.Errorf("wait for the pii classification: %w", ctx.Err())
	}
}

// store keeps s unless a later load was stored already.
func (m *Map) store(seq uint64, s *snapshot) {
	m.loads.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq < m.storedSeq {
		return
	}
	m.storedSeq = seq
	m.snap.Store(s)
}

// Tick is the hourly check: it starts a new tick (every unknown resource
// may reload once more, and missing fields are warned again), then reads
// the marks and reloads the map when they differ from the marks kept at the
// last load (or nothing was loaded yet).
func (m *Map) Tick(ctx context.Context, c Classes) (reloaded bool, err error) {
	m.mu.Lock()
	clear(m.tried)
	clear(m.warned)
	m.mu.Unlock()
	if cur := m.snap.Load(); cur != nil {
		now, err := c.Marks(ctx)
		if err != nil {
			return false, fmt.Errorf("read the pii fingerprint: %w", err)
		}
		if marksEqual(now, cur.marks) {
			return false, nil
		}
	}
	return true, m.load(ctx, c, true)
}

// Resolve returns the class of each field. A field whose resource is not in
// the map reloads the map first, at most once per resource per tick
// (CONTRACT.md: so a table with no classes does not reload on every query).
// A field still missing is UNCLASSIFIED and warned about once per tick. A
// computed value (an empty ref) has no class: its zero Class. A load that
// fails is an error, so the caller does not return values it cannot
// classify.
func (m *Map) Resolve(ctx context.Context, c Classes, refs []action.FieldRef) ([]Class, error) {
	s, err := m.current(ctx, c, refs)
	if err != nil {
		return nil, err
	}
	out := make([]Class, len(refs))
	var missing []action.FieldRef
	for i, r := range refs {
		if r == "" {
			continue
		}
		cl, ok := s.cols[r]
		if !ok {
			cl = Unclassified
			missing = append(missing, r)
		}
		out[i] = cl
	}
	m.warnMissing(missing)
	return out, nil
}

// current is the snapshot to resolve refs against, loading it first when
// none is loaded or a resource of refs is unknown and not yet tried this
// tick.
func (m *Map) current(ctx context.Context, c Classes, refs []action.FieldRef) (*snapshot, error) {
	s := m.snap.Load()
	if s != nil && !s.unknown(c, refs) {
		return s, nil
	}
	if s == nil {
		if err := m.load(ctx, c, false); err != nil {
			return nil, err
		}
		s = m.snap.Load()
	}
	m.mu.Lock()
	fresh := m.tryUnknownLocked(c, s, refs)
	m.mu.Unlock()
	if len(fresh) == 0 {
		return s, nil
	}
	if err := m.load(ctx, c, true); err != nil {
		// Not tried after all: the next result from those resources reloads.
		m.mu.Lock()
		for _, r := range fresh {
			delete(m.tried, r)
		}
		m.mu.Unlock()
		return nil, err
	}
	return m.snap.Load(), nil
}

// tryUnknownLocked marks the unknown resources of refs as tried for this
// tick and returns the ones not tried before (one reload covers them all).
func (m *Map) tryUnknownLocked(c Classes, s *snapshot, refs []action.FieldRef) []action.ResourceRef {
	var fresh []action.ResourceRef
	for _, r := range refs {
		if r == "" {
			continue
		}
		res := c.ResourceOf(r)
		if _, ok := s.resources[res]; ok {
			continue
		}
		if _, ok := m.tried[res]; ok || len(m.tried) >= maxReloadResources {
			continue
		}
		m.tried[res] = struct{}{}
		fresh = append(fresh, res)
	}
	return fresh
}

func (s *snapshot) unknown(c Classes, refs []action.FieldRef) bool {
	for _, r := range refs {
		if r == "" {
			continue
		}
		if _, ok := s.resources[c.ResourceOf(r)]; !ok {
			return true
		}
	}
	return false
}

// warnMissing logs each unclassified field once per tick, by its ref (no
// value, no name the agent did not already see).
func (m *Map) warnMissing(refs []action.FieldRef) {
	if len(refs) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range refs {
		if _, ok := m.warned[r]; ok || len(m.warned) >= maxWarnedFields {
			continue
		}
		m.warned[r] = struct{}{}
		m.log.Warn("pii: a column the agent read is not classified (UNCLASSIFIED); run basalt init to label it",
			"field", string(r))
	}
}

// Identifiers returns the IDENTIFIER fields of the map, in the store's
// order, loading it first when nothing is loaded.
func (m *Map) Identifiers(ctx context.Context, c Classes) ([]IdentifierColumn, error) {
	if _, err := m.current(ctx, c, nil); err != nil {
		return nil, err
	}
	s := m.snap.Load()
	out := make([]IdentifierColumn, 0, len(s.fields))
	for _, f := range s.fields {
		if f.class.Class == guardmodel.ClassIdentifier {
			out = append(out, IdentifierColumn{Ref: f.ref, Resource: f.resource, Class: f.class})
		}
	}
	return out, nil
}

// IdentifierColumn is one IDENTIFIER field to scan.
type IdentifierColumn struct {
	Ref      action.FieldRef
	Resource action.ResourceRef
	Class    Class
}
