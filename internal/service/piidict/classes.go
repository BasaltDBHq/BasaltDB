// Package piidict keeps the engine's PII dictionary fresh (M5.1 plan,
// section 6): the classification map of the columns an agent reads, the
// values the agent reads added before they leave the engine, the throttled
// scan that rebuilds the dictionary, and the hourly classification check.
// Nothing here logs, returns or stores a value in plain form: logs carry
// column names and counts only.
package piidict

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// Bounds of the per-tick bookkeeping, so an agent that reads many tables
// with no classes cannot grow the engine's memory or its reload count
// without limit. Past them a missing column is still UNCLASSIFIED, only no
// longer reloaded for or warned about again until the next tick.
const (
	// maxReloadOIDs is how many unknown table oids may each cause one reload
	// per hourly tick.
	maxReloadOIDs = 4096
	// maxWarnedColumns is how many unclassified columns are warned about per
	// hourly tick.
	maxWarnedColumns = 4096
)

// ColumnRef is a table column as Postgres names it in a row description:
// the table's oid and the column's attribute number.
type ColumnRef struct {
	TableOID uint32
	Attnum   int16
}

// Class is one row of basalt_meta.agent_pii_columns.
type Class struct {
	Schema, Table, Column string
	Class                 string
	// EntityType is set exactly when Class is IDENTIFIER.
	EntityType string
	// PhoneRegion is the region a PHONE column's values are parsed in, or "".
	PhoneRegion string
}

// Unclassified is the class of a column missing from the map: UNCLASSIFIED,
// warned in M5.1 and refused from M5.2 (CONTRACT.md, PII classification).
var Unclassified = Class{Class: guardmodel.ClassUnclassified}

// Name is schema.table.column (names are not PII).
func (c Class) Name() string { return c.Schema + "." + c.Table + "." + c.Column }

// marks are what the map was loaded with: the live fingerprint and the
// catalog row, compared on each hourly tick.
type marks struct {
	fingerprint  []byte
	catalogPrint []byte
	classifiedAt *time.Time
}

func (m marks) equal(o marks) bool {
	if !bytes.Equal(m.fingerprint, o.fingerprint) || !bytes.Equal(m.catalogPrint, o.catalogPrint) {
		return false
	}
	if m.classifiedAt == nil || o.classifiedAt == nil {
		return m.classifiedAt == nil && o.classifiedAt == nil
	}
	return m.classifiedAt.Equal(*o.classifiedAt)
}

// snapshot is one load of the map; it is never changed after the load.
type snapshot struct {
	cols  map[ColumnRef]Class
	oids  map[uint32]struct{}
	marks marks
}

// Map is one agent's classification map (CONTRACT.md, PII classification,
// Engine): agent_pii_columns keyed by table oid and attribute number, with
// the fingerprint and catalog row read with it. Lookups take no lock. No
// lock is ever held while waiting for the database: a load through the
// agent's pool runs as one flight that others wait on with their own
// context, and a load inside a caller's transaction (a write's RETURNING)
// reads on that transaction's connection, so a full pool cannot wedge it.
// Safe for concurrent use.
type Map struct {
	log  *slog.Logger
	snap atomic.Pointer[snapshot]
	// loads counts loads (tests).
	loads atomic.Int64
	// between runs between a load's two reads (tests); a no-op otherwise.
	between func()

	mu        sync.Mutex // guards the fields below; never held during I/O
	tried     map[uint32]struct{}
	warned    map[ColumnRef]struct{}
	flight    *flight // the pool load running now, or nil
	nextSeq   uint64  // the sequence number of the next load
	storedSeq uint64  // the sequence number of the stored snapshot
}

// flight is one load through the pool, which others may wait on.
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
	return &Map{log: log, tried: map[uint32]struct{}{}, warned: map[ColumnRef]struct{}{}, nextSeq: 1, between: func() {}}
}

// Load reads agent_pii_columns, pii_fingerprint() and agent_pii_catalog
// in one snapshot, begun after this call, and replaces the map.
func (m *Map) Load(ctx context.Context, db Querier) error {
	return m.load(ctx, db, true)
}

// load loads a snapshot. fresh asks for a load begun after this call (an
// unknown oid, a moved catalog); otherwise a load already running will do.
func (m *Map) load(ctx context.Context, db Querier, fresh bool) error {
	if _, ok := db.(beginner); !ok {
		// Inside the caller's transaction: read on its own connection.
		m.mu.Lock()
		seq := m.nextSeq
		m.nextSeq++
		m.mu.Unlock()
		s, err := readSnapshot(ctx, db, m.between)
		if err != nil {
			return fmt.Errorf("load the pii classification: %w", err)
		}
		m.store(seq, s)
		return nil
	}
	f, lead, err := m.joinFlight(ctx, fresh)
	if err != nil {
		return err
	}
	if !lead {
		return waitFlight(ctx, f)
	}
	s, err := withSnapshot(ctx, db, func(ctx context.Context, q Querier) (*snapshot, error) {
		return readSnapshot(ctx, q, m.between)
	})
	if err != nil {
		f.err = fmt.Errorf("load the pii classification: %w", err)
	} else {
		m.store(f.seq, s)
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

// Tick is the hourly check: it starts a new tick (every unknown oid may
// reload once more, and missing columns are warned again), then reads the
// fingerprint and the catalog row and reloads the map when either differs
// from the values kept at the last load (or nothing was loaded yet).
func (m *Map) Tick(ctx context.Context, db Querier) (reloaded bool, err error) {
	m.mu.Lock()
	clear(m.tried)
	clear(m.warned)
	m.mu.Unlock()
	if cur := m.snap.Load(); cur != nil {
		now, err := withSnapshot(ctx, db, readMarks)
		if err != nil {
			return false, fmt.Errorf("read the pii fingerprint: %w", err)
		}
		if now.equal(cur.marks) {
			return false, nil
		}
	}
	return true, m.load(ctx, db, true)
}

// Resolve returns the class of each column. A column whose table oid is
// not in the map reloads the map first, at most once per oid per tick
// (CONTRACT.md: so a table with no classes does not reload on every query).
// A column still missing is UNCLASSIFIED and warned about once per tick. A
// computed column (oid 0) has no class: its zero Class. A load that fails
// is an error, so the caller does not return values it cannot classify.
func (m *Map) Resolve(ctx context.Context, db Querier, refs []ColumnRef) ([]Class, error) {
	s, err := m.current(ctx, db, refs)
	if err != nil {
		return nil, err
	}
	out := make([]Class, len(refs))
	var missing []ColumnRef
	for i, r := range refs {
		if r.TableOID == 0 {
			continue
		}
		c, ok := s.cols[r]
		if !ok {
			c = Unclassified
			missing = append(missing, r)
		}
		out[i] = c
	}
	m.warnMissing(missing)
	return out, nil
}

// current is the snapshot to resolve refs against, loading it first when
// none is loaded or a table oid of refs is unknown and not yet tried this
// tick.
func (m *Map) current(ctx context.Context, db Querier, refs []ColumnRef) (*snapshot, error) {
	s := m.snap.Load()
	if s != nil && !s.unknown(refs) {
		return s, nil
	}
	if s == nil {
		if err := m.load(ctx, db, false); err != nil {
			return nil, err
		}
		s = m.snap.Load()
	}
	m.mu.Lock()
	fresh := m.tryUnknownLocked(s, refs)
	m.mu.Unlock()
	if len(fresh) == 0 {
		return s, nil
	}
	if err := m.load(ctx, db, true); err != nil {
		// Not tried after all: the next result from those tables reloads.
		m.mu.Lock()
		for _, oid := range fresh {
			delete(m.tried, oid)
		}
		m.mu.Unlock()
		return nil, err
	}
	return m.snap.Load(), nil
}

// tryUnknownLocked marks the unknown oids of refs as tried for this tick and
// returns the ones not tried before (one reload covers them all).
func (m *Map) tryUnknownLocked(s *snapshot, refs []ColumnRef) []uint32 {
	var fresh []uint32
	for _, r := range refs {
		if r.TableOID == 0 {
			continue
		}
		if _, ok := s.oids[r.TableOID]; ok {
			continue
		}
		if _, ok := m.tried[r.TableOID]; ok || len(m.tried) >= maxReloadOIDs {
			continue
		}
		m.tried[r.TableOID] = struct{}{}
		fresh = append(fresh, r.TableOID)
	}
	return fresh
}

func (s *snapshot) unknown(refs []ColumnRef) bool {
	for _, r := range refs {
		if r.TableOID == 0 {
			continue
		}
		if _, ok := s.oids[r.TableOID]; !ok {
			return true
		}
	}
	return false
}

// warnMissing logs each unclassified column once per tick, by table oid and
// attribute number (no value, no name the agent did not already see).
func (m *Map) warnMissing(refs []ColumnRef) {
	if len(refs) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range refs {
		if _, ok := m.warned[r]; ok || len(m.warned) >= maxWarnedColumns {
			continue
		}
		m.warned[r] = struct{}{}
		m.log.Warn("pii: a column the agent read is not classified (UNCLASSIFIED); run basalt init to label it",
			"tableOid", r.TableOID, "attnum", r.Attnum)
	}
}

// Identifiers returns the IDENTIFIER columns of the map, loading it first
// when nothing is loaded.
func (m *Map) Identifiers(ctx context.Context, db Querier) ([]IdentifierColumn, error) {
	if _, err := m.current(ctx, db, nil); err != nil {
		return nil, err
	}
	s := m.snap.Load()
	out := make([]IdentifierColumn, 0, len(s.cols))
	for ref, c := range s.cols {
		if c.Class == guardmodel.ClassIdentifier {
			out = append(out, IdentifierColumn{Ref: ref, Class: c})
		}
	}
	return out, nil
}

// IdentifierColumn is one IDENTIFIER column to scan.
type IdentifierColumn struct {
	Ref   ColumnRef
	Class Class
}

// beginner is a pool, which can open a read-only snapshot transaction.
type beginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// withSnapshot runs read in one repeatable-read, read-only transaction when
// db is a pool, so the map and its marks come from one snapshot; inside a
// caller's transaction (a write's RETURNING) it runs there.
func withSnapshot[T any](ctx context.Context, db Querier, read func(context.Context, Querier) (T, error)) (T, error) {
	b, ok := db.(beginner)
	if !ok {
		return read(ctx, db)
	}
	var out T
	tx, err := b.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	// Read-only: nothing to commit.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	return read(ctx, tx)
}

// readSnapshot reads the marks first, then the classes. Inside a write's
// read-committed transaction the two are separate statements, and a basalt
// classify may commit between them: marks read first are then the older
// ones, so the next hourly tick sees the catalog move and reloads. (Read
// the other way round, old classes would be kept with new marks and never
// reloaded.) between runs between the two reads (tests).
func readSnapshot(ctx context.Context, db Querier, between func()) (*snapshot, error) {
	mk, err := readMarks(ctx, db)
	if err != nil {
		return nil, err
	}
	between()
	q, args, err := psql.Select("table_oid", "attnum", "table_schema", "table_name", "column_name",
		"class", "coalesce(entity_type, '')", "coalesce(phone_region, '')").
		From("basalt_meta.agent_pii_columns").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	s := &snapshot{cols: map[ColumnRef]Class{}, oids: map[uint32]struct{}{}, marks: mk}
	var (
		ref ColumnRef
		c   Class
	)
	_, err = pgx.ForEachRow(rows, []any{&ref.TableOID, &ref.Attnum, &c.Schema, &c.Table, &c.Column, &c.Class, &c.EntityType, &c.PhoneRegion}, func() error {
		s.cols[ref] = c
		s.oids[ref.TableOID] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// readMarks reads pii_fingerprint() and the agent_pii_catalog row (none
// before the first basalt classify).
func readMarks(ctx context.Context, db Querier) (marks, error) {
	var mk marks
	q, args, err := psql.Select("basalt_meta.pii_fingerprint()").ToSql()
	if err != nil {
		return mk, err
	}
	if err := db.QueryRow(ctx, q, args...).Scan(&mk.fingerprint); err != nil {
		return mk, err
	}
	q, args, err = psql.Select("fingerprint", "classified_at").From("basalt_meta.agent_pii_catalog").ToSql()
	if err != nil {
		return mk, err
	}
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return mk, err
	}
	var (
		fp []byte
		at time.Time
	)
	_, err = pgx.ForEachRow(rows, []any{&fp, &at}, func() error {
		classified := at
		mk.catalogPrint, mk.classifiedAt = bytes.Clone(fp), &classified
		return nil
	})
	return mk, err
}
