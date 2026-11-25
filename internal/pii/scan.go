package pii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	sq "github.com/Masterminds/squirrel"

	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// Scan defaults (M5.1 plan, section 6; CONTRACT.md engine config).
const (
	DefaultScanInterval      = 5 * time.Minute
	DefaultScanPage          = 5000
	DefaultScanRowsPerSecond = 20_000
	bytesPerMB               = 1 << 20
	// bytesPerAddBound is what a build holds in memory per value until it
	// commits: two 8-byte keyed hashes. A cycle stops collecting past
	// budget / bytesPerAddBound values, so the build itself stays within
	// pii.maxMemoryMB.
	bytesPerAddBound = 16
	// DefaultLoadTimeout bounds a catalog read (the map, a table's key),
	// so a pool with no free connection cannot hold the scan for good.
	DefaultLoadTimeout = time.Minute
	// pageWaitMargin is how long a page may wait for a connection, on top
	// of the agent's statement timeout.
	pageWaitMargin = time.Minute
	// failWarnAfter is how many cycles in a row may fail before the scan
	// warns that the dictionary is not being rebuilt.
	failWarnAfter = 3
)

// SQLSTATEs that make the scan skip one table and go on: the table or
// column is gone, or the agent may no longer read it. Its values then drop
// out of the next base, as values the agent cannot read should. A statement
// timeout skips only a relation read in one pass (slowRelationError).
const (
	sqlStateUndefinedTable       = "42P01"
	sqlStateUndefinedColumn      = "42703"
	sqlStateInsufficient         = "42501"
	piidictSqlStateQueryCanceled = "57014"
)

// The type OIDs of json and jsonb, whose text values the scan unquotes.
const (
	jsonOID  = 114
	jsonbOID = 3802
)

// Relation kinds (pg_class.relkind) that have a ctid to page by.
const (
	relkindTable        = "r"
	relkindMaterialized = "m"
)

// ErrScanOverBudget is a scan that collected more values than the memory
// budget can hold even at 16-bit fingerprints; the previous base stays.
var ErrScanOverBudget = errors.New("pii: the scan found more values than pii.maxMemoryMB can hold; the previous dictionary stays")

// Builder is the dictionary the scan rebuilds (corepii.FuseDictionary).
type Builder interface {
	StartBuild() (*corepii.DictionaryBuild, error)
	RebuildNeeded() <-chan struct{}
}

// textQuerier is a handle that answers a query in Postgres's text format:
// each row's raw values (nil for NULL, valid only during the call) and its
// columns' type OIDs (pgquerier.Neutral).
type textQuerier interface {
	QueryText(ctx context.Context, sql string, args []any, row func(raw [][]byte, typeOIDs []uint32) error) error
}

// ScanSource is one agent whose readable IDENTIFIER columns the scan reads,
// with the agent's own credential (decision M51-2) and statement timeout.
type ScanSource struct {
	Agent string
	// DB is the agent's connection pool, for the catalog reads
	// (pgquerier.Neutralize).
	DB PiidictQuerier
	// ReadOnly runs each page in a read-only transaction of its own on the
	// same pool (pgquerier.ReadOnlyTx).
	ReadOnly ReadOnlyTx
	Classes  *Map
	Limits   sqlguard.Limits
}

// ScanOptions tune the scan; zero fields take the defaults.
type ScanOptions struct {
	Interval      time.Duration
	PageRows      int
	RowsPerSecond int
	// MaxMemoryBytes is pii.maxMemoryMB in bytes.
	MaxMemoryBytes int64
	// LoadTimeout bounds each catalog read; DefaultLoadTimeout when zero.
	LoadTimeout time.Duration
	Now         func() time.Time
	// Sleep waits d or until ctx is done (tests make it instant).
	Sleep func(ctx context.Context, d time.Duration) error
}

func (o ScanOptions) withDefaults() ScanOptions {
	if o.Interval <= 0 {
		o.Interval = DefaultScanInterval
	}
	if o.PageRows <= 0 {
		o.PageRows = DefaultScanPage
	}
	if o.RowsPerSecond <= 0 {
		o.RowsPerSecond = DefaultScanRowsPerSecond
	}
	if o.MaxMemoryBytes <= 0 {
		o.MaxMemoryBytes = corepii.DefaultMaxMemoryMB * bytesPerMB
	}
	if o.LoadTimeout <= 0 {
		o.LoadTimeout = DefaultLoadTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	return o
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Scanner rebuilds the dictionary from every agent's IDENTIFIER columns:
// one scanner per engine, one cycle at a time. It is engine housekeeping,
// not an agent read: nothing is recorded in the ledger.
type Scanner struct {
	dict    Builder
	sources []ScanSource
	opts    ScanOptions
	log     *slog.Logger
	// failures counts the cycles in a row that did not commit.
	failures atomic.Int32
}

// NewScanner returns the engine's scanner. It panics on a missing
// dependency.
func NewScanner(dict Builder, sources []ScanSource, opts ScanOptions, log *slog.Logger) *Scanner {
	if dict == nil || log == nil {
		panic("piidict: dictionary and logger required")
	}
	for _, s := range sources {
		if s.Agent == "" || s.DB == nil || s.Classes == nil {
			panic("piidict: scan source needs an agent, a pool and its classes")
		}
	}
	return &Scanner{dict: dict, sources: sources, opts: opts.withDefaults(), log: log}
}

// Run scans at once (the delta does not survive a restart, so values read
// before it are found again from the database), then every Interval after
// the previous cycle ended, or early when the delta reaches its cap.
func (s *Scanner) Run(ctx context.Context) {
	for {
		if _, err := s.Cycle(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("pii: dictionary scan failed; the previous dictionary and every value added since stay", "err", err)
		}
		t := time.NewTimer(s.opts.Interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-s.dict.RebuildNeeded():
			t.Stop()
		}
	}
}

// ScanResult is what one cycle read.
type ScanResult struct {
	Columns int
	Rows    int64
	Values  int64
	// Skipped counts the relations left out of this cycle.
	Skipped int
}

// Cycle reads every IDENTIFIER column and commits a new base. On any error
// but a relation it skips (gone, no longer readable, or too slow to read in
// one pass), the build is aborted and the previous base and the delta stay
// (fail closed: a base missing values is never committed). When cycles keep
// failing it warns: once the delta is full, reads of IDENTIFIER columns fail.
func (s *Scanner) Cycle(ctx context.Context) (ScanResult, error) {
	res, err := s.cycle(ctx)
	if err == nil {
		s.failures.Store(0)
		return res, nil
	}
	if n := s.failures.Add(1); n >= failWarnAfter && ctx.Err() == nil {
		s.log.Warn(fmt.Sprintf("pii: the dictionary has not been rebuilt for %d scans in a row; once its delta is full, reads of IDENTIFIER columns fail", n),
			"failedScans", n)
	}
	return res, err
}

func (s *Scanner) cycle(ctx context.Context) (ScanResult, error) {
	start := s.opts.Now()
	b, err := s.dict.StartBuild()
	if err != nil {
		return ScanResult{}, err
	}
	run := &scanRun{
		s: s, b: b, maxValues: s.opts.MaxMemoryBytes / bytesPerAddBound,
		limit: limiter{rate: s.opts.RowsPerSecond, start: start, now: s.opts.Now, sleep: s.opts.Sleep},
	}
	for _, src := range s.sources {
		if err := run.source(ctx, src); err != nil {
			b.Abort()
			return run.res, err
		}
	}
	if err := b.Commit(corepii.ScanStats{At: start, Columns: run.res.Columns, Rows: run.res.Rows}); err != nil {
		return run.res, err
	}
	s.log.Info("pii: dictionary scan", "columns", run.res.Columns, "rows", run.res.Rows,
		"values", run.res.Values, "skipped", run.res.Skipped, "duration", s.opts.Now().Sub(start).String())
	return run.res, nil
}

// scanRun is one cycle in progress.
type scanRun struct {
	s         *Scanner
	b         *corepii.DictionaryBuild
	limit     limiter
	maxValues int64
	res       ScanResult
}

func (r *scanRun) source(ctx context.Context, src ScanSource) error {
	lctx, cancel := context.WithTimeout(ctx, r.s.opts.LoadTimeout)
	cols, err := src.Classes.Identifiers(lctx, src.DB)
	cancel()
	if err != nil {
		return fmt.Errorf("agent %s: %w", src.Agent, err)
	}
	for _, t := range byTable(cols) {
		err := r.table(ctx, src, t)
		if why := skipReason(err); why != "" {
			r.res.Skipped++
			r.s.log.Warn("pii: skipped a relation in this scan: "+why, "agent", src.Agent,
				"table", t.schema+"."+t.name, "columns", len(t.cols))
			continue
		}
		if err != nil {
			return fmt.Errorf("agent %s: scan %s.%s: %w", src.Agent, t.schema, t.name, err)
		}
		r.res.Columns += len(t.cols)
	}
	return nil
}

// skipReason says why a relation's error skips it instead of failing the
// cycle, or "" when it does not: the relation is gone or no longer readable,
// or a relation without a keyset is too slow to read in one pass.
func skipReason(err error) string {
	var slow *slowRelationError
	if errors.As(err, &slow) {
		return "it has no key to page by and a full read exceeds the statement timeout; values the agent reads from it are still added"
	}
	var pe sqlStater
	if !errors.As(err, &pe) {
		return ""
	}
	switch pe.SQLState() {
	case sqlStateUndefinedTable, sqlStateUndefinedColumn, sqlStateInsufficient:
		return "the agent can no longer read it"
	}
	return ""
}

// scanTable is one table's IDENTIFIER columns.
type scanTable struct {
	oid          uint32
	schema, name string
	cols         []Class
}

// byTable groups columns by table, in a stable order.
func byTable(cols []IdentifierColumn) []scanTable {
	idx := map[uint32]int{}
	var out []scanTable
	for _, c := range cols {
		i, ok := idx[c.Ref.TableOID]
		if !ok {
			i = len(out)
			idx[c.Ref.TableOID] = i
			out = append(out, scanTable{oid: c.Ref.TableOID, schema: c.Class.Namespace, name: c.Class.Resource})
		}
		out[i].cols = append(out[i].cols, c.Class)
	}
	slices.SortFunc(out, func(a, b scanTable) int { return strings.Compare(a.schema+"."+a.name, b.schema+"."+b.name) })
	for i := range out {
		slices.SortFunc(out[i].cols, func(a, b Class) int { return strings.Compare(a.Field, b.Field) })
	}
	return out
}

// table pages through one table: by its primary key, or by ctid for a
// table or materialized view without one. A relation with neither (a view,
// a partitioned or foreign table without a key) is read in one pass, under
// the agent's statement timeout: a timeout there skips that relation
// (slowRelationError) instead of failing the whole cycle.
func (r *scanRun) table(ctx context.Context, src ScanSource, t scanTable) error {
	kctx, cancel := context.WithTimeout(ctx, r.s.opts.LoadTimeout)
	keys, relkind, err := keysetOf(kctx, src.DB, t.oid)
	cancel()
	if err != nil {
		return err
	}
	if len(keys) == 0 && relkind != relkindTable && relkind != relkindMaterialized {
		err := r.pageAll(ctx, src, onePassPager(t))
		var pe sqlStater
		if errors.As(err, &pe) && pe.SQLState() == piidictSqlStateQueryCanceled {
			return &slowRelationError{err: err}
		}
		return err
	}
	if len(keys) == 0 {
		keys = []keyColumn{{name: "ctid", typ: "tid", system: true}}
	}
	return r.pageAll(ctx, src, rowPager(t, keys))
}

// slowRelationError is a relation without a keyset that could not be read
// in one pass within the statement timeout. The cycle skips it with a
// warning; values the agent reads from it still go in the delta.
type slowRelationError struct{ err error }

func (e *slowRelationError) Error() string {
	return "read in one pass, it exceeded the statement timeout: " + e.err.Error()
}

func (e *slowRelationError) Unwrap() error { return e.err }

// relationGoneError is a relation dropped after the classes named it: the
// undefined_table Postgres raises for it, so the cycle skips it.
type relationGoneError struct{}

func (relationGoneError) Error() string    { return ": table is gone (SQLSTATE 42P01)" }
func (relationGoneError) SQLState() string { return sqlStateUndefinedTable }

// keyColumn is one column of the keyset a table is paged by.
type keyColumn struct {
	name, typ string
	// system is ctid, which is not quoted as an identifier.
	system bool
}

func (k keyColumn) sql() string {
	if k.system {
		return k.name
	}
	return quoteIdentifier(k.name)
}

// keysetOf reads a table's relkind and its primary key columns with their
// types; no key when any key column is not readable by the agent.
func keysetOf(ctx context.Context, db PiidictQuerier, oid uint32) ([]keyColumn, string, error) {
	q, args, err := piidictPsql.Select("relkind::text").From("pg_catalog.pg_class").Where(sq.Eq{"oid": oid}).ToSql()
	if err != nil {
		return nil, "", err
	}
	relRows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	var (
		relkind, kind string
		found         bool
	)
	if err := forEachRow(relRows, []any{&kind}, func() error {
		if !found {
			relkind, found = kind, true
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	if !found {
		return nil, "", relationGoneError{}
	}
	// Plain SQL: a catalog query over the unnested index key, which
	// squirrel cannot express.
	rows, err := db.Query(ctx, `SELECT a.attname::text, pg_catalog.format_type(a.atttypid, a.atttypmod),
		       coalesce(pg_catalog.has_column_privilege(a.attrelid, a.attnum, 'SELECT'), false)
		  FROM pg_catalog.pg_index i
		 CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		 WHERE i.indrelid = $1 AND i.indisprimary
		 ORDER BY k.ord`, oid)
	if err != nil {
		return nil, "", err
	}
	var (
		keys     []keyColumn
		k        keyColumn
		readable bool
		all      = true
	)
	err = forEachRow(rows, []any{&k.name, &k.typ, &readable}, func() error {
		keys = append(keys, k)
		all = all && readable
		return nil
	})
	if err != nil || !all {
		return nil, relkind, err
	}
	return keys, relkind, nil
}

// pager builds one page's statement from the cursor (nil for the first
// page). Each row holds keyCols cursor columns, then one value per column
// of cols.
type pager struct {
	query   func(cursor []string) (string, []any, error)
	keyCols int
	cols    []Class
	// onePass is a single statement with no LIMIT: its one page is all.
	onePass bool
}

// rowPager pages a table by its keyset, all IDENTIFIER columns at once:
// SELECT k…, c… FROM t WHERE (k…) > (cursor) ORDER BY k… LIMIT page.
func rowPager(t scanTable, keys []keyColumn) func(page int) pager {
	return func(page int) pager {
		sel := make([]string, 0, len(keys)+len(t.cols))
		order := make([]string, 0, len(keys))
		bounds := make([]string, 0, len(keys))
		for _, k := range keys {
			sel = append(sel, k.sql())
			order = append(order, k.sql())
			// The type is format_type's output, already quoted where needed.
			bounds = append(bounds, "CAST(? AS "+k.typ+")")
		}
		for _, c := range t.cols {
			sel = append(sel, quoteIdentifier(c.Field))
		}
		from := quoteIdentifier(t.schema, t.name)
		tuple := "(" + strings.Join(order, ", ") + ") > (" + strings.Join(bounds, ", ") + ")"
		return pager{
			keyCols: len(keys), cols: t.cols,
			query: func(cursor []string) (string, []any, error) {
				b := piidictPsql.Select(sel...).From(from).OrderBy(order...).Limit(uint64(page))
				if cursor != nil {
					b = b.Where(sq.Expr(tuple, toArgs(cursor)...))
				}
				return b.ToSql()
			},
		}
	}
}

// onePassPager reads a relation without a keyset in one streamed
// statement, all IDENTIFIER columns at once: SELECT c… FROM t. It reads
// each row once (no per-page re-sort of the whole relation), and the
// agent's statement timeout bounds it.
func onePassPager(t scanTable) func(page int) pager {
	return func(int) pager {
		sel := make([]string, 0, len(t.cols))
		for _, c := range t.cols {
			sel = append(sel, quoteIdentifier(c.Field))
		}
		from := quoteIdentifier(t.schema, t.name)
		return pager{
			cols: t.cols, onePass: true,
			query: func([]string) (string, []any, error) {
				return piidictPsql.Select(sel...).From(from).ToSql()
			},
		}
	}
}

func toArgs(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// pageAll reads every page of p, adding values to the build and pausing
// to keep the scan under RowsPerSecond.
func (r *scanRun) pageAll(ctx context.Context, src ScanSource, mk func(page int) pager) error {
	p := mk(r.s.opts.PageRows)
	var cursor []string
	for {
		next, n, err := r.page(ctx, src, p, cursor)
		if err != nil {
			return err
		}
		r.res.Rows += int64(n)
		if err := r.limit.wait(ctx, n); err != nil {
			return err
		}
		if p.onePass || n < r.s.opts.PageRows {
			return nil
		}
		cursor = next
	}
}

// page reads one page in its own read-only transaction under the agent's
// statement timeout, and returns the cursor after its last row.
func (r *scanRun) page(ctx context.Context, src ScanSource, p pager, cursor []string) ([]string, int, error) {
	q, args, err := p.query(cursor)
	if err != nil {
		return nil, 0, err
	}
	// The statement timeout bounds the query; the margin bounds the wait
	// for a connection.
	ctx, cancel := context.WithTimeout(ctx, src.Limits.StatementTimeout+pageWaitMargin)
	defer cancel()
	var next []string
	n := 0
	err = src.ReadOnly(ctx, func(tx Querier) error {
		timeout, targs, err := piidictPsql.Select().Column(sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", src.Limits.StatementTimeoutSetting())).ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, timeout, targs...); err != nil {
			return err
		}
		text, ok := tx.(textQuerier)
		if !ok {
			return errors.New("pii: the page's transaction cannot answer in text format")
		}
		return text.QueryText(ctx, q, args, func(raw [][]byte, typeOIDs []uint32) error {
			next = next[:0]
			for i := range p.keyCols {
				next = append(next, string(raw[i]))
			}
			for i, c := range p.cols {
				j := p.keyCols + i
				if err := r.add(c, typeOIDs[j], raw[j]); err != nil {
					return err
				}
			}
			n++
			return nil
		})
	})
	if err != nil {
		return nil, 0, err
	}
	return next, n, nil
}

// add puts one value in the build, bounded by the memory budget.
func (r *scanRun) add(c Class, typeOID uint32, raw []byte) error {
	v, ok := scanValue(typeOID, raw)
	if !ok {
		return nil
	}
	if r.res.Values >= r.maxValues {
		return ErrScanOverBudget
	}
	if err := r.b.Add(corepii.EntityType(c.EntityType), v, c.PhoneRegion); err != nil {
		return fmt.Errorf("add a value of %s (%s): %w", c.Name(), c.EntityType, err)
	}
	r.res.Values++
	return nil
}

// scanValue is a text-format value as the read path hands it to the
// dictionary: a JSON string unquoted, NULL and empty skipped.
func scanValue(typeOID uint32, raw []byte) (string, bool) {
	if raw == nil {
		return "", false
	}
	if typeOID == jsonOID || typeOID == jsonbOID {
		return valueText(json.RawMessage(raw))
	}
	return valueText(string(raw))
}

// limiter keeps the scan at or under rate rows per second over the cycle.
type limiter struct {
	rate  int
	start time.Time
	rows  int64
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

func (l *limiter) wait(ctx context.Context, n int) error {
	l.rows += int64(n)
	due := l.start.Add(time.Duration(l.rows) * time.Second / time.Duration(l.rate))
	if d := due.Sub(l.now()); d > 0 {
		return l.sleep(ctx, d)
	}
	return nil
}
