package pii

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// Scan defaults (M5.1 plan, section 6; CONTRACT.md engine config).
const (
	DefaultScanInterval      = 5 * time.Minute
	DefaultScanPage          = 5000
	DefaultScanRowsPerSecond = 20_000
	// BytesPerAddBound is what a build holds in memory per value until it
	// commits: two 8-byte keyed hashes. A cycle stops collecting past
	// budget / BytesPerAddBound values, so the build itself stays within
	// pii.maxMemoryMB.
	BytesPerAddBound = 16
	// DefaultLoadTimeout bounds a catalog read (the map; the store's
	// adapter takes it for a resource's key), so a pool with no free
	// connection cannot hold the scan for good.
	DefaultLoadTimeout = time.Minute
	// FailWarnAfter is how many cycles in a row may fail before the scan
	// warns that the dictionary is not being rebuilt.
	FailWarnAfter = 3
)

// ErrScanOverBudget is a scan that collected more values than the memory
// budget can hold even at 16-bit fingerprints; the previous base stays.
var ErrScanOverBudget = errors.New("pii: the scan found more values than pii.maxMemoryMB can hold; the previous dictionary stays")

// ScanSource is one agent whose readable IDENTIFIER fields the scan reads.
type ScanSource struct {
	Agent string
	// Map is the agent's classification map, read through Classes.
	Map     *Map
	Classes Classes
	// Fields reads the values, on the agent's credential.
	Fields Fields
}

// ScanOptions tune the scan; zero fields take the defaults.
type ScanOptions struct {
	Interval      time.Duration
	PageRows      int
	RowsPerSecond int
	// MaxMemoryBytes is pii.maxMemoryMB in bytes.
	MaxMemoryBytes int64
	// LoadTimeout bounds each load of the class map; DefaultLoadTimeout when
	// zero. The store's adapter bounds its own catalog reads.
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
		o.MaxMemoryBytes = corepii.DefaultMaxMemoryMB * corepii.BytesPerMB
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
		if s.Agent == "" || s.Fields == nil || s.Classes == nil {
			panic("piidict: scan source needs an agent, its fields and its classes")
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
	// Skipped counts the resources left out of this cycle.
	Skipped int
}

// Cycle reads every IDENTIFIER column and commits a new base. On any error
// but a resource it skips (gone, no longer readable, or too slow to read in
// one pass), the build is aborted and the previous base and the delta stay
// (fail closed: a base missing values is never committed). When cycles keep
// failing it warns: once the delta is full, reads of IDENTIFIER columns fail.
func (s *Scanner) Cycle(ctx context.Context) (ScanResult, error) {
	res, err := s.cycle(ctx)
	if err == nil {
		s.failures.Store(0)
		return res, nil
	}
	if n := s.failures.Add(1); n >= FailWarnAfter && ctx.Err() == nil {
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
		s: s, b: b, maxValues: s.opts.MaxMemoryBytes / BytesPerAddBound,
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
	cols, err := src.Map.Identifiers(lctx, src.Classes)
	cancel()
	if err != nil {
		return fmt.Errorf("agent %s: %w", src.Agent, err)
	}
	for _, t := range byResource(cols) {
		err := r.resource(ctx, src, t)
		if why := skipReason(err); why != "" {
			r.res.Skipped++
			r.s.log.Warn("pii: skipped a resource in this scan: "+why, "agent", src.Agent,
				"resource", t.target.Namespace+"."+t.target.Name, "columns", len(t.cols))
			continue
		}
		if err != nil {
			return fmt.Errorf("agent %s: scan %s.%s: %w", src.Agent, t.target.Namespace, t.target.Name, err)
		}
		r.res.Columns += len(t.cols)
	}
	return nil
}

// skipReason says why a resource's error skips it instead of failing the
// cycle, or "" when it does not: the resource is gone or no longer readable,
// or a resource without a keyset is too slow to read in one pass.
func skipReason(err error) string {
	switch {
	case errors.Is(err, piistore.ErrTooSlow):
		return "it has no key to page by and a full read exceeds the statement timeout; values the agent reads from it are still added"
	case errors.Is(err, piistore.ErrUnreadable):
		return "the agent can no longer read it"
	}
	return ""
}

// scanResource is one resource's IDENTIFIER fields: the target the store reads,
// and each field's class, in the same order.
type scanResource struct {
	target piistore.ScanTarget
	cols   []Class
}

// byResource groups fields by resource, in a stable order: resources by printed
// name, fields by name.
func byResource(cols []IdentifierColumn) []scanResource {
	idx := map[action.ResourceRef]int{}
	var groups [][]IdentifierColumn
	for _, c := range cols {
		i, ok := idx[c.Resource]
		if !ok {
			i = len(groups)
			idx[c.Resource] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], c)
	}
	out := make([]scanResource, 0, len(groups))
	for _, g := range groups {
		slices.SortFunc(g, func(a, b IdentifierColumn) int { return strings.Compare(a.Class.Field, b.Class.Field) })
		t := scanResource{target: piistore.ScanTarget{Resource: g[0].Resource, Namespace: g[0].Class.Namespace, Name: g[0].Class.Resource}}
		for _, c := range g {
			t.target.Fields = append(t.target.Fields, piistore.FieldClass{
				Ref: c.Ref, Resource: c.Resource, Namespace: c.Class.Namespace, ResourceName: c.Class.Resource, Field: c.Class.Field,
				Class: c.Class.Class, EntityType: c.Class.EntityType, PhoneRegion: c.Class.PhoneRegion,
			})
			t.cols = append(t.cols, c.Class)
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b scanResource) int {
		return strings.Compare(a.target.Namespace+"."+a.target.Name, b.target.Namespace+"."+b.target.Name)
	})
	return out
}

// resource reads every page of one resource through the store's adapter,
// adding each value to the build and pausing after each page to keep the
// scan under RowsPerSecond.
func (r *scanRun) resource(ctx context.Context, src ScanSource, t scanResource) error {
	return src.Fields.Read(ctx, t.target, r.s.opts.PageRows,
		func(field int, v any) error { return r.add(t.cols[field], v) },
		func(rows int) error {
			r.res.Rows += int64(rows)
			return r.limit.wait(ctx, rows)
		})
}

// add puts one value in the build, bounded by the memory budget. v is as
// the read path hands it (a string, or json.RawMessage for a JSON value),
// so the dictionary text is the same on both paths.
func (r *scanRun) add(c Class, v any) error {
	text, ok := valueText(v)
	if !ok {
		return nil
	}
	if r.res.Values >= r.maxValues {
		return ErrScanOverBudget
	}
	if err := r.b.Add(corepii.EntityType(c.EntityType), text, c.PhoneRegion); err != nil {
		return fmt.Errorf("add a value of %s (%s): %w", c.Name(), c.EntityType, err)
	}
	r.res.Values++
	return nil
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
