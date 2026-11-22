// Package resultsize bounds what the reads of one tool call cost the engine
// (CONTRACT.md, QUERY_TIMEOUT SIZE_LIMIT): every row read on the agent's
// connection is charged against one budget the call carries in its context,
// and a read that goes over it stops with ErrSizeLimit. A context with no
// budget (the person's CLI, upkeep) reads unbounded.
package resultsize

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MaxBytes bounds what one call's reads cost, summed over their rows: the
// 16 MiB the shim accepts in one line.
const MaxBytes = 16 << mibShift

// mibShift turns bytes into MiB.
const mibShift = 20

// ErrSizeLimit is a read stopped because the call's reads came to more than
// MaxBytes.
var ErrSizeLimit = fmt.Errorf("the query result is larger than %d MiB", MaxBytes>>mibShift)

// valueOverhead is what one value costs the engine beyond its bytes: its
// map entry and Go value in the row, and its key, quotes and comma in the
// JSON answer. A NULL or empty value costs it too, so a wide result of
// NULLs is bounded like one of long values.
const valueOverhead = 128

// jsonEscapeCost is the most bytes JSON adds for one byte it escapes: a
// control byte, <, > or & becomes \u00XX, and the result is JSON again as
// the text of the MCP content, where the backslash doubles (\\u00XX): 7
// bytes for 1.
const jsonEscapeCost = 6

// Budget is one call's budget. Reads of the call may run concurrently.
type Budget struct {
	used atomic.Int64
	max  int64
}

type budgetKey struct{}

// With returns ctx carrying a new budget of MaxBytes for one call.
func With(ctx context.Context) context.Context {
	return WithMax(ctx, MaxBytes)
}

// WithMax returns ctx carrying a new budget of max bytes: With's, or a
// small one in tests.
func WithMax(ctx context.Context, maxBytes int64) context.Context {
	return context.WithValue(ctx, budgetKey{}, &Budget{max: maxBytes})
}

// Ensure returns ctx with a budget: its own when it has one, else a new one.
func Ensure(ctx context.Context) context.Context {
	if From(ctx) != nil {
		return ctx
	}
	return With(ctx)
}

// From returns ctx's budget, nil when it has none.
func From(ctx context.Context) *Budget {
	b, _ := ctx.Value(budgetKey{}).(*Budget)
	return b
}

// Charge adds cost to b and reports ErrSizeLimit once the total is over
// MaxBytes. A nil budget charges nothing.
func (b *Budget) Charge(cost int) error {
	if b == nil {
		return nil
	}
	if b.used.Add(int64(cost)) > b.max {
		return ErrSizeLimit
	}
	return nil
}

// RowCost is what one row costs: valueOverhead per column, each column's
// name (the JSON answer repeats it per row), and its values' bytes with what
// JSON adds for the bytes it escapes.
func RowCost(fds []pgconn.FieldDescription, raw [][]byte) int {
	cost := len(fds) * valueOverhead
	for _, fd := range fds {
		cost += len(fd.Name)
	}
	for _, v := range raw {
		cost += len(v)
		for _, c := range v {
			if c < ' ' || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
				cost += jsonEscapeCost
			}
		}
	}
	return cost
}

// Rows charges each row of rows to ctx's budget as it is read. Past the
// budget Next returns false, Err returns ErrSizeLimit, and cancel (the
// query's context) stops the statement instead of draining it. Rows already
// charging are returned as they are, so a row is never charged twice.
func Rows(ctx context.Context, rows pgx.Rows, cancel context.CancelFunc) pgx.Rows {
	if _, ok := rows.(*budgetRows); ok {
		return rows
	}
	b := From(ctx)
	if b == nil {
		return rows
	}
	return &budgetRows{Rows: rows, budget: b, cancel: cancel}
}

type budgetRows struct {
	pgx.Rows
	budget *Budget
	cancel context.CancelFunc
	err    error
}

func (r *budgetRows) Next() bool {
	if r.err != nil || !r.Rows.Next() {
		return false
	}
	fds, raw := r.FieldDescriptions(), r.RawValues()
	cost := RowCost(fds, raw)
	if int64(cost) > r.budget.max {
		r.err = rowTooLarge(cost, fds, raw)
		r.cancel()
		r.Rows.Close()
		return false
	}
	if err := r.budget.Charge(cost); err != nil {
		r.err = err
		r.cancel()
		r.Rows.Close()
		return false
	}
	return true
}

func (r *budgetRows) Err() error {
	if r.err != nil {
		return r.err
	}
	return r.Rows.Err()
}

func (r *budgetRows) Close() {
	r.Rows.Close()
	r.cancel()
}

// Querier is the part of a pgx pool or transaction that runs statements.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// query runs sql on q with its rows charged to ctx's budget.
func query(ctx context.Context, q Querier, sql string, args ...any) (pgx.Rows, error) {
	if From(ctx) == nil {
		return q.Query(ctx, sql, args...)
	}
	queryCtx, cancel := context.WithCancel(ctx)
	rows, err := q.Query(queryCtx, sql, args...)
	if err != nil {
		cancel()
		return nil, err
	}
	return Rows(ctx, rows, cancel), nil
}

// queryRow is QueryRow with its row charged to ctx's budget, as pgx's own
// QueryRow reads the first row of Query.
func queryRow(ctx context.Context, q Querier, sql string, args ...any) pgx.Row {
	if From(ctx) == nil {
		return q.QueryRow(ctx, sql, args...)
	}
	rows, err := query(ctx, q, sql, args...)
	return &budgetRow{rows: rows, err: err}
}

type budgetRow struct {
	rows pgx.Rows
	err  error
}

func (r *budgetRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	defer r.rows.Close()
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if err := r.rows.Scan(dest...); err != nil {
		return err
	}
	r.rows.Close()
	return r.rows.Err()
}

// Pool is the part of a pgx pool the agent's stores use.
type Pool interface {
	Querier
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// Budgeted is p with every statement's rows, on p and in its transactions,
// charged to the budget of the context they run under.
func Budgeted(p Pool) Pool {
	if p == nil {
		panic("resultsize: pool required")
	}
	return budgetPool{p: p}
}

type budgetPool struct{ p Pool }

func (b budgetPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return b.p.Exec(ctx, sql, args...)
}

func (b budgetPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return query(ctx, b.p, sql, args...)
}

func (b budgetPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return queryRow(ctx, b.p, sql, args...)
}

func (b budgetPool) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := b.p.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return budgetTx{Tx: tx}, nil
}

// budgetTx is a transaction whose statements' rows are charged like the
// pool's.
type budgetTx struct{ pgx.Tx }

func (t budgetTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return query(ctx, t.Tx, sql, args...)
}

func (t budgetTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return queryRow(ctx, t.Tx, sql, args...)
}

func (t budgetTx) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := t.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return budgetTx{Tx: tx}, nil
}

// IsSizeLimit reports whether err is a read stopped by the budget.
func IsSizeLimit(err error) bool { return errors.Is(err, ErrSizeLimit) }

// RowTooLargeError is one row of a result that costs more than the whole
// budget on its own (CONTRACT.md, QUERY_TIMEOUT ROW_TOO_LARGE), or that
// was over the connection's message cap and never read (OnWire). It is a
// SIZE_LIMIT too (errors.Is ErrSizeLimit).
type RowTooLargeError struct {
	// Bytes is the row's cost, or its size on the wire when OnWire.
	Bytes  int
	OnWire bool
	// Columns are the row's columns, largest first; Bytes is -1 for every
	// column when OnWire (the row was never read).
	Columns []ColumnSize
}

// ColumnSize is one column of a row too large and what its value costs.
type ColumnSize struct {
	Name  string
	Bytes int
}

// maxNamedColumns bounds the columns a RowTooLargeError message names.
const maxNamedColumns = 5

func (e *RowTooLargeError) Error() string {
	shown := e.Columns[:min(len(e.Columns), maxNamedColumns)]
	names := make([]string, 0, len(shown))
	for _, c := range shown {
		if c.Bytes < 0 {
			names = append(names, c.Name)
			continue
		}
		names = append(names, fmt.Sprintf("%s (%s)", c.Name, Size(c.Bytes)))
	}
	more := ""
	if n := len(e.Columns) - len(names); n > 0 {
		more = fmt.Sprintf(" and %d more", n)
	}
	if e.OnWire {
		return fmt.Sprintf("one row of the result is %s on the wire, over the %d MiB result budget on its own, so it was not read; "+
			"its columns: %s%s (which is largest is unknown)", Size(e.Bytes), MaxBytes>>mibShift, strings.Join(names, ", "), more)
	}
	return fmt.Sprintf("one row of the result costs %s, over the %d MiB result budget on its own; its largest columns: %s%s",
		Size(e.Bytes), MaxBytes>>mibShift, strings.Join(names, ", "), more)
}

// Unwrap makes a row too large a SIZE_LIMIT for any caller that does not
// tell the two apart.
func (e *RowTooLargeError) Unwrap() error { return ErrSizeLimit }

// RowTooLargeOnWire is the error of a row over the connection's message
// cap, of size bytes, in a result with columns fds: pgx refused it before
// reading it, so no column's size is known.
func RowTooLargeOnWire(bytes int, fds []pgconn.FieldDescription) *RowTooLargeError {
	cols := make([]ColumnSize, 0, len(fds))
	for _, fd := range fds {
		cols = append(cols, ColumnSize{Name: fd.Name, Bytes: -1})
	}
	return &RowTooLargeError{Bytes: bytes, OnWire: true, Columns: cols}
}

// rowTooLarge names a row's columns by what each value costs, largest
// first.
func rowTooLarge(cost int, fds []pgconn.FieldDescription, raw [][]byte) *RowTooLargeError {
	cols := make([]ColumnSize, 0, len(fds))
	for i, fd := range fds {
		cols = append(cols, ColumnSize{Name: fd.Name, Bytes: RowCost(fds[i:i+1], raw[i:i+1])})
	}
	sort.SliceStable(cols, func(a, b int) bool { return cols[a].Bytes > cols[b].Bytes })
	return &RowTooLargeError{Bytes: cost, Columns: cols}
}

// kib is 1 KiB.
const kib = 1 << 10

// Size is n bytes for a person: bytes, KiB or MiB with one decimal.
func Size(n int) string {
	switch {
	case n >= 1<<mibShift:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<mibShift))
	case n >= kib:
		return fmt.Sprintf("%.1f KiB", float64(n)/kib)
	}
	return fmt.Sprintf("%d bytes", n)
}

// Unbudgeted is ctx with no budget: the reads made with it are not
// charged. For reads the engine keeps to itself and never hands to the
// agent, such as a held write's preview lines on their way back to
// Postgres (CONTRACT.md, Large values, rule 6).
func Unbudgeted(ctx context.Context) context.Context {
	return context.WithValue(ctx, budgetKey{}, (*Budget)(nil))
}
