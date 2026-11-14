// Package agentdb runs an agent's statements on that agent's scoped Postgres
// credential. Agent SQL is run as given, with bound parameters, never
// rewritten; the engine's policy (internal/sqlguard) has already allowed it.
package agentdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/pkg/wiretime"
)

// ErrRowLimit is a read canceled because it returned more rows than the
// engine's read row limit.
var ErrRowLimit = errors.New("the query returned more rows than the read row limit")

// ErrSizeLimit is a read canceled because its result came to more than
// MaxResultBytes (resultCost; CONTRACT.md, QUERY_TIMEOUT SIZE_LIMIT).
var ErrSizeLimit = fmt.Errorf("the query result is larger than %d MiB", MaxResultBytes>>mibShift)

// MaxResultBytes bounds what one result costs the engine, summed over its
// rows (resultCost): the 16 MiB the shim accepts in one line. The engine
// stops reading there.
const MaxResultBytes = 16 << mibShift

// mibShift turns bytes into MiB.
const mibShift = 20

// maxMessageBytes bounds one message from Postgres on an agent connection
// (pgx MaxProtocolMessageBodyLen): a row of MaxResultBytes of values plus
// its framing (a length per column). pgx refuses a longer message before it
// reads its body, so a row too large for a result is never buffered.
const maxMessageBytes = MaxResultBytes + messageSlack

// messageSlack covers a row message's framing: 2 bytes for the column
// count and 4 per column, for at most Postgres's 1664 result columns.
const messageSlack = 64 << 10

// Column is one result column.
type Column struct {
	Name string
	// Type is the Postgres type name, or "oid:<n>" for a type pgx does not know.
	Type string
	// TableOID and Attnum are the table column the value comes from (pgx
	// FieldDescription), both 0 for a computed column. The engine maps them
	// to the column's PII class; they never reach the agent.
	TableOID uint32
	Attnum   int16
}

// ReadResult is the rows of one read.
type ReadResult struct {
	Columns  []Column
	Rows     []map[string]any
	Duration time.Duration
	// Versions are the guarded rows the read saw, by primary key and xmin
	// (recorded reads); empty when no row could be identified.
	Versions []guard.RowVersion
}

// Pool is the part of a pgx pool the reader needs.
type Pool interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// Reader runs reads for one agent.
type Reader struct {
	pool   Pool
	limits sqlguard.Limits
	now    func() time.Time
}

// NewReader returns a reader on pool with limits. Every read runs pinned
// (guard.PinSession), so values print the same whatever the session's
// TimeZone or styles. It panics on a nil pool.
func NewReader(pool Pool, limits sqlguard.Limits, now func() time.Time) *Reader {
	if pool == nil || now == nil {
		panic("agentdb: pool and clock required")
	}
	return &Reader{pool: guard.PinnedBeginner{TxBeginner: pool}, limits: limits, now: now}
}

// psql builds the engine's own statements with Postgres placeholders.
var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// setTimeout sets the time limit for the current transaction only:
// transaction-local, so it cannot leak through a transaction pooler.
func setTimeout(ctx context.Context, tx pgx.Tx, limits sqlguard.Limits) error {
	q, args, err := psql.Select().Column(sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", limits.StatementTimeoutSetting())).ToSql()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, args...)
	return err
}

// Read runs one SELECT in a read-only transaction within the time limit,
// and cancels it once it returns more than the row limit. For the sources
// that are guarded tables the agent can read, it also returns the version
// of each row: the statement runs with version columns added through the
// parse tree (sqlguard.WithRowVersions), which are stripped from the rows.
// If that statement fails to plan, the original runs as given and the read
// carries no versions.
func (r *Reader) Read(ctx context.Context, sql string, params []any, sources []sqlguard.RowSource) (ReadResult, error) {
	start := r.now()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return ReadResult{}, err
	}
	// A read-only transaction has nothing to commit; rollback ends it.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := setTimeout(ctx, tx, r.limits); err != nil {
		return ReadResult{}, err
	}

	res, ok, err := r.readVersioned(ctx, tx, sql, params, sources)
	if err != nil {
		return ReadResult{}, err
	}
	if !ok {
		res.Columns, res.Rows, _, err = runText(ctx, tx, sql, params, r.limits.ReadRowLimit, 0)
		if err != nil {
			return ReadResult{}, err
		}
	}
	res.Duration = r.now().Sub(start)
	return res, nil
}

// readVersioned runs the statement with version columns under a savepoint.
// ok is false when no source is a guarded table, or the rewritten
// statement failed to plan (a class 42 error) and was rolled back: the
// caller then runs the original.
func (r *Reader) readVersioned(ctx context.Context, tx pgx.Tx, sql string, params []any, sources []sqlguard.RowSource) (ReadResult, bool, error) {
	versioned, oids, err := guardedSources(ctx, tx, sources)
	if err != nil || len(versioned) == 0 {
		return ReadResult{}, false, err
	}
	rewritten, err := sqlguard.WithRowVersions(sql, versioned)
	if err != nil {
		return ReadResult{}, false, nil //nolint:nilerr // no row identity: read without versions
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return ReadResult{}, false, err
	}
	cols, rows, extras, err := runText(ctx, sp, rewritten, params, r.limits.ReadRowLimit, len(versioned)*sqlguard.VersionColumns)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && strings.HasPrefix(pe.Code, sqlStateClassSyntaxOrAccess) {
		return ReadResult{}, false, sp.Rollback(ctx)
	}
	if err != nil {
		return ReadResult{}, false, err
	}
	if err := sp.Commit(ctx); err != nil {
		return ReadResult{}, false, err
	}
	return ReadResult{Columns: cols, Rows: rows, Versions: rowVersions(extras, oids)}, true, nil
}

// sqlStateClassSyntaxOrAccess is SQLSTATE class 42: syntax error or access
// rule violation, what a rewritten statement the shape check missed fails with.
const sqlStateClassSyntaxOrAccess = "42"

// guardedSources keeps the sources that are guarded tables the agent can
// read, with their primary keys and table oids, in order.
func guardedSources(ctx context.Context, tx pgx.Tx, sources []sqlguard.RowSource) ([]sqlguard.Versioned, []uint32, error) {
	if len(sources) == 0 {
		return nil, nil, nil
	}
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		names = append(names, s.RegName())
	}
	guarded, err := guard.ResolveGuarded(ctx, tx, names)
	if err != nil {
		return nil, nil, err
	}
	var versioned []sqlguard.Versioned
	var oids []uint32
	for _, s := range sources {
		g, ok := guarded[s.RegName()]
		if !ok {
			continue
		}
		versioned = append(versioned, sqlguard.Versioned{Source: s, PKCols: g.PKCols})
		oids = append(oids, g.OID)
	}
	return versioned, oids, nil
}

// rowVersions reads the version columns: per row, per source, the key
// (jsonb text) then xmin. A source with no row on this output row (an
// outer join) has a NULL xmin and is skipped.
func rowVersions(extras [][][]byte, oids []uint32) []guard.RowVersion {
	var out []guard.RowVersion
	for _, row := range extras {
		for i, oid := range oids {
			key, version := row[i*sqlguard.VersionColumns], row[i*sqlguard.VersionColumns+1]
			if version == nil {
				continue
			}
			out = append(out, guard.RowVersion{TableOID: oid, Key: json.RawMessage(key), Version: string(version)})
		}
	}
	return out
}

// runText runs one statement on tx with every result column in text format,
// so any type renders without a type-specific decoder, and returns its rows.
// The last extra columns are returned raw instead of in the rows. Past
// limit rows the statement is canceled instead of drained.
func runText(ctx context.Context, tx pgx.Tx, sql string, params []any, limit, extra int) ([]Column, []map[string]any, [][][]byte, error) {
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	args := append([]any{pgx.QueryResultFormats{pgx.TextFormatCode}}, params...)
	rows, err := tx.Query(queryCtx, sql, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()

	fds := rows.FieldDescriptions()
	if len(fds) < extra {
		// No row description: the statement failed to plan (a column that
		// does not exist), and the error shows once the rows are closed.
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, nil, err
		}
		return nil, nil, nil, fmt.Errorf("statement returned %d columns, fewer than its %d version columns", len(fds), extra)
	}
	visible := len(fds) - extra
	cols := columns(tx.Conn().TypeMap(), fds[:visible])
	out := []map[string]any{}
	var extras [][][]byte
	size, perRow := 0, rowOverhead(cols, len(fds))
	for rows.Next() {
		if len(out) == limit {
			cancel()
			return nil, nil, nil, ErrRowLimit
		}
		raw := rows.RawValues()
		if size += perRow + valuesCost(raw); size > MaxResultBytes {
			cancel()
			return nil, nil, nil, ErrSizeLimit
		}
		out = append(out, rowValues(cols, fds, raw))
		if extra > 0 {
			extras = append(extras, cloneRaw(raw[visible:]))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	return cols, out, extras, nil
}

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

// rowOverhead is the fixed cost of a row of the result: valueOverhead per
// column, version columns included, plus each visible column's name, which
// the JSON answer repeats in every row.
func rowOverhead(cols []Column, n int) int {
	cost := n * valueOverhead
	for _, c := range cols {
		cost += len(c.Name)
	}
	return cost
}

// valuesCost is the bytes of a row's values, with what JSON adds for the
// bytes it escapes.
func valuesCost(raw [][]byte) int {
	n := 0
	for _, v := range raw {
		n += len(v)
		for _, b := range v {
			if b < ' ' || b == '"' || b == '\\' || b == '<' || b == '>' || b == '&' {
				n += jsonEscapeCost
			}
		}
	}
	return n
}

// cloneRaw copies raw values, which pgx reuses for the next row.
func cloneRaw(raw [][]byte) [][]byte {
	out := make([][]byte, len(raw))
	for i, v := range raw {
		if v != nil {
			out[i] = bytes.Clone(v)
		}
	}
	return out
}

// columns names the result columns. A repeated name (a join selecting two
// "id" columns) gets a "_2", "_3" suffix so no value is lost in the row
// object; the column list shows the key used.
func columns(tm *pgtype.Map, fds []pgconn.FieldDescription) []Column {
	seen := map[string]int{}
	cols := make([]Column, 0, len(fds))
	for _, fd := range fds {
		name := fd.Name
		seen[name]++
		if n := seen[name]; n > 1 {
			name = name + "_" + strconv.Itoa(n)
		}
		typ := "oid:" + strconv.FormatUint(uint64(fd.DataTypeOID), 10)
		if t, ok := tm.TypeForOID(fd.DataTypeOID); ok {
			typ = t.Name
		}
		cols = append(cols, Column{Name: name, Type: typ, TableOID: fd.TableOID, Attnum: int16(fd.TableAttributeNumber)})
	}
	return cols
}

func rowValues(cols []Column, fds []pgconn.FieldDescription, raw [][]byte) map[string]any {
	row := make(map[string]any, len(cols))
	for i, c := range cols {
		row[c.Name] = textValue(fds[i].DataTypeOID, raw[i])
	}
	return row
}

// textValue maps one text-format value to JSON: booleans and finite numbers
// as JSON values, json and jsonb inline, NULL as null, a timestamptz as RFC
// 3339 UTC with Z whatever the session's TimeZone, everything else as the
// string Postgres printed.
func textValue(oid uint32, raw []byte) any {
	if raw == nil {
		return nil
	}
	s := string(raw)
	switch oid {
	case pgtype.BoolOID:
		return s == "t"
	case pgtype.Int2OID, pgtype.Int4OID, pgtype.Int8OID, pgtype.OIDOID:
		return json.Number(s)
	case pgtype.Float4OID, pgtype.Float8OID, pgtype.NumericOID:
		if _, err := strconv.ParseFloat(s, 64); err != nil || s == "NaN" || s == "Infinity" || s == "-Infinity" {
			return s
		}
		return json.Number(s)
	case pgtype.TimestamptzOID:
		out, _ := wiretime.Text(s) // infinity and the like stay as printed
		return out
	case pgtype.JSONOID, pgtype.JSONBOID:
		return json.RawMessage(bytes.Clone(raw)) // pgx reuses raw for the next read on the connection
	}
	return s
}

// ParamValues converts JSON-decoded parameters for pgx: integral numbers
// become int64 and other numbers float64, so an id passed as 4211 binds to
// an integer column.
func ParamValues(params []any) ([]any, error) {
	out := make([]any, 0, len(params))
	for i, p := range params {
		switch p.(type) {
		case map[string]any, []any:
			return nil, fmt.Errorf("params[%d]: must be a string, number, boolean or null", i)
		}
		n, ok := p.(json.Number)
		if !ok {
			out = append(out, p)
			continue
		}
		if v, err := n.Int64(); err == nil {
			out = append(out, v)
			continue
		}
		v, err := n.Float64()
		if err != nil {
			return nil, fmt.Errorf("params[%d]: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// NewPool opens a lazy pool on an agent's credential: no connection is made
// until the first statement, so the engine starts while the database is down.
func NewPool(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	pool, _, err := NewSwitchablePool(ctx, url, maxConns)
	return pool, err
}
