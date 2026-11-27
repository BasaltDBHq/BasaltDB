package pgpii

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// scanRows answers a catalog query (scanned) or a page (raw values in text
// format, with their type OIDs).
type scanRows struct {
	pgx.Rows
	scanned [][]any
	raw     [][][]byte
	oids    []uint32
	i       int
	err     error
}

func (r *scanRows) Next() bool {
	r.i++
	return r.i <= max(len(r.scanned), len(r.raw))
}

func (r *scanRows) Scan(dest ...any) error {
	for j, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(r.scanned[r.i-1][j]))
	}
	return nil
}

func (r *scanRows) RawValues() [][]byte { return r.raw[r.i-1] }

func (r *scanRows) FieldDescriptions() []pgconn.FieldDescription {
	out := make([]pgconn.FieldDescription, len(r.oids))
	for i, o := range r.oids {
		out[i].DataTypeOID = o
	}
	return out
}

func (r *scanRows) Close()     {}
func (r *scanRows) Err() error { return r.err }

// scanPool is an agent's pool: relkind and key rows for the catalog reads,
// and pages handed out in order, each in a transaction of its own.
type scanPool struct {
	Querier
	relkind  []string // none: the relation is gone
	keys     [][]any  // name, type, readable
	catErr   error
	pages    []*scanRows
	pageErr  error
	txs      []*pageTx
	queries  []string
	args     [][]any // each page's bound arguments, after the result format
	execArgs [][]any
}

func (p *scanPool) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if p.catErr != nil {
		return nil, p.catErr
	}
	if strings.Contains(sql, "pg_class") {
		r := &scanRows{}
		for _, k := range p.relkind {
			r.scanned = append(r.scanned, []any{k})
		}
		return r, nil
	}
	return &scanRows{scanned: p.keys}, nil
}

func (p *scanPool) BeginTx(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	if opts.AccessMode != pgx.ReadOnly {
		return nil, errors.New("a page must read in a read-only transaction")
	}
	tx := &pageTx{p: p}
	p.txs = append(p.txs, tx)
	return tx, nil
}

// pageTx is one page's transaction.
type pageTx struct {
	pgx.Tx
	p        *scanPool
	rolledBk bool
}

func (t *pageTx) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	t.p.execArgs = append(t.p.execArgs, args)
	return pgconn.CommandTag{}, nil
}

func (t *pageTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if f, ok := args[0].(pgx.QueryResultFormats); !ok || len(f) != 1 || f[0] != pgx.TextFormatCode {
		return nil, errors.New("a page must read in text format")
	}
	t.p.queries = append(t.p.queries, sql)
	t.p.args = append(t.p.args, args[1:])
	if t.p.pageErr != nil {
		return nil, t.p.pageErr
	}
	r := t.p.pages[0]
	t.p.pages = t.p.pages[1:]
	return r, nil
}

func (t *pageTx) Rollback(context.Context) error { t.rolledBk = true; return nil }

func target(fields ...string) piistore.ScanTarget {
	t := piistore.ScanTarget{Resource: "16384", Namespace: "public", Name: "people"}
	for _, f := range fields {
		t.Fields = append(t.Fields, piistore.FieldClass{Field: f})
	}
	return t
}

func page(oids []uint32, rows ...[][]byte) *scanRows {
	return &scanRows{raw: rows, oids: oids}
}

type got struct {
	values []any
	fields []int
	pages  []int
}

func (g *got) value(f int, v any) error {
	g.fields = append(g.fields, f)
	g.values = append(g.values, v)
	return nil
}
func (g *got) page(n int) error { g.pages = append(g.pages, n); return nil }

// A keyed table is paged by its key, the cursor bound by the key's types;
// json and jsonb values come as json.RawMessage, others as text, NULLs not
// at all; the statement timeout is set in each page's transaction.
func TestReadPagesByKey(t *testing.T) {
	text, js, jsb := uint32(pgtype.TextOID), uint32(pgtype.JSONOID), uint32(pgtype.JSONBOID)
	oids := []uint32{pgtype.Int8OID, text, js, jsb}
	pool := &scanPool{
		relkind: []string{"r"}, keys: [][]any{{"id", "bigint", true}},
		pages: []*scanRows{
			page(oids, [][]byte{[]byte("1"), []byte("a@corp.ee"), []byte(`"b@corp.ee"`), nil},
				[][]byte{[]byte("2"), nil, nil, []byte(`{"e": "c@corp.ee"}`)}),
			page(oids),
		},
	}
	limits := action.DefaultLimits()
	var g got
	require.NoError(t, Fields(pool, limits, time.Minute).Read(context.Background(), target("t", "j", "jb"), 2, g.value, g.page))
	require.Equal(t, []int{0, 1, 2}, g.fields)
	require.Equal(t, []any{"a@corp.ee", json.RawMessage(`"b@corp.ee"`), json.RawMessage(`{"e": "c@corp.ee"}`)}, g.values)
	require.Equal(t, []int{2, 0}, g.pages)
	require.Equal(t, []string{
		`SELECT "id", "t", "j", "jb" FROM "public"."people" ORDER BY "id" LIMIT 2`,
		`SELECT "id", "t", "j", "jb" FROM "public"."people" WHERE ("id") > (CAST($1 AS bigint)) ORDER BY "id" LIMIT 2`,
	}, pool.queries)
	require.Equal(t, [][]any{{}, {"2"}}, pool.args, "the second page is bound after the first page's last key")
	require.Equal(t, [][]any{{"5000"}, {"5000"}}, pool.execArgs)
}

// A table without a readable key is paged by ctid; a view without one is
// read in one pass.
func TestReadWithoutAKey(t *testing.T) {
	for _, c := range []struct {
		relkind string
		keys    [][]any
		want    string
	}{
		{"r", nil, `SELECT ctid, "email" FROM "public"."people" ORDER BY ctid LIMIT 5`},
		{"m", [][]any{{"id", "bigint", false}}, `SELECT ctid, "email" FROM "public"."people" ORDER BY ctid LIMIT 5`},
		{"v", nil, `SELECT "email" FROM "public"."people"`},
	} {
		pool := &scanPool{relkind: []string{c.relkind}, keys: c.keys, pages: []*scanRows{page(nil)}}
		var g got
		require.NoError(t, Fields(pool, action.DefaultLimits(), time.Minute).Read(context.Background(), target("email"), 5, g.value, g.page))
		require.Equal(t, []string{c.want}, pool.queries, c.relkind)
		require.Equal(t, []int{0}, g.pages)
	}
}

// page runs after the page's transaction has rolled back, so the rate
// limit's sleep never holds a pool connection.
func TestPageRunsAfterTheTransactionCloses(t *testing.T) {
	pool := &scanPool{
		relkind: []string{"r"}, keys: [][]any{{"id", "bigint", true}},
		pages: []*scanRows{page([]uint32{pgtype.Int8OID, pgtype.TextOID}, [][]byte{[]byte("1"), []byte("a@corp.ee")})},
	}
	calls := 0
	err := Fields(pool, action.DefaultLimits(), time.Minute).Read(context.Background(), target("email"), 5,
		func(int, any) error {
			require.False(t, pool.txs[0].rolledBk, "values are read inside the transaction")
			return nil
		},
		func(int) error {
			calls++
			require.True(t, pool.txs[0].rolledBk, "the page's transaction is closed")
			return nil
		})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}

// The store's errors map to the scan's skip errors, wrapping the cause; a
// statement timeout skips only a one-pass read; a callback's error and any
// other error pass through as they are.
func TestReadErrors(t *testing.T) {
	ctx := context.Background()
	read := func(pool *scanPool, value func(int, any) error) error {
		var g got
		if value == nil {
			value = g.value
		}
		return Fields(pool, action.DefaultLimits(), time.Minute).Read(ctx, target("email"), 5, value, g.page)
	}
	keyed := func() *scanPool {
		return &scanPool{
			relkind: []string{"r"}, keys: [][]any{{"id", "bigint", true}},
			pages: []*scanRows{page([]uint32{pgtype.Int8OID, pgtype.TextOID}, [][]byte{[]byte("1"), []byte("a@corp.ee")})},
		}
	}
	for _, code := range []string{"42P01", "42703", "42501"} {
		pgErr := &pgconn.PgError{Code: code}
		err := read(&scanPool{catErr: pgErr}, nil)
		require.ErrorIs(t, err, piistore.ErrUnreadable, code)
		require.ErrorIs(t, err, pgErr, "the cause stays")

		p := keyed()
		p.pageErr = pgErr
		require.ErrorIs(t, read(p, nil), piistore.ErrUnreadable, code)
	}
	require.ErrorIs(t, read(&scanPool{}, nil), piistore.ErrUnreadable, "the relation is gone")

	canceled := &pgconn.PgError{Code: "57014"}
	err := read(&scanPool{relkind: []string{"v"}, pageErr: canceled}, nil)
	require.ErrorIs(t, err, piistore.ErrTooSlow)
	require.ErrorIs(t, err, canceled)
	p := keyed()
	p.pageErr = canceled
	err = read(p, nil)
	require.ErrorIs(t, err, canceled)
	require.NotErrorIs(t, err, piistore.ErrTooSlow, "a keyed page that times out fails the cycle")
	require.NotErrorIs(t, err, piistore.ErrUnreadable)

	over := errors.New("over budget")
	require.Equal(t, over, read(keyed(), func(int, any) error { return over }))

	conn := errors.New("conn closed")
	require.Equal(t, conn, read(&scanPool{catErr: conn}, nil))
}

// A resource ref this adapter did not write fails the cycle: it is a defect,
// never a skip.
func TestReadRefusesARefItDidNotWrite(t *testing.T) {
	for _, ref := range []string{"", "0", "users", "16384/3", "016384", "-1"} {
		tg := target("email")
		tg.Resource = agentstore.ResourceRef(ref)
		err := Fields(&scanPool{}, action.DefaultLimits(), time.Minute).Read(context.Background(), tg, 5,
			func(int, any) error { return nil }, func(int) error { return nil })
		require.Error(t, err, ref)
		require.NotErrorIs(t, err, piistore.ErrUnreadable, ref)
	}
}

// readValue hands json and jsonb as json.RawMessage, a copy of the
// driver's buffer, and every other type as text.
func TestReadValue(t *testing.T) {
	raw := []byte(`"a@corp.ee"`)
	for _, oid := range []uint32{pgtype.JSONOID, pgtype.JSONBOID} {
		v := readValue(oid, raw)
		require.Equal(t, json.RawMessage(raw), v)
	}
	v := readValue(pgtype.JSONOID, raw)
	raw[1] = 'X'
	require.Equal(t, json.RawMessage(`"a@corp.ee"`), v, "a copy")
	require.Equal(t, `"X@corp.ee"`, readValue(pgtype.TextOID, raw))
}
