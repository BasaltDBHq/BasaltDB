package app

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// A result column from a table is its field ref; a computed one (oid 0)
// has none. The key is the column's name in each row.
func TestResultFieldsNameEachColumnsField(t *testing.T) {
	got := resultFields([]action.Column{
		{Name: "email", TableOID: 16384, Attnum: 3},
		{Name: "lower", TableOID: 0, Attnum: 0},
	})
	require.Equal(t, []piistore.ResultField{{Ref: "16384/3", Key: "email"}, {Key: "lower"}}, got)
	require.Empty(t, resultFields(nil))
}

// classTx is a write's transaction holding one class row: public.people's
// email (16384/3), IDENTIFIER email. It records the statements it ran.
type classTx struct {
	pgquerier.Querier
	ran []string
}

func (t *classTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	t.ran = append(t.ran, sql)
	return classRow{}
}

func (t *classTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	t.ran = append(t.ran, sql)
	if strings.Contains(sql, "agent_pii_columns") {
		return &classRows{rows: [][]any{{
			uint32(16384), int16(3), "public", "people", "email",
			guardmodel.ClassIdentifier, guardmodel.EntityEmail, "",
		}}}, nil
	}
	return &classRows{}, nil
}

// classRow is the fingerprint.
type classRow struct{}

func (classRow) Scan(dest ...any) error {
	*dest[0].(*[]byte) = []byte{1}
	return nil
}

type classRows struct {
	pgx.Rows
	rows [][]any
	i    int
}

func (r *classRows) Next() bool { r.i++; return r.i <= len(r.rows) }
func (r *classRows) Close()     {}
func (r *classRows) Err() error { return nil }

func (r *classRows) Scan(dest ...any) error {
	for j, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(r.rows[r.i-1][j]))
	}
	return nil
}

// adds records the values added to the dictionary.
type adds []string

func (a *adds) Add(t corepii.EntityType, value, _ string) error {
	*a = append(*a, string(t)+":"+value)
	return nil
}

// returnedPII reads the classes on the write's own transaction and adds the
// RETURNING values of IDENTIFIER columns; a computed column has no class.
func TestReturnedPIIReadsOnTheWritesTransaction(t *testing.T) {
	var added adds
	obs := pii.NewObserver(pii.NewMap(slog.New(slog.DiscardHandler)), &added)
	tx := &classTx{}
	err := returnedPII(obs)(context.Background(), pgquerier.Neutralize(tx),
		[]action.Column{{Name: "email", TableOID: 16384, Attnum: 3}, {Name: "lower", TableOID: 0}},
		[]map[string]any{{"email": "ada@corp.ee", "lower": "eve@corp.ee"}})
	require.NoError(t, err)
	require.Equal(t, adds{string(corepii.EntityEmail) + ":ada@corp.ee"}, added)
	require.NotEmpty(t, tx.ran, "the classes are read on the write's transaction")

	failing := &failingTx{err: errors.New("tx aborted")}
	err = returnedPII(obs)(context.Background(), pgquerier.Neutralize(failing),
		[]action.Column{{Name: "email", TableOID: 16385, Attnum: 3}}, []map[string]any{{"email": "bob@corp.ee"}})
	require.ErrorIs(t, err, failing.err, "a reload on the transaction fails the write")
}

// failingTx fails every read.
type failingTx struct {
	pgquerier.Querier
	err error
}

func (t *failingTx) QueryRow(context.Context, string, ...any) pgx.Row { return failingRow{t.err} }
func (t *failingTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, t.err
}

type failingRow struct{ err error }

func (r failingRow) Scan(...any) error { return r.err }
