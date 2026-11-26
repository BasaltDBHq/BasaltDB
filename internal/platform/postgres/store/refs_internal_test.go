package store

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// A result column from a table carries its field ref; a computed column
// (table 0) carries none.
func TestColumnsCarryFieldRefs(t *testing.T) {
	t.Parallel()
	cols := columns(pgtype.NewMap(), []pgconn.FieldDescription{
		{Name: "email", TableOID: 16384, TableAttributeNumber: 3, DataTypeOID: pgtype.TextOID},
		{Name: "lower", DataTypeOID: pgtype.TextOID},
	})
	require.Equal(t, []action.Column{
		{Name: "email", Type: "text", Ref: "16384/3"},
		{Name: "lower", Type: "text"},
	}, cols)
}

// The reader names a version's resource by its ref, and the record reads the
// ref back as the table's OID; a ref the reader did not write is refused.
func TestRowVersionsRoundTripTheResourceRef(t *testing.T) {
	t.Parallel()
	vs := rowVersions([][][]byte{{[]byte(`{"id": 1}`), []byte("7")}}, []uint32{16384})
	require.Equal(t, []action.RowVersion{{Resource: "16384", Key: json.RawMessage(`{"id": 1}`), Version: "7"}}, vs)

	got, err := guardVersions(vs)
	require.NoError(t, err)
	require.Equal(t, []guard.RowVersion{{TableOID: 16384, Key: json.RawMessage(`{"id": 1}`), Version: "7"}}, got)

	for _, bad := range []action.ResourceRef{"", "public.leads", "16384/3", "-1", "4294967296"} {
		_, err := guardRead(action.Read{Versions: []action.RowVersion{{Resource: bad, Version: "1"}}})
		require.Error(t, err, "ref %q", bad)
	}
	got, err = guardVersions(nil)
	require.NoError(t, err)
	require.Nil(t, got)
}
