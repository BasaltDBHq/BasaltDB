package agentcatalog

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgcatalog"
)

// A SELECT grant is Basalt's READ; INSERT, UPDATE and DELETE keep their
// names, and a resource read without privileges names no action.
func TestPgActionNamesBasaltsOps(t *testing.T) {
	t.Parallel()
	require.Equal(t, action.OpRead, pgAction("SELECT"))
	require.Equal(t, action.OpInsert, pgAction("INSERT"))
	require.Equal(t, action.OpUpdate, pgAction("UPDATE"))
	require.Equal(t, action.OpDelete, pgAction("DELETE"))

	r := pgResource(pgcatalog.Relation{OID: 16384, Schema: "public", Name: "leads", Kind: "TABLE", Privileges: []string{"SELECT", "UPDATE"}})
	require.Equal(t, []action.Op{action.OpRead, action.OpUpdate}, r.Actions)
	require.Nil(t, pgResource(pgcatalog.Relation{OID: 16384, Schema: "public", Name: "leads", Kind: "TABLE"}).Actions)
}

// TestPgMatchedNamesTheStoreNeutralWords: a search match says resource,
// namespace and field, never the catalog's table, schema and column.
func TestPgMatchedNamesTheStoreNeutralWords(t *testing.T) {
	t.Parallel()
	require.Equal(t, "resource", pgMatched("table"))
	require.Equal(t, "namespace", pgMatched("schema"))
	require.Equal(t, "field invoice_id", pgMatched("column invoice_id"))
	require.Equal(t, "field column x", pgMatched("column column x"))
	require.Equal(t, "comment", pgMatched("comment"))
}
