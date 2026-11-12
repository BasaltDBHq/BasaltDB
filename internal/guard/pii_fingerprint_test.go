package guard_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// plainIdent is a name quote_ident leaves bare (keywords aside: the test
// names are not reserved words).
var plainIdent = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

func quoteIdent(s string) string {
	if plainIdent.MatchString(s) {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// fingerprintOf is pii_fingerprint() built in Go from pii_readable_columns():
// lines schema.table.column:type:table_oid:attnum, names quoted as %I
// quotes them, sorted in byte order and joined by a line break.
func fingerprintOf(t *testing.T, q guard.Querier) []byte {
	t.Helper()
	rows, err := q.Query(context.Background(), `SELECT table_schema, table_name, column_name, data_type,
		table_oid::bigint, attnum FROM basalt_meta.pii_readable_columns()`)
	require.NoError(t, err)
	lines, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var schema, table, column, typ string
		var oid int64
		var attnum int16
		err := r.Scan(&schema, &table, &column, &typ, &oid, &attnum)
		return fmt.Sprintf("%s.%s.%s:%s:%d:%d", quoteIdent(schema), quoteIdent(table), quoteIdent(column),
			typ, oid, attnum), err
	})
	require.NoError(t, err)
	sort.Strings(lines) // byte order, as COLLATE "C"
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return sum[:]
}

func liveFingerprint(t *testing.T, q guard.Querier) []byte {
	t.Helper()
	var fp []byte
	require.NoError(t, q.QueryRow(context.Background(), `SELECT basalt_meta.pii_fingerprint()`).Scan(&fp))
	return fp
}

// A classified table dropped and created again with the same columns has a
// new oid, so the fingerprint moves and an engine keyed by oid reloads.
func TestPIIFingerprintMovesWhenATableIsRecreated(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	ctx := context.Background()
	const create = `CREATE TABLE public.contacts (id bigint PRIMARY KEY, email text)`
	p.Exec(t, create)
	p.Exec(t, `GRANT SELECT ON public.contacts TO `+p.bot.Role)
	p.classifyAll(t)

	oidOf := func() uint32 {
		var oid uint32
		require.NoError(t, p.bot.Conn.QueryRow(ctx, `SELECT DISTINCT table_oid FROM basalt_meta.agent_pii_columns
			WHERE table_schema = 'public' AND table_name = 'contacts'`).Scan(&oid))
		return oid
	}
	before, oldOID := liveFingerprint(t, p.bot.Conn), oidOf()

	p.Exec(t, `DROP TABLE public.contacts`)
	p.Exec(t, create)
	p.Exec(t, `GRANT SELECT ON public.contacts TO `+p.bot.Role)

	newOID := oidOf()
	require.NotEqual(t, oldOID, newOID, "the classes follow the table by name")
	after := liveFingerprint(t, p.bot.Conn)
	require.NotEqual(t, before, after)
	require.Equal(t, fingerprintOf(t, p.Admin), after)
}

// Names are quoted, so a table "x.y" in public and a table y in a schema
// "public.x" give different lines, and a name with a quote is quoted whole.
func TestPIIFingerprintQuotesNames(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.Exec(t, `CREATE SCHEMA "public.x"`)
	p.Exec(t, `CREATE TABLE public."x.y" (c text, "say ""hi""" text)`)
	p.Exec(t, `GRANT SELECT ON public."x.y" TO `+p.bot.Role)
	dotted := liveFingerprint(t, p.bot.Conn)
	require.Equal(t, fingerprintOf(t, p.Admin), dotted)

	// The same table (same oid and attnums) moved to public.x.y: unquoted,
	// both are public.x.y.c.
	p.Exec(t, `ALTER TABLE public."x.y" RENAME TO y`)
	p.Exec(t, `ALTER TABLE public.y SET SCHEMA "public.x"`)
	moved := liveFingerprint(t, p.bot.Conn)
	require.NotEqual(t, dotted, moved)
	require.Equal(t, fingerprintOf(t, p.Admin), moved)
}

// Version 19 replaces the function only: owner, SECURITY INVOKER, the
// pinned search_path and the grants are the ones version 15 gave it.
func TestPIIFingerprintPrivilegesUnchanged(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	ctx := context.Background()

	var owner string
	var definer bool
	var config []string
	require.NoError(t, p.Admin.QueryRow(ctx, `SELECT pg_get_userbyid(proowner)::text, prosecdef, proconfig
		FROM pg_proc WHERE oid = 'basalt_meta.pii_fingerprint()'::regprocedure`).Scan(&owner, &definer, &config))
	require.Equal(t, p.Names.Guard(), owner)
	require.False(t, definer)
	require.Equal(t, []string{"search_path=pg_catalog"}, config)

	// The same ACL as pii_unclassified(), which version 19 does not touch:
	// the owner and the agents group, not PUBLIC.
	acl := func(fn string) []string {
		return strings2(t, p.Admin, `SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END
			|| ':' || a.privilege_type FROM pg_proc f, aclexplode(f.proacl) a
			WHERE f.oid = 'basalt_meta.`+fn+`'::regprocedure ORDER BY 1`)
	}
	require.Equal(t, []string{p.Names.Agents() + ":EXECUTE", p.Names.Guard() + ":EXECUTE"}, acl("pii_fingerprint()"))
	require.Equal(t, acl("pii_unclassified()"), acl("pii_fingerprint()"))

	for _, role := range []string{p.bot.Role, p.other.Role} {
		var can bool
		require.NoError(t, p.Admin.QueryRow(ctx, `SELECT has_function_privilege($1, 'basalt_meta.pii_fingerprint()', 'EXECUTE')`,
			role).Scan(&can))
		require.True(t, can, role)
	}
	require.Len(t, liveFingerprint(t, p.bot.Conn), sha256.Size)
}
