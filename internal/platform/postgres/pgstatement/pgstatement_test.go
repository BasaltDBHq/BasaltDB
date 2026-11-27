package pgstatement_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgstatement"
)

func refusalOf(t *testing.T, err error) pgstatement.Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	var r *pgstatement.RefusalError
	require.True(t, errors.As(err, &r), "error %v is not a refusal", err)
	return r.Reason
}

func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sql     string
		kind    pgstatement.Kind
		op      pgstatement.Op
		refused pgstatement.Reason
		tables  []string
		funcs   []string
		params  int
	}{
		{
			sql:  "SELECT id, lower(name) FROM public.leads l JOIN deals d ON d.lead_id = l.id WHERE l.created_at > now() - interval '1 day'",
			kind: pgstatement.KindRead, op: pgstatement.OpRead, tables: []string{"deals", "public.leads"}, funcs: []string{"lower", "now"},
		},
		{sql: "SELECT count(id), coalesce(max(score), 0) FROM leads", kind: pgstatement.KindRead, op: pgstatement.OpRead, tables: []string{"leads"}, funcs: []string{"count", "max"}},
		{sql: "WITH recent AS (SELECT * FROM leads) SELECT * FROM recent", kind: pgstatement.KindRead, op: pgstatement.OpRead, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT * FROM leads WHERE id = $1 AND status = $3", kind: pgstatement.KindRead, op: pgstatement.OpRead, tables: []string{"leads"}, funcs: []string{}, params: 3},
		{sql: "SELECT pg_catalog.lower('A')", kind: pgstatement.KindRead, op: pgstatement.OpRead, tables: []string{}, funcs: []string{"pg_catalog.lower"}},
		{sql: "UPDATE cases SET status = $1 WHERE id = $2", kind: pgstatement.KindWrite, op: pgstatement.OpUpdate, tables: []string{"cases"}, funcs: []string{}, params: 2},
		{sql: "INSERT INTO leads(name) VALUES ('a') ON CONFLICT (name) DO UPDATE SET name = excluded.name", kind: pgstatement.KindWrite, op: pgstatement.OpInsert, tables: []string{"leads"}, funcs: []string{}},
		{sql: "DELETE FROM leads WHERE id IN (SELECT lead_id FROM spam) RETURNING id", kind: pgstatement.KindWrite, op: pgstatement.OpDelete, tables: []string{"leads", "spam"}, funcs: []string{}},
		{sql: "WITH s AS (SELECT id FROM spam) DELETE FROM leads WHERE id IN (SELECT id FROM s)", kind: pgstatement.KindWrite, op: pgstatement.OpDelete, tables: []string{"leads", "spam"}, funcs: []string{}},

		{sql: "SELECT 1; DELETE FROM leads", refused: pgstatement.ReasonMultipleStatements},
		{sql: "SELEC 1", refused: pgstatement.ReasonParseError},
		{sql: "", refused: pgstatement.ReasonMultipleStatements},
		{sql: "WITH d AS (DELETE FROM leads RETURNING id) SELECT count(*) FROM d", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonDataModifyingWith, tables: []string{"leads"}, funcs: []string{"count"}},
		{sql: "WITH d AS (DELETE FROM a RETURNING id) INSERT INTO b SELECT id FROM d", kind: pgstatement.KindWrite, op: pgstatement.OpInsert, refused: pgstatement.ReasonDataModifyingWith, tables: []string{"a", "b"}, funcs: []string{}},
		{sql: "COPY leads TO '/tmp/x'", kind: pgstatement.KindUtility, op: "CopyStmt", refused: pgstatement.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "COPY leads FROM PROGRAM 'curl evil'", kind: pgstatement.KindUtility, op: "CopyStmt", refused: pgstatement.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "DROP TABLE leads", kind: pgstatement.KindDDL, op: "DropStmt", refused: pgstatement.ReasonDDL, tables: []string{}, funcs: []string{}},
		{sql: "ALTER TABLE leads DISABLE TRIGGER ALL", kind: pgstatement.KindDDL, op: "AlterTableStmt", refused: pgstatement.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "TRUNCATE leads", kind: pgstatement.KindDDL, op: "TruncateStmt", refused: pgstatement.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "CREATE TABLE x (id int)", kind: pgstatement.KindDDL, op: "CreateStmt", refused: pgstatement.ReasonDDL, tables: []string{"x"}, funcs: []string{}},
		{sql: "GRANT SELECT ON leads TO public", kind: pgstatement.KindDDL, op: "GrantStmt", refused: pgstatement.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT * INTO copy_of_leads FROM leads", kind: pgstatement.KindDDL, op: pgstatement.OpRead, refused: pgstatement.ReasonSelectInto, tables: []string{"copy_of_leads", "leads"}, funcs: []string{}},
		{sql: "SELECT * FROM leads FOR UPDATE", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonLockingRead, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT pg_sleep(100)", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"pg_sleep"}},
		{sql: "SELECT pg_read_file('/etc/passwd')", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"pg_read_file"}},
		{sql: "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"dblink"}},
		{sql: "SELECT lo_import('/etc/passwd')", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"lo_import"}},
		{sql: "SELECT set_config('basalt.intent', 'x', false)", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"set_config"}},
		{sql: "SELECT nextval('leads_id_seq')", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"nextval"}},
		{sql: "UPDATE leads SET name = pg_catalog.pg_advisory_lock(1)::text", kind: pgstatement.KindWrite, op: pgstatement.OpUpdate, refused: pgstatement.ReasonFunction, tables: []string{"leads"}, funcs: []string{"pg_catalog.pg_advisory_lock"}},
		{sql: "SELECT net.http_post('https://x', '{}')", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"net.http_post"}},
		{sql: "SELECT public.lower('x')", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{}, funcs: []string{"public.lower"}},
		{sql: "SELECT * FROM leads WHERE id = (SELECT max(id) FROM leads WHERE pg_sleep(1) IS NOT NULL)", kind: pgstatement.KindRead, op: pgstatement.OpRead, refused: pgstatement.ReasonFunction, tables: []string{"leads"}, funcs: []string{"max", "pg_sleep"}},
		{sql: "SET basalt.intent = 'x'", kind: pgstatement.KindUtility, op: "VariableSetStmt", refused: pgstatement.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "SET session_replication_role = replica", kind: pgstatement.KindUtility, op: "VariableSetStmt", refused: pgstatement.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "DO $$ BEGIN DELETE FROM leads; END $$", kind: pgstatement.KindUtility, op: "DoStmt", refused: pgstatement.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "EXPLAIN ANALYZE DELETE FROM leads", kind: pgstatement.KindUtility, op: "ExplainStmt", refused: pgstatement.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "MERGE INTO leads l USING src s ON l.id = s.id WHEN MATCHED THEN DELETE", kind: pgstatement.KindWrite, op: pgstatement.OpMerge, refused: pgstatement.ReasonMerge, tables: []string{"leads", "src"}, funcs: []string{}},
		{sql: "BEGIN", kind: pgstatement.KindUtility, op: "TransactionStmt", refused: pgstatement.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "CALL do_things()", kind: pgstatement.KindUtility, op: "CallStmt", refused: pgstatement.ReasonUtility, tables: []string{}, funcs: []string{"do_things"}},
	}
	for _, c := range cases {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			stmt, err := pgstatement.Classify(c.sql)
			require.Equal(t, c.refused, refusalOf(t, err), "err=%v", err)
			if c.refused == pgstatement.ReasonParseError || c.refused == pgstatement.ReasonMultipleStatements {
				return
			}
			require.Equal(t, c.kind, stmt.Kind)
			require.Equal(t, c.op, stmt.Op)
			require.Equal(t, c.tables, stmt.Tables)
			require.Equal(t, c.funcs, stmt.Functions)
			require.Equal(t, c.params, stmt.ParamCount)
		})
	}
}

// Target is the relation a write writes, as written; another table the
// statement names never is.
func TestTarget(t *testing.T) {
	t.Parallel()
	for sql, want := range map[string]string{
		"UPDATE payroll SET amount = 0 FROM audit_log a WHERE a.id = payroll.id":                           "payroll",
		"DELETE FROM public.leads USING archive WHERE archive.id = leads.id":                               "public.leads",
		"INSERT INTO leads (id) SELECT id FROM a_import":                                                   "leads",
		`UPDATE "Old Leads" SET id = 1`:                                                                    "Old Leads",
		"SELECT * FROM leads":                                                                              "",
		"MERGE INTO payroll p USING audit_log a ON p.id = a.id WHEN MATCHED THEN DELETE":                   "payroll",
		"WITH d AS (DELETE FROM payroll RETURNING *) INSERT INTO audit_log SELECT * FROM d":                "payroll",
		"WITH d AS (DELETE FROM payroll RETURNING *) SELECT * FROM d JOIN audit_log USING (id)":            "payroll",
		"WITH r AS (SELECT * FROM audit_log), u AS (UPDATE public.leads SET id = 1 RETURNING id) SELECT 1": "public.leads",
		"WITH r AS (SELECT * FROM audit_log) UPDATE payroll SET id = 1 FROM r":                             "payroll",
		"DROP TABLE leads": "",
	} {
		stmt, _ := pgstatement.Classify(sql)
		require.Equal(t, want, stmt.Target, sql)
	}
}

func TestCheckTool(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sql     string
		tool    pgstatement.Tool
		refused pgstatement.Reason
	}{
		{"SELECT 1", pgstatement.ToolQuery, ""},
		{"VALUES (1), (2)", pgstatement.ToolQuery, ""},
		{"UPDATE leads SET a = 1", pgstatement.ToolQuery, pgstatement.ReasonWrongTool},
		{"DELETE FROM leads", pgstatement.ToolQuery, pgstatement.ReasonWrongTool},
		{"UPDATE leads SET a = 1", pgstatement.ToolWrite, ""},
		{"INSERT INTO leads(a) SELECT a FROM other", pgstatement.ToolWrite, ""},
		{"DELETE FROM leads WHERE id = $1", pgstatement.ToolWrite, ""},
		{"SELECT 1", pgstatement.ToolWrite, pgstatement.ReasonWrongTool},
		{"DROP TABLE leads", pgstatement.ToolWrite, pgstatement.ReasonDDL},
		{"SELECT pg_sleep(1)", pgstatement.ToolQuery, pgstatement.ReasonFunction},
		{"SELECT 1", "OTHER", pgstatement.ReasonWrongTool},
	}
	for _, c := range cases {
		t.Run(string(c.tool)+" "+c.sql, func(t *testing.T) {
			t.Parallel()
			_, err := pgstatement.Check(c.sql, c.tool)
			require.Equal(t, c.refused, refusalOf(t, err), "err=%v", err)
		})
	}
}

// A refusal's detail talks SQL, so a read is named by its SQL word, SELECT,
// not by Basalt's op, READ.
func TestRefusalDetailUsesTheSQLWord(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		sql    string
		tool   pgstatement.Tool
		detail string
	}{
		{"SELECT 1", pgstatement.ToolWrite, "write runs one INSERT, UPDATE or DELETE; use query for SELECT"},
		{"DELETE FROM leads", pgstatement.ToolQuery, "query runs one SELECT; use write for DELETE"},
		{"SELECT * INTO copy_of_leads FROM leads", pgstatement.ToolQuery, "SELECT"},
		{"SELECT * FROM leads FOR UPDATE", pgstatement.ToolQuery, "SELECT"},
	} {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			_, err := pgstatement.Check(c.sql, c.tool)
			var re *pgstatement.RefusalError
			require.ErrorAs(t, err, &re)
			require.Equal(t, c.detail, re.Detail)
		})
	}
}

// The guard's own functions are never callable through the SQL tools: the
// plugin event writer, which every agent role may execute, is refused by
// either tool, qualified or not, wherever it appears in the statement.
func TestGuardFunctionsAreRefused(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		sql  string
		tool pgstatement.Tool
	}{
		{`SELECT basalt_meta.record_plugin_event('PLUGIN_TRUST_ADDED', '{"signerKeyId":"jNZPxNG5htlwfhg4ZgknAA"}')`, pgstatement.ToolQuery},
		{`SELECT record_plugin_event('PLUGIN_TRUST_ADDED', '{}')`, pgstatement.ToolQuery},
		{`SELECT id FROM leads WHERE id = (SELECT basalt_meta.record_plugin_event('PLUGIN_DISABLED', '{}'))`, pgstatement.ToolQuery},
		{`UPDATE leads SET name = basalt_meta.record_plugin_event('PLUGIN_TRUST_REMOVED', '{}')::text WHERE id = 1`, pgstatement.ToolWrite},
		{`INSERT INTO leads (name) VALUES ("basalt_meta"."record_plugin_event"('PLUGIN_ENABLED', '{}')::text)`, pgstatement.ToolWrite},
		{`SELECT * FROM basalt_meta.open_plugin_approval('{}', '{}')`, pgstatement.ToolQuery},
		{`SELECT basalt_meta.submit_plugin_approval(NULL, NULL, NULL, NULL, NULL)`, pgstatement.ToolQuery},
	} {
		_, err := pgstatement.Check(c.sql, c.tool)
		require.Equal(t, pgstatement.ReasonFunction, refusalOf(t, err), "%s: err=%v", c.sql, err)
	}
}

func TestRefusalMessage(t *testing.T) {
	t.Parallel()
	_, err := pgstatement.Check("SELECT pg_sleep(1)", pgstatement.ToolQuery)
	require.EqualError(t, err, "FUNCTION_NOT_ALLOWED: pg_sleep is not on the function allowlist")
	require.Equal(t, "LOCKING_READ", (&pgstatement.RefusalError{Reason: pgstatement.ReasonLockingRead}).Error())
}

func BenchmarkCheckSimpleUpdate(b *testing.B) {
	for b.Loop() {
		_, _ = pgstatement.Check("UPDATE cases SET status = $1 WHERE id = $2", pgstatement.ToolWrite)
	}
}
