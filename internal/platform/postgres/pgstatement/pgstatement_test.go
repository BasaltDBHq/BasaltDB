package pgstatement_test

import (
	"errors"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/core/action"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgstatement"
)

func refusalOf(t *testing.T, err error) action.RefusalReason {
	t.Helper()
	if err == nil {
		return ""
	}
	var r *action.RefusalError
	require.True(t, errors.As(err, &r), "error %v is not a refusal", err)
	return r.Reason
}

func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sql     string
		kind    pgstatement.Kind
		op      action.Op
		refused action.RefusalReason
		tables  []string
		funcs   []string
		params  int
	}{
		{
			sql:  "SELECT id, lower(name) FROM public.leads l JOIN deals d ON d.lead_id = l.id WHERE l.created_at > now() - interval '1 day'",
			kind: pgstatement.KindRead, op: action.OpRead, tables: []string{"deals", "public.leads"}, funcs: []string{"lower", "now"},
		},
		{sql: "SELECT count(id), coalesce(max(score), 0) FROM leads", kind: pgstatement.KindRead, op: action.OpRead, tables: []string{"leads"}, funcs: []string{"count", "max"}},
		{sql: "WITH recent AS (SELECT * FROM leads) SELECT * FROM recent", kind: pgstatement.KindRead, op: action.OpRead, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT * FROM leads WHERE id = $1 AND status = $3", kind: pgstatement.KindRead, op: action.OpRead, tables: []string{"leads"}, funcs: []string{}, params: 3},
		{sql: "SELECT pg_catalog.lower('A')", kind: pgstatement.KindRead, op: action.OpRead, tables: []string{}, funcs: []string{"pg_catalog.lower"}},
		{sql: "UPDATE cases SET status = $1 WHERE id = $2", kind: pgstatement.KindWrite, op: action.OpUpdate, tables: []string{"cases"}, funcs: []string{}, params: 2},
		{sql: "INSERT INTO leads(name) VALUES ('a') ON CONFLICT (name) DO UPDATE SET name = excluded.name", kind: pgstatement.KindWrite, op: action.OpInsert, tables: []string{"leads"}, funcs: []string{}},
		{sql: "DELETE FROM leads WHERE id IN (SELECT lead_id FROM spam) RETURNING id", kind: pgstatement.KindWrite, op: action.OpDelete, tables: []string{"leads", "spam"}, funcs: []string{}},
		{sql: "WITH s AS (SELECT id FROM spam) DELETE FROM leads WHERE id IN (SELECT id FROM s)", kind: pgstatement.KindWrite, op: action.OpDelete, tables: []string{"leads", "spam"}, funcs: []string{}},

		{sql: "SELECT 1; DELETE FROM leads", refused: action.ReasonMultipleStatements},
		{sql: "SELEC 1", refused: action.ReasonParseError},
		{sql: "", refused: action.ReasonMultipleStatements},
		{sql: "WITH d AS (DELETE FROM leads RETURNING id) SELECT count(*) FROM d", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonDataModifyingWith, tables: []string{"leads"}, funcs: []string{"count"}},
		{sql: "WITH d AS (DELETE FROM a RETURNING id) INSERT INTO b SELECT id FROM d", kind: pgstatement.KindWrite, op: action.OpInsert, refused: action.ReasonDataModifyingWith, tables: []string{"a", "b"}, funcs: []string{}},
		{sql: "COPY leads TO '/tmp/x'", kind: pgstatement.KindUtility, op: "CopyStmt", refused: action.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "COPY leads FROM PROGRAM 'curl evil'", kind: pgstatement.KindUtility, op: "CopyStmt", refused: action.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "DROP TABLE leads", kind: pgstatement.KindDDL, op: "DropStmt", refused: action.ReasonDDL, tables: []string{}, funcs: []string{}},
		{sql: "ALTER TABLE leads DISABLE TRIGGER ALL", kind: pgstatement.KindDDL, op: "AlterTableStmt", refused: action.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "TRUNCATE leads", kind: pgstatement.KindDDL, op: "TruncateStmt", refused: action.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "CREATE TABLE x (id int)", kind: pgstatement.KindDDL, op: "CreateStmt", refused: action.ReasonDDL, tables: []string{"x"}, funcs: []string{}},
		{sql: "GRANT SELECT ON leads TO public", kind: pgstatement.KindDDL, op: "GrantStmt", refused: action.ReasonDDL, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT * INTO copy_of_leads FROM leads", kind: pgstatement.KindDDL, op: action.OpRead, refused: action.ReasonSelectInto, tables: []string{"copy_of_leads", "leads"}, funcs: []string{}},
		{sql: "SELECT * FROM leads FOR UPDATE", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonLockingRead, tables: []string{"leads"}, funcs: []string{}},
		{sql: "SELECT pg_sleep(100)", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"pg_sleep"}},
		{sql: "SELECT pg_read_file('/etc/passwd')", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"pg_read_file"}},
		{sql: "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"dblink"}},
		{sql: "SELECT lo_import('/etc/passwd')", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"lo_import"}},
		{sql: "SELECT set_config('basalt.intent', 'x', false)", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"set_config"}},
		{sql: "SELECT nextval('leads_id_seq')", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"nextval"}},
		{sql: "UPDATE leads SET name = pg_catalog.pg_advisory_lock(1)::text", kind: pgstatement.KindWrite, op: action.OpUpdate, refused: action.ReasonFunction, tables: []string{"leads"}, funcs: []string{"pg_catalog.pg_advisory_lock"}},
		{sql: "SELECT net.http_post('https://x', '{}')", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"net.http_post"}},
		{sql: "SELECT public.lower('x')", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{}, funcs: []string{"public.lower"}},
		{sql: "SELECT * FROM leads WHERE id = (SELECT max(id) FROM leads WHERE pg_sleep(1) IS NOT NULL)", kind: pgstatement.KindRead, op: action.OpRead, refused: action.ReasonFunction, tables: []string{"leads"}, funcs: []string{"max", "pg_sleep"}},
		{sql: "SET basalt.intent = 'x'", kind: pgstatement.KindUtility, op: "VariableSetStmt", refused: action.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "SET session_replication_role = replica", kind: pgstatement.KindUtility, op: "VariableSetStmt", refused: action.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "DO $$ BEGIN DELETE FROM leads; END $$", kind: pgstatement.KindUtility, op: "DoStmt", refused: action.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "EXPLAIN ANALYZE DELETE FROM leads", kind: pgstatement.KindUtility, op: "ExplainStmt", refused: action.ReasonUtility, tables: []string{"leads"}, funcs: []string{}},
		{sql: "MERGE INTO leads l USING src s ON l.id = s.id WHEN MATCHED THEN DELETE", kind: pgstatement.KindWrite, op: action.OpMerge, refused: action.ReasonMerge, tables: []string{"leads", "src"}, funcs: []string{}},
		{sql: "BEGIN", kind: pgstatement.KindUtility, op: "TransactionStmt", refused: action.ReasonUtility, tables: []string{}, funcs: []string{}},
		{sql: "CALL do_things()", kind: pgstatement.KindUtility, op: "CallStmt", refused: action.ReasonUtility, tables: []string{}, funcs: []string{"do_things"}},
	}
	for _, c := range cases {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			stmt, err := pgstatement.Classify(c.sql)
			require.Equal(t, c.refused, refusalOf(t, err), "err=%v", err)
			if c.refused == action.ReasonParseError || c.refused == action.ReasonMultipleStatements {
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
		tool    action.Tool
		refused action.RefusalReason
	}{
		{"SELECT 1", action.ToolQuery, ""},
		{"VALUES (1), (2)", action.ToolQuery, ""},
		{"UPDATE leads SET a = 1", action.ToolQuery, action.ReasonWrongTool},
		{"DELETE FROM leads", action.ToolQuery, action.ReasonWrongTool},
		{"UPDATE leads SET a = 1", action.ToolWrite, ""},
		{"INSERT INTO leads(a) SELECT a FROM other", action.ToolWrite, ""},
		{"DELETE FROM leads WHERE id = $1", action.ToolWrite, ""},
		{"SELECT 1", action.ToolWrite, action.ReasonWrongTool},
		{"DROP TABLE leads", action.ToolWrite, action.ReasonDDL},
		{"SELECT pg_sleep(1)", action.ToolQuery, action.ReasonFunction},
		{"SELECT 1", "OTHER", action.ReasonWrongTool},
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
		tool   action.Tool
		detail string
	}{
		{"SELECT 1", action.ToolWrite, "write runs one INSERT, UPDATE or DELETE; use query for SELECT"},
		{"DELETE FROM leads", action.ToolQuery, "query runs one SELECT; use write for DELETE"},
		{"SELECT * INTO copy_of_leads FROM leads", action.ToolQuery, "SELECT"},
		{"SELECT * FROM leads FOR UPDATE", action.ToolQuery, "SELECT"},
	} {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			_, err := pgstatement.Check(c.sql, c.tool)
			var re *action.RefusalError
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
		tool action.Tool
	}{
		{`SELECT basalt_meta.record_plugin_event('PLUGIN_TRUST_ADDED', '{"signerKeyId":"jNZPxNG5htlwfhg4ZgknAA"}')`, action.ToolQuery},
		{`SELECT record_plugin_event('PLUGIN_TRUST_ADDED', '{}')`, action.ToolQuery},
		{`SELECT id FROM leads WHERE id = (SELECT basalt_meta.record_plugin_event('PLUGIN_DISABLED', '{}'))`, action.ToolQuery},
		{`UPDATE leads SET name = basalt_meta.record_plugin_event('PLUGIN_TRUST_REMOVED', '{}')::text WHERE id = 1`, action.ToolWrite},
		{`INSERT INTO leads (name) VALUES ("basalt_meta"."record_plugin_event"('PLUGIN_ENABLED', '{}')::text)`, action.ToolWrite},
		{`SELECT * FROM basalt_meta.open_plugin_approval('{}', '{}')`, action.ToolQuery},
		{`SELECT basalt_meta.submit_plugin_approval(NULL, NULL, NULL, NULL, NULL)`, action.ToolQuery},
	} {
		_, err := pgstatement.Check(c.sql, c.tool)
		require.Equal(t, action.ReasonFunction, refusalOf(t, err), "%s: err=%v", c.sql, err)
	}
}

func TestRefusalMessage(t *testing.T) {
	t.Parallel()
	_, err := pgstatement.Check("SELECT pg_sleep(1)", action.ToolQuery)
	require.EqualError(t, err, "FUNCTION_NOT_ALLOWED: pg_sleep is not on the function allowlist")
	require.Equal(t, "LOCKING_READ", (&action.RefusalError{Reason: action.ReasonLockingRead}).Error())
}

func BenchmarkCheckSimpleUpdate(b *testing.B) {
	for b.Loop() {
		_, _ = pgstatement.Check("UPDATE cases SET status = $1 WHERE id = $2", action.ToolWrite)
	}
}
