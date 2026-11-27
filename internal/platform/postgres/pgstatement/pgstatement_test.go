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
		op      action.Op
		refused action.RefusalReason
		tables  []string
		params  int
	}{
		{
			sql: "SELECT id, lower(name) FROM public.leads l JOIN deals d ON d.lead_id = l.id WHERE l.created_at > now() - interval '1 day'",
			op:  action.OpRead, tables: []string{"deals", "public.leads"},
		},
		{sql: "SELECT count(id), coalesce(max(score), 0) FROM leads", op: action.OpRead, tables: []string{"leads"}},
		{sql: "WITH recent AS (SELECT * FROM leads) SELECT * FROM recent", op: action.OpRead, tables: []string{"leads"}},
		{sql: "SELECT * FROM leads WHERE id = $1 AND status = $3", op: action.OpRead, tables: []string{"leads"}, params: 3},
		{sql: "SELECT pg_catalog.lower('A')", op: action.OpRead, tables: []string{}},
		{sql: "UPDATE cases SET status = $1 WHERE id = $2", op: action.OpUpdate, tables: []string{"cases"}, params: 2},
		{sql: "INSERT INTO leads(name) VALUES ('a') ON CONFLICT (name) DO UPDATE SET name = excluded.name", op: action.OpInsert, tables: []string{"leads"}},
		{sql: "DELETE FROM leads WHERE id IN (SELECT lead_id FROM spam) RETURNING id", op: action.OpDelete, tables: []string{"leads", "spam"}},
		{sql: "WITH s AS (SELECT id FROM spam) DELETE FROM leads WHERE id IN (SELECT id FROM s)", op: action.OpDelete, tables: []string{"leads", "spam"}},

		{sql: "SELECT 1; DELETE FROM leads", refused: action.ReasonMultipleStatements},
		{sql: "SELEC 1", refused: action.ReasonParseError},
		{sql: "", refused: action.ReasonMultipleStatements},
		{sql: "WITH d AS (DELETE FROM leads RETURNING id) SELECT count(*) FROM d", op: action.OpRead, refused: action.ReasonDataModifyingWith, tables: []string{"leads"}},
		{sql: "WITH d AS (DELETE FROM a RETURNING id) INSERT INTO b SELECT id FROM d", op: action.OpInsert, refused: action.ReasonDataModifyingWith, tables: []string{"a", "b"}},
		{sql: "COPY leads TO '/tmp/x'", op: action.OpOther, refused: action.ReasonUtility, tables: []string{"leads"}},
		{sql: "COPY leads FROM PROGRAM 'curl evil'", op: action.OpOther, refused: action.ReasonUtility, tables: []string{"leads"}},
		{sql: "DROP TABLE leads", op: action.OpOther, refused: action.ReasonDDL, tables: []string{}},
		{sql: "ALTER TABLE leads DISABLE TRIGGER ALL", op: action.OpOther, refused: action.ReasonDDL, tables: []string{"leads"}},
		{sql: "TRUNCATE leads", op: action.OpOther, refused: action.ReasonDDL, tables: []string{"leads"}},
		{sql: "CREATE TABLE x (id int)", op: action.OpOther, refused: action.ReasonDDL, tables: []string{"x"}},
		{sql: "GRANT SELECT ON leads TO public", op: action.OpOther, refused: action.ReasonDDL, tables: []string{"leads"}},
		{sql: "SELECT * INTO copy_of_leads FROM leads", op: action.OpRead, refused: action.ReasonSelectInto, tables: []string{"copy_of_leads", "leads"}},
		{sql: "SELECT * FROM leads FOR UPDATE", op: action.OpRead, refused: action.ReasonLockingRead, tables: []string{"leads"}},
		{sql: "SELECT pg_sleep(100)", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT pg_read_file('/etc/passwd')", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT lo_import('/etc/passwd')", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT set_config('basalt.intent', 'x', false)", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT nextval('leads_id_seq')", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "UPDATE leads SET name = pg_catalog.pg_advisory_lock(1)::text", op: action.OpUpdate, refused: action.ReasonFunction, tables: []string{"leads"}},
		{sql: "SELECT net.http_post('https://x', '{}')", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT public.lower('x')", op: action.OpRead, refused: action.ReasonFunction, tables: []string{}},
		{sql: "SELECT * FROM leads WHERE id = (SELECT max(id) FROM leads WHERE pg_sleep(1) IS NOT NULL)", op: action.OpRead, refused: action.ReasonFunction, tables: []string{"leads"}},
		{sql: "SET basalt.intent = 'x'", op: action.OpOther, refused: action.ReasonUtility, tables: []string{}},
		{sql: "SET session_replication_role = replica", op: action.OpOther, refused: action.ReasonUtility, tables: []string{}},
		{sql: "DO $$ BEGIN DELETE FROM leads; END $$", op: action.OpOther, refused: action.ReasonUtility, tables: []string{}},
		{sql: "EXPLAIN ANALYZE DELETE FROM leads", op: action.OpOther, refused: action.ReasonUtility, tables: []string{"leads"}},
		{sql: "MERGE INTO leads l USING src s ON l.id = s.id WHEN MATCHED THEN DELETE", op: action.OpMerge, refused: action.ReasonMerge, tables: []string{"leads", "src"}},
		{sql: "BEGIN", op: action.OpOther, refused: action.ReasonUtility, tables: []string{}},
		{sql: "CALL do_things()", op: action.OpOther, refused: action.ReasonUtility, tables: []string{}},
	}
	for _, c := range cases {
		t.Run(c.sql, func(t *testing.T) {
			t.Parallel()
			stmt, err := pgstatement.Classify(c.sql)
			require.Equal(t, c.refused, refusalOf(t, err), "err=%v", err)
			if c.refused == action.ReasonParseError || c.refused == action.ReasonMultipleStatements {
				return
			}
			require.Equal(t, c.op, stmt.Op)
			require.Equal(t, c.tables, stmt.Tables)
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

// A DDL or utility statement's op is OTHER, never its parse node name; the
// node name is the refusal's detail.
func TestOtherStatementsNameTheirNodeInTheDetail(t *testing.T) {
	t.Parallel()
	for sql, node := range map[string]string{
		"DROP TABLE leads":        "DropStmt",
		"SET basalt.intent = 'x'": "VariableSetStmt",
		"COPY leads TO '/tmp/x'":  "CopyStmt",
		"BEGIN":                   "TransactionStmt",
		"MERGE INTO leads l USING src s ON l.id = s.id WHEN MATCHED THEN DELETE": "MERGE",
	} {
		stmt, err := pgstatement.Check(sql, action.ToolWrite)
		var re *action.RefusalError
		require.ErrorAs(t, err, &re, sql)
		require.Equal(t, node, re.Detail, sql)
		if node != "MERGE" {
			require.Equal(t, action.OpOther, stmt.Op, sql)
		}
	}
}

// The first function off the allowlist, in name order, is the one a
// refusal names, as written.
func TestFunctionRefusalNamesTheFirstByName(t *testing.T) {
	t.Parallel()
	_, err := pgstatement.Check("SELECT pg_sleep(1), pg_catalog.pg_advisory_lock(1), dblink('x', 'y')", action.ToolQuery)
	require.EqualError(t, err, "FUNCTION_NOT_ALLOWED: dblink is not on the function allowlist")
	_, err = pgstatement.Check("SELECT pg_sleep(1), pg_catalog.pg_advisory_lock(1)", action.ToolQuery)
	require.EqualError(t, err, "FUNCTION_NOT_ALLOWED: pg_catalog.pg_advisory_lock is not on the function allowlist")
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
