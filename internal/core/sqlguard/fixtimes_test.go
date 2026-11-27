package sqlguard_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// fixed plans sent with columns, applies values and checks the result is
// still a write the policy and the repeatable check accept, and that
// FixedFrom recognizes it as made from sent.
func fixed(t *testing.T, sent string, columns []sqlguard.Column, values ...string) (eval, held string) {
	t.Helper()
	fix, err := sqlguard.PlanTimes(sent, columns)
	require.NoError(t, err, sent)
	held, err = fix.Apply(values)
	require.NoError(t, err, sent)
	_, err = sqlguard.Check(held, sqlguard.ToolWrite)
	require.NoError(t, err, held)
	_, err = sqlguard.CheckRepeatable(held, nil)
	require.NoError(t, err, held)
	require.True(t, sqlguard.FixedFrom(held, sent, columns), "%s\nfrom\n%s", held, sent)
	return fix.Eval, held
}

func TestPlanTimesStatement(t *testing.T) {
	t.Parallel()
	const ts = "2026-11-27 10:00:00.123456+07"
	cases := []struct {
		sent, eval, held string
		values           []string
	}{
		{
			`UPDATE basalt_demo.leads SET updated_at = now() WHERE id <= 25`,
			`SELECT now()::pg_catalog.text`,
			`UPDATE basalt_demo.leads SET updated_at = '` + ts + `'::timestamp with time zone WHERE id <= 25`,
			[]string{ts},
		},
		{
			`UPDATE t SET a = CURRENT_TIMESTAMP, b = LOCALTIMESTAMP(0), c = CURRENT_DATE, d = CURRENT_TIME WHERE e < pg_catalog.statement_timestamp()`,
			`SELECT current_timestamp::pg_catalog.text, localtimestamp(0)::pg_catalog.text, current_date::pg_catalog.text, current_time::pg_catalog.text, pg_catalog.statement_timestamp()::pg_catalog.text`,
			`UPDATE t SET a = '` + ts + `'::timestamp with time zone, b = '2026-11-27 10:00:00'::timestamp, c = '2026-11-27'::pg_catalog.date, d = '10:00:00.123456+07'::time with time zone WHERE e < '` + ts + `'::timestamp with time zone`,
			[]string{ts, "2026-11-27 10:00:00", "2026-11-27", "10:00:00.123456+07", ts},
		},
		{
			`DELETE FROM t WHERE created_at < transaction_timestamp() - interval '7 days'`,
			`SELECT transaction_timestamp()::pg_catalog.text`,
			`DELETE FROM t WHERE created_at < ('` + ts + `'::timestamp with time zone - '7 days'::interval)`,
			[]string{ts},
		},
		{
			`UPDATE t SET x = 1 WHERE id IN (SELECT id FROM u WHERE ts > clock_timestamp())`,
			`SELECT clock_timestamp()::pg_catalog.text`,
			`UPDATE t SET x = 1 WHERE id IN (SELECT id FROM u WHERE ts > '` + ts + `'::timestamp with time zone)`,
			[]string{ts},
		},
	}
	for _, tc := range cases {
		eval, held := fixed(t, tc.sent, nil, tc.values...)
		require.Equal(t, tc.eval, eval, tc.sent)
		require.Equal(t, tc.held, held, tc.sent)
	}
}

func TestPlanTimesNothingToFix(t *testing.T) {
	t.Parallel()
	for _, sent := range []string{
		`UPDATE t SET a = $1 WHERE id = $2`,
		`INSERT INTO t (id, name) VALUES (1, 'a')`,
		`UPDATE t SET seen = '2026-11-27 10:00:00+00'::timestamp with time zone`,
	} {
		fix, err := sqlguard.PlanTimes(sent, nil)
		require.NoError(t, err, sent)
		require.Empty(t, fix.Eval, sent)
	}
}

// leads is a table whose updated_at defaults to now(), as in the demo.
var leads = []sqlguard.Column{
	{Name: "id", Default: "nextval('leads_id_seq'::regclass)"},
	{Name: "name"},
	{Name: "status", Default: "'new'::text"},
	{Name: "score_x2", Generated: true},
	{Name: "updated_at", Default: "now()"},
	{Name: "due", Default: "(CURRENT_DATE + 7)"},
}

func TestPlanTimesInsertDefaults(t *testing.T) {
	t.Parallel()
	const ts, day = "2026-11-27 10:00:00+00", "2026-11-27"
	cases := []struct{ sent, eval, held string }{
		{
			`INSERT INTO basalt_demo.leads VALUES (1, 'a')`,
			`SELECT now()::pg_catalog.text, current_date::pg_catalog.text`,
			`INSERT INTO basalt_demo.leads (id, name, updated_at, due) VALUES (1, 'a', '` + ts + `'::timestamp with time zone, '` + day + `'::pg_catalog.date + 7)`,
		},
		{
			`INSERT INTO leads VALUES (1, 'a', 'x'), (2, 'b', 'y') RETURNING id`,
			`SELECT now()::pg_catalog.text, current_date::pg_catalog.text`,
			`INSERT INTO leads (id, name, status, updated_at, due) VALUES (1, 'a', 'x', '` + ts + `'::timestamp with time zone, '` + day + `'::pg_catalog.date + 7), ` +
				`(2, 'b', 'y', '` + ts + `'::timestamp with time zone, '` + day + `'::pg_catalog.date + 7) RETURNING id`,
		},
		{
			`INSERT INTO leads SELECT id, name FROM staging`,
			`SELECT now()::pg_catalog.text, current_date::pg_catalog.text`,
			`INSERT INTO leads (id, name, updated_at, due) SELECT id, name, '` + ts + `'::timestamp with time zone, '` + day + `'::pg_catalog.date + 7 FROM staging`,
		},
	}
	for _, tc := range cases {
		eval, held := fixed(t, tc.sent, leads, ts, day)
		require.Equal(t, tc.eval, eval, tc.sent)
		require.Equal(t, tc.held, held, tc.sent)
	}

	// The usual UTC defaults go in as they are, their now() fixed.
	for def, want := range map[string]string{
		"timezone('utc'::text, now())":     `timezone('utc'::text, '` + ts + `'::timestamp with time zone)`,
		"(now() AT TIME ZONE 'utc'::text)": `'` + ts + `'::timestamp with time zone AT TIME ZONE 'utc'::text`,
	} {
		cols := []sqlguard.Column{{Name: "id"}, {Name: "created_at", Default: def}}
		_, held := fixed(t, `INSERT INTO t VALUES (1)`, cols, ts)
		require.Equal(t, `INSERT INTO t (id, created_at) VALUES (1, `+want+`)`, held, def)
	}

	// A default the policy refuses is not written into the statement.
	_, err := sqlguard.PlanTimes(`INSERT INTO t VALUES (1)`,
		[]sqlguard.Column{{Name: "id"}, {Name: "at", Default: "app.stamp(now())"}})
	var re *sqlguard.RefusalError
	require.ErrorAs(t, err, &re)
	require.Contains(t, re.Detail, `"at"`)
	require.Contains(t, re.Detail, "list the columns")

	// A statement time and a default time are separate slots, in order.
	eval, held := fixed(t, `INSERT INTO leads VALUES (1, now())`, leads[:2:2], ts)
	require.Equal(t, `SELECT now()::pg_catalog.text`, eval)
	require.Equal(t, `INSERT INTO leads VALUES (1, '`+ts+`'::timestamp with time zone)`, held)

	// Every column given, a column list, or a width the tree cannot tell:
	// nothing is added.
	for _, sent := range []string{
		`INSERT INTO leads VALUES (1, 'a', 'x', DEFAULT, '2026-01-01', '2026-01-08')`,
		`INSERT INTO leads (id, name) VALUES (1, 'a')`,
		`INSERT INTO leads SELECT * FROM staging`,
		`INSERT INTO leads SELECT 1, 'a' UNION ALL SELECT 2, 'b'`,
	} {
		fix, err := sqlguard.PlanTimes(sent, leads)
		require.NoError(t, err, sent)
		require.Empty(t, fix.Eval, sent)
	}
}

func TestPlanTimesInsertDefaultValues(t *testing.T) {
	t.Parallel()
	cols := []sqlguard.Column{{Name: "note", Default: "'x'::text"}, {Name: "at", Default: "now()"}}
	eval, held := fixed(t, `INSERT INTO log DEFAULT VALUES`, cols, "2026-11-27 10:00:00+00")
	require.Equal(t, `SELECT now()::pg_catalog.text`, eval)
	require.Equal(t, `INSERT INTO log (at) VALUES ('2026-11-27 10:00:00+00'::timestamp with time zone)`, held)
}

func TestPlanTimesRefusesVolatileDefaults(t *testing.T) {
	t.Parallel()
	cases := map[string][]sqlguard.Column{
		`"id"`:     {{Name: "name"}, {Name: "id", Default: "nextval('t_id_seq'::regclass)"}},
		`"token"`:  {{Name: "name"}, {Name: "token", Default: "gen_random_uuid()"}},
		`"lucky"`:  {{Name: "name"}, {Name: "lucky", Default: "(random() * 10)"}},
		`"serial"`: {{Name: "name"}, {Name: "serial", Identity: true}},
	}
	for column, cols := range cases {
		_, err := sqlguard.PlanTimes(`INSERT INTO t VALUES ('a')`, cols)
		var re *sqlguard.RefusalError
		require.True(t, errors.As(err, &re), column)
		require.Equal(t, sqlguard.ReasonNotRepeatable, re.Reason, column)
		require.Contains(t, re.Detail, column)
		require.Contains(t, re.Detail, "list the columns", column)
	}
	// Given by position, the same columns are bound as given.
	fix, err := sqlguard.PlanTimes(`INSERT INTO t VALUES ('a', 1)`, cases[`"id"`])
	require.NoError(t, err)
	require.Empty(t, fix.Eval)
}

func TestFixedFromRefusesAnotherWrite(t *testing.T) {
	t.Parallel()
	const sent = `UPDATE t SET a = now(), b = 2 WHERE id <= 25`
	for _, held := range []string{
		`UPDATE t SET a = '2026-11-27 10:00:00+00'::timestamp with time zone, b = 3 WHERE id <= 25`,
		`UPDATE t SET a = '2026-11-27 10:00:00+00'::timestamp with time zone, b = 2 WHERE id <= 26`,
		`UPDATE t SET a = '2026-11-27'::date, b = 2 WHERE id <= 25`,
		`UPDATE t SET a = '2026-11-27 10:00:00+00'::text, b = 2 WHERE id <= 25`,
		`UPDATE t SET a = 5, b = 2 WHERE id <= 25`,
		`UPDATE t SET a = NULL::timestamp with time zone, b = 2 WHERE id <= 25`,
		`UPDATE u SET a = '2026-11-27 10:00:00+00'::timestamp with time zone, b = 2 WHERE id <= 25`,
		`UPDATE t SET a = now(), b = 2 WHERE id <= 25; SELECT 1`,
		`not sql`,
	} {
		require.False(t, sqlguard.FixedFrom(held, sent, nil), held)
	}
	require.True(t, sqlguard.FixedFrom(`UPDATE t SET a = '2026-11-27 10:00:00+00'::timestamp with time zone, b = 2 WHERE id <= 25`, sent, nil))

	// No literal of the agent's is a wildcard.
	require.False(t, sqlguard.FixedFrom(`UPDATE t SET name = 'Bob'`, `UPDATE t SET name = 'basalt fixed value'`, nil))
	require.False(t, sqlguard.FixedFrom(
		`UPDATE t SET a = '2026-11-27 10:00:00+00'::timestamp with time zone`,
		`UPDATE t SET a = '2026-11-26 10:00:00+00'::timestamp with time zone`, nil))

	// Only the columns the hold adds from the table's defaults, in its
	// order and with its values, are taken for the agent's.
	cols := []sqlguard.Column{{Name: "id"}, {Name: "name"}, {Name: "at", Default: "now()"}}
	held := `INSERT INTO t (id, name, at) VALUES (1, 'a', '2026-11-27 10:00:00+00'::timestamp with time zone)`
	require.True(t, sqlguard.FixedFrom(held, `INSERT INTO t VALUES (1, 'a')`, cols))
	require.False(t, sqlguard.FixedFrom(held, `INSERT INTO t VALUES (1, 'a')`, nil), "without the catalog nothing is added")
	require.False(t, sqlguard.FixedFrom(held, `INSERT INTO t VALUES (2, 'a')`, cols))
	require.False(t, sqlguard.FixedFrom(held, `INSERT INTO u VALUES (1, 'a')`, cols))
	require.False(t, sqlguard.FixedFrom(
		`INSERT INTO t (id, name, at) VALUES (1, 'a', '2026-11-27'::date)`, `INSERT INTO t VALUES (1, 'a')`, cols))
	require.False(t, sqlguard.FixedFrom(
		`INSERT INTO t (name, id, at) VALUES ('a', 1, '2026-11-27 10:00:00+00'::timestamp with time zone)`, `INSERT INTO t VALUES (1, 'a')`, cols))
	// An approved INSERT with its own column list is not an INSERT without one.
	require.False(t, sqlguard.FixedFrom(`INSERT INTO t (name, id) VALUES ('a', 1)`, `INSERT INTO t VALUES ('a')`,
		[]sqlguard.Column{{Name: "id"}, {Name: "name"}}))
	require.False(t, sqlguard.FixedFrom(
		`INSERT INTO t (id, name, at) VALUES (1, 'a', '2026-11-27 10:00:00+00'::timestamp with time zone)`,
		`INSERT INTO t (id, name) VALUES (1, 'a')`, cols))

	// Spacing, comments and the case of unquoted names do not count.
	require.True(t, sqlguard.FixedFrom(`UPDATE t SET a = 1`, "update  T\nSET a = 1 -- note", nil))
}

func TestNowWithOverIsRefused(t *testing.T) {
	t.Parallel()
	for sql, what := range map[string]string{
		`UPDATE t SET a = now() OVER ()`:             "now()",
		`UPDATE t SET a = clock_timestamp() OVER ()`: "clock_timestamp()",
	} {
		_, err := sqlguard.CheckRepeatable(sql, nil)
		var re *sqlguard.RefusalError
		require.ErrorAs(t, err, &re, sql)
		require.Equal(t, sqlguard.ReasonNotRepeatable, re.Reason, sql)
		require.Contains(t, re.Detail, what, sql)
	}
}

func TestPlanTimesRefusesAVolatileFunctionInADefault(t *testing.T) {
	t.Parallel()
	cols := []sqlguard.Column{{Name: "name"}, {Name: "token", Default: "extensions.uuid_generate_v4()", Volatile: "extensions.uuid_generate_v4()"}}
	_, err := sqlguard.PlanTimes(`INSERT INTO t VALUES ('a')`, cols)
	var re *sqlguard.RefusalError
	require.ErrorAs(t, err, &re)
	require.Equal(t, sqlguard.ReasonNotRepeatable, re.Reason)
	require.Contains(t, re.Detail, `"token"`)
	require.Contains(t, re.Detail, "extensions.uuid_generate_v4()")
}
