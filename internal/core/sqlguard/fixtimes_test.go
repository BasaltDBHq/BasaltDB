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
	require.True(t, sqlguard.FixedFrom(held, sent), "%s\nfrom\n%s", held, sent)
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
		`UPDATE t SET a = '2026-11-27'::pg_catalog.date, b = 2 WHERE id <= 25`,
		`UPDATE t SET a = 5, b = 2 WHERE id <= 25`,
		`UPDATE u SET a = '2026-11-27 10:00:00+00'::timestamp with time zone, b = 2 WHERE id <= 25`,
		`UPDATE t SET a = now(), b = 2 WHERE id <= 25; SELECT 1`,
		`not sql`,
	} {
		require.False(t, sqlguard.FixedFrom(held, sent), held)
	}
	// An INSERT that already had a column list gains no columns.
	require.False(t, sqlguard.FixedFrom(
		`INSERT INTO t (id, name, at) VALUES (1, 'a', '2026-11-27 10:00:00+00'::timestamp with time zone)`,
		`INSERT INTO t (id, name) VALUES (1, 'a')`))
	// An added column keeps the values sent before it.
	held := `INSERT INTO t (id, name, at) VALUES (1, 'a', '2026-11-27 10:00:00+00'::timestamp with time zone)`
	require.True(t, sqlguard.FixedFrom(held, `INSERT INTO t VALUES (1, 'a')`))
	require.False(t, sqlguard.FixedFrom(held, `INSERT INTO t VALUES (2, 'a')`))
	require.False(t, sqlguard.FixedFrom(held, `INSERT INTO t VALUES (1, 'a', 'b')`))
	require.False(t, sqlguard.FixedFrom(held, `INSERT INTO u VALUES (1, 'a')`))
	// A literal the agent sent is not a slot.
	require.False(t, sqlguard.FixedFrom(
		`UPDATE t SET a = '2026-11-27 10:00:00+00'::timestamp with time zone`,
		`UPDATE t SET a = '2026-11-26 10:00:00+00'::timestamp with time zone`))
	// The same text matches itself, spacing aside.
	require.True(t, sqlguard.FixedFrom(`UPDATE t SET a = 1`, "UPDATE  t\nSET a = 1"))
}
