package sqlguard_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

func TestCheckRepeatable(t *testing.T) {
	t.Parallel()
	ok := []struct {
		sql      string
		table    string
		assigned []string
	}{
		{`UPDATE public.leads SET status = $1, score = score + 1 WHERE id < $2`, "public.leads", []string{"status", "score"}},
		{`UPDATE leads SET (status, score) = ($1, 2) WHERE lower(name) = 'x'`, "leads", []string{"status", "score"}},
		{`DELETE FROM leads WHERE created_at < $1::timestamptz`, "leads", []string{}},
		{`INSERT INTO leads (id, name) VALUES ($1, $2), ($3, $4)`, "leads", []string{"id", "name"}},
		{`INSERT INTO leads (id, name) VALUES (1, 'a') ON CONFLICT (id) DO UPDATE SET status = excluded.status`, "leads", []string{"id", "name", "status"}},
		{`INSERT INTO leads SELECT * FROM staging`, "leads", nil},
		{`UPDATE leads SET note = 'nowhere' WHERE date_trunc('day', $1::timestamptz) > '2026-01-01'::date`, "leads", []string{"note"}},
		// Text that holds a time word among other words is plain text.
		{`UPDATE leads SET note = 'call back tomorrow' WHERE id < $1`, "leads", []string{"note"}},
		{`UPDATE leads SET note = 'now or never'`, "leads", []string{"note"}},
		{`UPDATE leads SET note = 'nowhere'`, "leads", []string{"note"}},
		{`UPDATE leads SET seen = '2026-11-14T10:00:00Z'`, "leads", []string{"seen"}},
		{`UPDATE leads SET seen = 'epoch'`, "leads", []string{"seen"}},
		{`UPDATE leads SET seen = 'infinity'`, "leads", []string{"seen"}},
		{`UPDATE leads SET n = 7 WHERE note = ''`, "leads", []string{"n"}},
	}
	for _, tc := range ok {
		h, err := sqlguard.CheckRepeatable(tc.sql, nil)
		require.NoError(t, err, tc.sql)
		require.Equal(t, tc.table, h.Table, tc.sql)
		require.Equal(t, tc.assigned, h.Assigned, tc.sql)
	}

	refused := map[string]string{
		`UPDATE leads SET updated_at = now()`:                                      "now()",
		`UPDATE leads SET updated_at = pg_catalog.clock_timestamp()`:               "clock_timestamp()",
		`UPDATE leads SET seen = CURRENT_TIMESTAMP`:                                "CURRENT_TIMESTAMP",
		`DELETE FROM leads WHERE created_at < CURRENT_DATE - 7`:                    "CURRENT_DATE",
		`UPDATE leads SET seen = LOCALTIMESTAMP(0)`:                                "LOCALTIMESTAMP",
		`INSERT INTO leads (id, name) VALUES (gen_random_uuid(), 'a')`:             "gen_random_uuid()",
		`UPDATE leads SET score = (random() * 10)::int`:                            "random()",
		`DELETE FROM leads WHERE age(created_at) > interval '1 day'`:               "age()",
		`UPDATE leads SET seen = 'now'::timestamptz`:                               "'now'",
		`UPDATE leads SET updated_at = 'now' WHERE id <= 15`:                       "'now'",
		`UPDATE leads SET a = 'now()'`:                                             "'now()'",
		`UPDATE leads SET a = '(now)'`:                                             "'(now)'",
		`UPDATE leads SET a = '"now"'`:                                             "now",
		`UPDATE leads SET a = 'today+02'`:                                          "'today+02'",
		`UPDATE leads SET a = 'today T10:00'`:                                      "'today T10:00'",
		`UPDATE leads SET a = 'today 10:00:00Z'`:                                   "'today 10:00:00Z'",
		`UPDATE leads SET a = 'tomorrow 10:00 +0530'`:                              "'tomorrow 10:00 +0530'",
		`UPDATE leads SET a = 'today 12:00 pm'`:                                    "'today 12:00 pm'",
		`UPDATE leads SET a = '{now,tomorrow}'::timestamptz[]`:                     "'{now,tomorrow}'",
		`UPDATE leads SET a = '[today,tomorrow)'::tstzrange`:                       "'[today,tomorrow)'",
		`UPDATE leads SET a = E'n\x6fw'`:                                           "now",
		`UPDATE leads SET a = $$now$$`:                                             "'now'",
		`UPDATE leads SET a = 'tomorrow 09:00 Europe/Berlin'`:                      "'tomorrow 09:00 Europe/Berlin'",
		`UPDATE leads SET a = 'yesterday Monday'`:                                  "'yesterday Monday'",
		`UPDATE leads SET updated_at = 'NOW'`:                                      "'NOW'",
		`UPDATE leads SET due = ' Tomorrow '`:                                      "Tomorrow",
		`UPDATE leads SET due = 'tomorrow 10:00'`:                                  "'tomorrow 10:00'",
		`UPDATE leads SET due = 'yesterday, 23:59:59.5 +02'`:                       "'yesterday",
		`UPDATE leads SET due = 'now UTC'`:                                         "'now UTC'",
		`UPDATE leads SET d = 'today'::date`:                                       "'today'",
		`UPDATE leads SET x = 1 WHERE seen < 'yesterday'`:                          "'yesterday'",
		`INSERT INTO leads (id, seen) VALUES ($1, 'now')`:                          "'now'",
		`UPDATE leads SET x = 1 WHERE id IN (SELECT id FROM t WHERE ts > 'today')`: "'today'",
		`INSERT INTO leads (id, name, status) VALUES ($1, $2, DEFAULT)`:            "DEFAULT",
		`UPDATE leads SET status = DEFAULT`:                                        "DEFAULT",
		`UPDATE leads SET x = 1 WHERE id IN (SELECT id FROM t WHERE ts > now())`:   "now()",
	}
	for sql, what := range refused {
		_, err := sqlguard.CheckRepeatable(sql, nil)
		var re *sqlguard.RefusalError
		require.True(t, errors.As(err, &re), sql)
		require.Equal(t, sqlguard.ReasonNotRepeatable, re.Reason, sql)
		require.Contains(t, re.Detail, what, sql)
		require.Contains(t, re.Detail, "parameter", sql)
	}
}

func TestCheckRepeatableParams(t *testing.T) {
	t.Parallel()
	const sql = `UPDATE leads SET updated_at = $1 WHERE id <= $2`
	for _, p := range []any{"now", "Now", " TODAY ", "tomorrow", "yesterday", "tomorrow 10:00", "now,UTC", "yesterday\t23:59 PST", "now()", "NOW() ", "now ()", "(now)", "\"now\"", "now;", "[now]", "{now}", "today()", "today+02", "today T10:00", "today 10:00:00Z", "tomorrow 10:00 z", "{now,tomorrow}", "[today,tomorrow)", "tomorrow 10:00 +0530", "today 12:00 pm", "yesterday msk", "tomorrow 09:00 Europe/Berlin", "today 09:00 America/Argentina/Buenos_Aires", "now Etc/GMT+2", "tomorrow 10:00 nzt", "now on", "Sun today", "tomorrow 10:00 hkt", "today 10:00 ta" + "ht"} {
		_, err := sqlguard.CheckRepeatable(sql, []any{p, 12})
		var re *sqlguard.RefusalError
		require.True(t, errors.As(err, &re), "%q", p)
		require.Equal(t, sqlguard.ReasonNotRepeatable, re.Reason, "%q", p)
		require.Contains(t, re.Detail, "time word", "%q", p)
		require.Contains(t, re.Detail, "parameter", "%q", p)
		// The second parameter position is checked too.
		_, err = sqlguard.CheckRepeatable(sql, []any{"2026-11-14T10:00:00Z", p})
		require.True(t, errors.As(err, &re), "%q", p)
	}
	for _, p := range []any{"2026-11-14T10:00:00Z", "epoch", "infinity", "call back tomorrow", "nowhere", "Tomorrowland", "now or never", "know now", "see (you) tomorrow", "Japan today", "today and/or tomorrow", "meet in Europe/Berlin tomorrow", "", nil, 12, 1.5, true, json.Number("1")} {
		_, err := sqlguard.CheckRepeatable(sql, []any{p, 12})
		require.NoError(t, err, "%v", p)
	}
	_, err := sqlguard.CheckRepeatable(sql, nil)
	require.NoError(t, err)
}
