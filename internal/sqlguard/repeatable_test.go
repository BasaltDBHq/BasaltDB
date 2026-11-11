package sqlguard_test

import (
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
	}
	for _, tc := range ok {
		h, err := sqlguard.CheckRepeatable(tc.sql)
		require.NoError(t, err, tc.sql)
		require.Equal(t, tc.table, h.Table, tc.sql)
		require.Equal(t, tc.assigned, h.Assigned, tc.sql)
	}

	refused := map[string]string{
		`UPDATE leads SET updated_at = now()`:                                    "now()",
		`UPDATE leads SET updated_at = pg_catalog.clock_timestamp()`:             "clock_timestamp()",
		`UPDATE leads SET seen = CURRENT_TIMESTAMP`:                              "CURRENT_TIMESTAMP",
		`DELETE FROM leads WHERE created_at < CURRENT_DATE - 7`:                  "CURRENT_DATE",
		`UPDATE leads SET seen = LOCALTIMESTAMP(0)`:                              "LOCALTIMESTAMP",
		`INSERT INTO leads (id, name) VALUES (gen_random_uuid(), 'a')`:           "gen_random_uuid()",
		`UPDATE leads SET score = (random() * 10)::int`:                          "random()",
		`DELETE FROM leads WHERE age(created_at) > interval '1 day'`:             "age()",
		`UPDATE leads SET seen = 'now'::timestamptz`:                             "'now'",
		`INSERT INTO leads (id, name, status) VALUES ($1, $2, DEFAULT)`:          "DEFAULT",
		`UPDATE leads SET status = DEFAULT`:                                      "DEFAULT",
		`UPDATE leads SET x = 1 WHERE id IN (SELECT id FROM t WHERE ts > now())`: "now()",
	}
	for sql, what := range refused {
		_, err := sqlguard.CheckRepeatable(sql)
		var re *sqlguard.RefusalError
		require.True(t, errors.As(err, &re), sql)
		require.Equal(t, sqlguard.ReasonNotRepeatable, re.Reason, sql)
		require.Contains(t, re.Detail, what, sql)
		require.Contains(t, re.Detail, "parameter", sql)
	}
}
