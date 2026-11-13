package sqlguard_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

func TestRowSources(t *testing.T) {
	t.Parallel()
	leads := sqlguard.RowSource{Name: "leads"}
	cases := []struct {
		name string
		sql  string
		want []sqlguard.RowSource
	}{
		{"one table", "SELECT * FROM leads WHERE id = $1", []sqlguard.RowSource{leads}},
		{"alias", "SELECT l.name FROM leads l", []sqlguard.RowSource{{Name: "leads", Alias: "l"}}},
		{"qualified", "SELECT name FROM public.leads", []sqlguard.RowSource{{Schema: "public", Name: "leads"}}},
		{"quoted", `SELECT 1 FROM "Leads"`, []sqlguard.RowSource{{Name: "Leads"}}},
		{
			"inner join", "SELECT * FROM leads a JOIN notes n ON n.lead_id = a.id",
			[]sqlguard.RowSource{{Name: "leads", Alias: "a"}, {Name: "notes", Alias: "n"}},
		},
		{
			"outer join and comma", "SELECT * FROM leads LEFT JOIN notes USING (id), owners",
			[]sqlguard.RowSource{leads, {Name: "notes"}, {Name: "owners"}},
		},
		{
			"self join", "SELECT a.id, b.id FROM leads a JOIN leads b ON b.id = a.id",
			[]sqlguard.RowSource{{Name: "leads", Alias: "a"}, {Name: "leads", Alias: "b"}},
		},
		{"window function", "SELECT id, rank() OVER (ORDER BY score) FROM leads", []sqlguard.RowSource{leads}},
		{"count over window", "SELECT id, count(id) OVER () FROM leads", []sqlguard.RowSource{leads}},
		{"aggregate in a subquery", "SELECT id, (SELECT count(id) FROM notes) FROM leads", []sqlguard.RowSource{leads}},
		{"order and limit", "SELECT name FROM leads ORDER BY 1 LIMIT 5 OFFSET 2", []sqlguard.RowSource{leads}},
		{
			"CTE name left out", "WITH x AS (SELECT * FROM leads) SELECT * FROM x JOIN owners o ON true",
			[]sqlguard.RowSource{{Name: "owners", Alias: "o"}},
		},
		{"subquery in FROM left out", "SELECT * FROM (SELECT * FROM leads) s", nil},
		{"function in FROM left out", "SELECT * FROM generate_series(1, 3) g", nil},
		{"aliased join left out", "SELECT * FROM (leads JOIN notes USING (id)) j", nil},
		{"renaming alias left out", "SELECT * FROM leads AS l(a, b)", nil},
		{"aggregate", "SELECT count(id) FROM leads", nil},
		{"aggregate star", "SELECT count(*) FROM leads", nil},
		{"aggregate in ORDER BY", "SELECT 1 FROM leads ORDER BY max(id)", nil},
		{"group by", "SELECT status FROM leads GROUP BY status", nil},
		{"having", "SELECT 1 FROM leads HAVING true", nil},
		{"distinct", "SELECT DISTINCT status FROM leads", nil},
		{"distinct on", "SELECT DISTINCT ON (status) * FROM leads", nil},
		{"union", "SELECT id FROM leads UNION SELECT id FROM notes", nil},
		{"values", "VALUES (1), (2)", nil},
		{"no FROM", "SELECT 1", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			stmt, err := sqlguard.Check(c.sql, sqlguard.ToolQuery)
			require.NoError(t, err)
			require.Equal(t, c.want, stmt.RowSources)
		})
	}
}

func TestRowSourceRegName(t *testing.T) {
	t.Parallel()
	require.Equal(t, `"leads"`, sqlguard.RowSource{Name: "leads"}.RegName())
	require.Equal(t, `"public"."Le""ads"`, sqlguard.RowSource{Schema: "public", Name: `Le"ads`}.RegName())
}

func TestWithRowVersions(t *testing.T) {
	t.Parallel()
	got, err := sqlguard.WithRowVersions("SELECT name FROM leads WHERE id = $1 ORDER BY name LIMIT $2",
		[]sqlguard.Versioned{{Source: sqlguard.RowSource{Name: "leads"}, PKCols: []string{"id"}}})
	require.NoError(t, err)
	require.Equal(t, "SELECT name, jsonb_build_object('id', leads.id) AS __basalt_key_1, leads.xmin AS __basalt_version_1 "+
		"FROM leads WHERE id = $1 ORDER BY name LIMIT $2", got)

	got, err = sqlguard.WithRowVersions(`SELECT * FROM public.leads a LEFT JOIN "Notes" n ON n.lead_id = a.id`,
		[]sqlguard.Versioned{
			{Source: sqlguard.RowSource{Schema: "public", Name: "leads", Alias: "a"}, PKCols: []string{"id"}},
			{Source: sqlguard.RowSource{Name: "Notes", Alias: "n"}, PKCols: []string{"lead_id", "Seq"}},
		})
	require.NoError(t, err)
	require.Equal(t, `SELECT *, jsonb_build_object('id', a.id) AS __basalt_key_1, a.xmin AS __basalt_version_1, `+
		`jsonb_build_object('lead_id', n.lead_id, 'Seq', n."Seq") AS __basalt_key_2, n.xmin AS __basalt_version_2 `+
		`FROM public.leads a LEFT JOIN "Notes" n ON n.lead_id = a.id`, got)

	got, err = sqlguard.WithRowVersions(`SELECT 1 FROM public.leads`,
		[]sqlguard.Versioned{{Source: sqlguard.RowSource{Schema: "public", Name: "leads"}, PKCols: []string{"id"}}})
	require.NoError(t, err)
	require.Equal(t, `SELECT 1, jsonb_build_object('id', public.leads.id) AS __basalt_key_1, public.leads.xmin AS __basalt_version_1 FROM public.leads`, got)

	_, err = sqlguard.WithRowVersions("SELECT count(id) FROM leads",
		[]sqlguard.Versioned{{Source: sqlguard.RowSource{Name: "leads"}, PKCols: []string{"id"}}})
	require.ErrorIs(t, err, sqlguard.ErrNoRowIdentity)
	_, err = sqlguard.WithRowVersions("SELECT * FROM leads",
		[]sqlguard.Versioned{{Source: sqlguard.RowSource{Name: "leads"}}})
	require.ErrorIs(t, err, sqlguard.ErrNoRowIdentity)
}
