package pgcatalog_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

const describeSchema = "pgcatalog_describe"

// describeFixture builds the fixture schema and returns a connection whose
// session_user is a role with selective grants. SET SESSION AUTHORIZATION
// (the test URL is a superuser) changes session_user, which SET ROLE does
// not, and the catalog functions under test answer from session_user.
func describeFixture(t *testing.T) *pgx.Conn {
	t.Helper()
	url := os.Getenv("BASALTDB_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("BASALTDB_TEST_POSTGRES_URL not set")
	}
	ctx := context.Background()
	role := fmt.Sprintf("pgcatalog_describe_agent_%d", time.Now().UnixNano())

	admin, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	agent, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	t.Cleanup(func() {
		bg := context.Background()
		_ = agent.Close(bg)
		_, _ = admin.Exec(bg, `DROP SCHEMA IF EXISTS `+describeSchema+` CASCADE`)
		_, _ = admin.Exec(bg, `DROP OWNED BY `+role)
		_, _ = admin.Exec(bg, `DROP ROLE IF EXISTS `+role)
		_ = admin.Close(bg)
	})

	s := describeSchema
	_, err = admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+s+` CASCADE;
		CREATE ROLE `+role+`;
		CREATE SCHEMA `+s+`;
		CREATE TABLE `+s+`.a (id int PRIMARY KEY, zqxlabel text);
		COMMENT ON TABLE `+s+`.a IS '  Accounts, zqxpadded  ';
		COMMENT ON COLUMN `+s+`.a.id IS 'account id';
		CREATE TABLE `+s+`.b (id int PRIMARY KEY, zqxlabel text, zqxsecret text,
			doubled int GENERATED ALWAYS AS (id * 2) STORED);
		CREATE INDEX b_secret_idx ON `+s+`.b (zqxsecret);
		CREATE INDEX b_partial_idx ON `+s+`.b (zqxlabel) WHERE zqxsecret IS NOT NULL;
		CREATE TABLE `+s+`.hidden (id int PRIMARY KEY, a_id int REFERENCES `+s+`.a (id) ON DELETE CASCADE);
		CREATE TABLE `+s+`.child (id int PRIMARY KEY, a_id int REFERENCES `+s+`.a (id) ON DELETE CASCADE);
		CREATE TABLE `+s+`.leaf (id int PRIMARY KEY, b_id int REFERENCES `+s+`.b (id));
		CREATE TABLE `+s+`.p (id int, v text) PARTITION BY RANGE (id);
		CREATE TABLE `+s+`.p1 PARTITION OF `+s+`.p FOR VALUES FROM (0) TO (10);
		CREATE TABLE `+s+`.p2 PARTITION OF `+s+`.p FOR VALUES FROM (10) TO (20);
		CREATE TABLE `+s+`.p3 PARTITION OF `+s+`.p FOR VALUES FROM (20) TO (30);
		CREATE TABLE `+s+`.fresh (x int);
		CREATE TABLE `+s+`.zqx_orders (id int PRIMARY KEY);
		CREATE TABLE `+s+`.pfk (id int, a_id int REFERENCES `+s+`.a (id) ON DELETE CASCADE) PARTITION BY RANGE (id);
		CREATE TABLE `+s+`.pfk1 PARTITION OF `+s+`.pfk FOR VALUES FROM (0) TO (10);
		CREATE TABLE `+s+`.pfk2 PARTITION OF `+s+`.pfk FOR VALUES FROM (10) TO (20);
		CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA `+s+`;
		CREATE VIEW `+s+`.v AS SELECT id, zqxlabel FROM `+s+`.a;
		GRANT USAGE ON SCHEMA `+s+` TO `+role+`;
		GRANT SELECT, INSERT, UPDATE, DELETE ON `+s+`.a TO `+role+`;
		GRANT SELECT (id, zqxlabel) ON `+s+`.b TO `+role+`;
		GRANT SELECT ON `+s+`.child, `+s+`.leaf, `+s+`.p, `+s+`.pfk, `+s+`.zqx_orders, `+s+`.fresh, `+s+`.v TO `+role+`;
		INSERT INTO `+s+`.a VALUES (1, 'x');
		ANALYZE `+s+`.a;`)
	require.NoError(t, err)

	_, err = agent.Exec(ctx, `SET SESSION AUTHORIZATION `+role)
	require.NoError(t, err)
	return agent
}

func relByName(t *testing.T, rels []pgcatalog.Relation, name string) pgcatalog.Relation {
	t.Helper()
	for _, r := range rels {
		if r.Schema == describeSchema && r.Name == name {
			return r
		}
	}
	require.FailNow(t, "relation not listed", name)
	return pgcatalog.Relation{}
}

func fixtureNames(rels []pgcatalog.Relation) []string {
	var names []string
	for _, r := range rels {
		if r.Schema == describeSchema {
			names = append(names, r.Name)
		}
	}
	return names
}

func TestRelationsHidesUngranted(t *testing.T) {
	db := describeFixture(t)
	rels, notGranted, err := pgcatalog.Relations(context.Background(), db)
	require.NoError(t, err)

	names := fixtureNames(rels)
	require.NotContains(t, names, "hidden")
	require.NotContains(t, names, "p1")
	require.NotContains(t, names, "p2")
	require.NotContains(t, names, "p3")
	require.NotContains(t, names, "pfk1")
	require.ElementsMatch(t, []string{"a", "b", "child", "leaf", "p", "pfk", "zqx_orders", "fresh", "v"}, names)
	require.Equal(t, "PARTITIONED_TABLE", relByName(t, rels, "p").Kind)
	require.Equal(t, "VIEW", relByName(t, rels, "v").Kind)
	require.Equal(t, "TABLE", relByName(t, rels, "a").Kind)
	require.GreaterOrEqual(t, notGranted, 1)
	require.Equal(t, "  Accounts, zqxpadded  ", relByName(t, rels, "a").Comment)
}

// TestRelationsReportPrivileges: the overview lists each table's access, so
// Relations and FindRelation report SELECT by the visibility rule (a
// column grant counts) and the table-level writes.
func TestRelationsReportPrivileges(t *testing.T) {
	db := describeFixture(t)
	ctx := context.Background()
	rels, _, err := pgcatalog.Relations(ctx, db)
	require.NoError(t, err)
	require.Equal(t, []string{"DELETE", "INSERT", "SELECT", "UPDATE"}, sorted(relByName(t, rels, "a").Privileges))
	require.Equal(t, []string{"SELECT"}, relByName(t, rels, "b").Privileges, "a column grant is SELECT")
	require.Equal(t, []string{"SELECT"}, relByName(t, rels, "v").Privileges)

	r, ok, err := pgcatalog.FindRelation(ctx, db, describeSchema, "a")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []string{"DELETE", "INSERT", "SELECT", "UPDATE"}, sorted(r.Privileges))
}

func TestRelationsEstimatedRowsNilWhenNeverAnalyzed(t *testing.T) {
	db := describeFixture(t)
	rels, _, err := pgcatalog.Relations(context.Background(), db)
	require.NoError(t, err)
	require.Nil(t, relByName(t, rels, "fresh").EstimatedRows)
	require.NotNil(t, relByName(t, rels, "a").EstimatedRows)
	require.Equal(t, int64(1), *relByName(t, rels, "a").EstimatedRows)
}

func TestFindRelation(t *testing.T) {
	db := describeFixture(t)
	ctx := context.Background()
	r, ok, err := pgcatalog.FindRelation(ctx, db, describeSchema, "a")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "a", r.Name)

	_, ok, err = pgcatalog.FindRelation(ctx, db, describeSchema, "hidden")
	require.NoError(t, err)
	require.False(t, ok)
	_, ok, err = pgcatalog.FindRelation(ctx, db, describeSchema, "nope")
	require.NoError(t, err)
	require.False(t, ok)
	_, ok, err = pgcatalog.FindRelation(ctx, db, describeSchema, "p1")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestDescribeRelationColumnsAndKeys(t *testing.T) {
	db := describeFixture(t)
	ctx := context.Background()
	rels, _, err := pgcatalog.Relations(ctx, db)
	require.NoError(t, err)

	b, err := pgcatalog.DescribeRelation(ctx, db, relByName(t, rels, "b").OID)
	require.NoError(t, err)
	cols := map[string]pgcatalog.Column{}
	for _, c := range b.Columns {
		cols[c.Name] = c
	}
	require.True(t, cols["id"].Selectable)
	require.False(t, cols["id"].Nullable)
	require.Equal(t, "integer", cols["id"].Type)
	require.False(t, cols["zqxsecret"].Selectable)
	require.Equal(t, int16(3), cols["zqxsecret"].Attnum)
	require.True(t, cols["doubled"].Generated)
	require.Equal(t, []int16{1}, cols["doubled"].DefaultAttnums)
	require.Equal(t, []int16{1}, b.PrimaryKey)

	idx := map[string]pgcatalog.Index{}
	for _, i := range b.Indexes {
		idx[i.Name] = i
	}
	require.Contains(t, idx["b_secret_idx"].Attnums, int16(3))
	require.Contains(t, idx["b_partial_idx"].Attnums, int16(3))
	require.Contains(t, idx["b_partial_idx"].Attnums, int16(2))
	require.True(t, idx["b_partial_idx"].Partial)
	require.False(t, idx["b_partial_idx"].Unique)
	require.True(t, idx["b_pkey"].Unique)
	require.False(t, b.RLS)

	a, err := pgcatalog.DescribeRelation(ctx, db, relByName(t, rels, "a").OID)
	require.NoError(t, err)
	require.Equal(t, 1, a.CascadesIntoHidden)
	require.Equal(t, "  Accounts, zqxpadded  ", a.Comment)
	require.Equal(t, []string{"DELETE", "INSERT", "SELECT", "UPDATE"}, sorted(a.Privileges))
	require.Equal(t, "account id", a.Columns[0].Comment)

	var hiddenKeys, childKeys int
	for _, k := range a.Keys {
		require.False(t, k.Outgoing)
		require.Equal(t, "CASCADE", k.OnDelete)
		if !k.OtherReadable {
			hiddenKeys++
			// A table the role cannot read never leaks its name.
			require.Empty(t, k.OtherSchema)
			require.Empty(t, k.OtherTable)
			require.Empty(t, k.OtherColumns)
			continue
		}
		childKeys++
		require.Contains(t, []string{"child", "pfk"}, k.OtherTable)
		require.Equal(t, []string{"a_id"}, k.OtherColumns)
		require.Equal(t, []int16{1}, k.Attnums)
	}
	require.Equal(t, 1, hiddenKeys)
	require.Equal(t, 2, childKeys)

	leaf, err := pgcatalog.DescribeRelation(ctx, db, relByName(t, rels, "leaf").OID)
	require.NoError(t, err)
	require.Len(t, leaf.Keys, 1)
	require.True(t, leaf.Keys[0].Outgoing)
	require.Equal(t, "b", leaf.Keys[0].OtherTable)
	require.Equal(t, "NO ACTION", leaf.Keys[0].OnDelete)
	require.Equal(t, "NO ACTION", leaf.Keys[0].OnUpdate)
	require.Equal(t, 0, leaf.CascadesIntoHidden)
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func searchFixture(t *testing.T, db pgcatalog.Querier, q string, exclude []pgcatalog.ColumnKey, limit int) []pgcatalog.Match {
	t.Helper()
	got, err := pgcatalog.Search(context.Background(), db, q, exclude, nil, limit)
	require.NoError(t, err)
	var mine []pgcatalog.Match
	for _, m := range got {
		if m.Schema == describeSchema {
			mine = append(mine, m)
		}
	}
	return mine
}

func TestSearchRanksAndPages(t *testing.T) {
	db := describeFixture(t)

	exact := searchFixture(t, db, "a", nil, 100000)
	require.NotEmpty(t, exact)
	require.Equal(t, "a", exact[0].Name)
	require.Equal(t, 0, exact[0].Rank)
	require.Equal(t, "table", exact[0].Matched)
	require.Equal(t, []string{"DELETE", "INSERT", "SELECT", "UPDATE"}, sorted(exact[0].Privileges))
	for _, m := range exact {
		require.NotEqual(t, "hidden", m.Name)
	}

	prefix := searchFixture(t, db, "zqx_ord", nil, 100)
	require.Len(t, prefix, 1)
	require.Equal(t, 1, prefix[0].Rank)
	contains := searchFixture(t, db, "x_ord", nil, 100)
	require.Len(t, contains, 1)
	require.Equal(t, 2, contains[0].Rank)

	secret := searchFixture(t, db, "zqxsecret", nil, 100)
	require.Empty(t, secret, "an unselectable column must not match")

	byComment := searchFixture(t, db, "zqxpadded", nil, 100)
	require.Len(t, byComment, 1)
	require.Equal(t, 5, byComment[0].Rank)
	require.Equal(t, "comment", byComment[0].Matched)

	byColumn := searchFixture(t, db, "zqxlabel", nil, 100)
	require.NotEmpty(t, byColumn)
	require.Equal(t, 4, byColumn[0].Rank)
	require.Equal(t, "column zqxlabel", byColumn[0].Matched)

	bySchema := searchFixture(t, db, "catalog_describe", nil, 100000)
	require.NotEmpty(t, bySchema)
	for _, m := range bySchema {
		require.Equal(t, 3, m.Rank)
		require.Equal(t, "schema", m.Matched)
	}

	all := searchFixture(t, db, "zqx", nil, 100000)
	require.GreaterOrEqual(t, len(all), 3)
	var paged []pgcatalog.Match
	var cursor *pgcatalog.SearchCursor
	for range len(all) + 5 {
		page, err := pgcatalog.Search(context.Background(), db, "zqx", nil, cursor, 1)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		require.Len(t, page, 1)
		if page[0].Schema == describeSchema {
			paged = append(paged, page[0])
		}
		cursor = &pgcatalog.SearchCursor{Rank: page[0].Rank, Schema: page[0].Schema, Name: page[0].Name}
	}
	require.Equal(t, all, paged)
}

func TestSearchExcludesColumns(t *testing.T) {
	db := describeFixture(t)
	ctx := context.Background()
	rels, _, err := pgcatalog.Relations(ctx, db)
	require.NoError(t, err)
	a := relByName(t, rels, "a")
	d, err := pgcatalog.DescribeRelation(ctx, db, a.OID)
	require.NoError(t, err)
	var attnum int16
	for _, c := range d.Columns {
		if c.Name == "zqxlabel" {
			attnum = c.Attnum
		}
	}
	require.NotZero(t, attnum)

	// Excluding a's only matching column leaves it unmatched, and no other
	// match names that column on a.
	got := searchFixture(t, db, "zqxlabel", []pgcatalog.ColumnKey{{OID: a.OID, Attnum: attnum}}, 100)
	for _, m := range got {
		require.NotEqual(t, "a", m.Name, "a's only matching column is excluded")
	}
	// The same column name on another table still matches.
	require.NotEmpty(t, got)
}

func TestSearchTreatsWildcardsAsText(t *testing.T) {
	db := describeFixture(t)
	got, err := pgcatalog.Search(context.Background(), db, "%", nil, nil, 100)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestListAccess(t *testing.T) {
	url := os.Getenv("BASALTDB_TEST_POSTGRES_URL")
	db := describeFixture(t)
	ctx := context.Background()
	admin, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	_, err = admin.Exec(ctx, `CREATE TABLE `+describeSchema+`."Odd Name" (id int)`)
	require.NoError(t, err)

	acc, err := pgcatalog.ListAccess(ctx, db)
	require.NoError(t, err)

	mine := func(in []string) []string {
		var out []string
		for _, s := range in {
			if len(s) > len(describeSchema) && s[:len(describeSchema)+1] == describeSchema+"." {
				out = append(out, s)
			}
		}
		return out
	}
	require.Contains(t, acc.Read, describeSchema+".b")
	require.Contains(t, acc.Read, describeSchema+".a")
	require.Equal(t, []string{describeSchema + ".a"}, mine(acc.Write))
	// Names print as Postgres prints them, as describe names them.
	require.Equal(t, []string{describeSchema + `."Odd Name"`, describeSchema + ".hidden"}, mine(acc.NotGranted))
	require.NotContains(t, acc.Read, describeSchema+".p1")
}

func TestStructureLinesChangeOnAddColumn(t *testing.T) {
	url := os.Getenv("BASALTDB_TEST_POSTGRES_URL")
	db := describeFixture(t)
	ctx := context.Background()
	before, err := pgcatalog.StructureLines(ctx, db)
	require.NoError(t, err)
	require.True(t, slices.IsSorted(before))
	require.True(t, slices.ContainsFunc(before, func(l string) bool { return strings.HasPrefix(l, describeSchema+".a:TABLE:") }))
	for _, l := range before {
		require.NotContains(t, l, describeSchema+".hidden")
		require.NotContains(t, l, "zqxsecret:text")
	}

	admin, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	_, err = admin.Exec(ctx, `ALTER TABLE `+describeSchema+`.a ADD COLUMN extra int`)
	require.NoError(t, err)

	after, err := pgcatalog.StructureLines(ctx, db)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
	require.Greater(t, len(after), len(before))
}

// TestStructureLinesFollowGrantsAndComments: the catalog fingerprint moves
// when the agent gains a write grant or a table comment changes, and not
// when rows are added.
func TestStructureLinesFollowGrantsAndComments(t *testing.T) {
	url := os.Getenv("BASALTDB_TEST_POSTGRES_URL")
	db := describeFixture(t)
	ctx := context.Background()
	admin, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	lines := func() []string {
		t.Helper()
		l, err := pgcatalog.StructureLines(ctx, db)
		require.NoError(t, err)
		return l
	}
	exec := func(sql string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql)
		require.NoError(t, err)
	}

	base := lines()
	exec(`INSERT INTO ` + describeSchema + `.a VALUES (2, 'y'), (3, 'z')`)
	require.Equal(t, base, lines(), "rows do not move it")

	var role string
	require.NoError(t, db.QueryRow(ctx, `SELECT session_user`).Scan(&role))
	exec(`GRANT INSERT ON ` + describeSchema + `.zqx_orders TO ` + role)
	granted := lines()
	require.NotEqual(t, base, granted, "a write grant moves it")

	exec(`COMMENT ON TABLE ` + describeSchema + `.zqx_orders IS 'orders, one per checkout'`)
	require.NotEqual(t, granted, lines(), "a table comment moves it")
}
