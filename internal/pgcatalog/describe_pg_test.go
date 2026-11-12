package pgcatalog_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
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
		CREATE TABLE `+s+`.a (id int PRIMARY KEY, label text);
		COMMENT ON TABLE `+s+`.a IS '  Accounts, padded  ';
		COMMENT ON COLUMN `+s+`.a.id IS 'account id';
		CREATE TABLE `+s+`.b (id int PRIMARY KEY, label text, secret_note text,
			doubled int GENERATED ALWAYS AS (id * 2) STORED);
		CREATE INDEX b_secret_idx ON `+s+`.b (secret_note);
		CREATE INDEX b_partial_idx ON `+s+`.b (label) WHERE secret_note IS NOT NULL;
		CREATE TABLE `+s+`.hidden (id int PRIMARY KEY, a_id int REFERENCES `+s+`.a (id) ON DELETE CASCADE);
		CREATE TABLE `+s+`.child (id int PRIMARY KEY, a_id int REFERENCES `+s+`.a (id) ON DELETE CASCADE);
		CREATE TABLE `+s+`.leaf (id int PRIMARY KEY, b_id int REFERENCES `+s+`.b (id));
		CREATE TABLE `+s+`.p (id int, v text) PARTITION BY RANGE (id);
		CREATE TABLE `+s+`.p1 PARTITION OF `+s+`.p FOR VALUES FROM (0) TO (10);
		CREATE TABLE `+s+`.p2 PARTITION OF `+s+`.p FOR VALUES FROM (10) TO (20);
		CREATE TABLE `+s+`.p3 PARTITION OF `+s+`.p FOR VALUES FROM (20) TO (30);
		CREATE TABLE `+s+`.fresh (x int);
		CREATE VIEW `+s+`.v AS SELECT id, label FROM `+s+`.a;
		GRANT USAGE ON SCHEMA `+s+` TO `+role+`;
		GRANT SELECT, INSERT, UPDATE, DELETE ON `+s+`.a TO `+role+`;
		GRANT SELECT (id, label) ON `+s+`.b TO `+role+`;
		GRANT SELECT ON `+s+`.child, `+s+`.leaf, `+s+`.p, `+s+`.fresh, `+s+`.v TO `+role+`;
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
	require.ElementsMatch(t, []string{"a", "b", "child", "leaf", "p", "fresh", "v"}, names)
	require.Equal(t, "PARTITIONED_TABLE", relByName(t, rels, "p").Kind)
	require.Equal(t, "VIEW", relByName(t, rels, "v").Kind)
	require.Equal(t, "TABLE", relByName(t, rels, "a").Kind)
	require.GreaterOrEqual(t, notGranted, 1)
	require.Equal(t, "  Accounts, padded  ", relByName(t, rels, "a").Comment)
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
	require.False(t, cols["secret_note"].Selectable)
	require.Equal(t, int16(3), cols["secret_note"].Attnum)
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
	require.Equal(t, "  Accounts, padded  ", a.Comment)
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
		require.Equal(t, "child", k.OtherTable)
		require.Equal(t, []string{"a_id"}, k.OtherColumns)
		require.Equal(t, []int16{1}, k.Attnums)
	}
	require.Equal(t, 1, hiddenKeys)
	require.Equal(t, 1, childKeys)

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

func TestForeignKeysSeesReadOnlyTables(t *testing.T) {
	db := describeFixture(t)
	fks, err := pgcatalog.ForeignKeys(context.Background(), db, describeSchema, "leaf")
	require.NoError(t, err)
	require.Equal(t, []pgcatalog.ForeignKey{{Column: "b_id", RefSchema: describeSchema, RefTable: "b", RefColumn: "id"}}, fks)
}

func TestSearchRanksAndPages(t *testing.T) {
	db := describeFixture(t)
	ctx := context.Background()

	all, err := pgcatalog.Search(ctx, db, "a", nil, 100)
	require.NoError(t, err)
	var mine []pgcatalog.Match
	for _, m := range all {
		if m.Schema == describeSchema {
			mine = append(mine, m)
		}
	}
	require.NotEmpty(t, mine)
	require.Equal(t, "a", mine[0].Name)
	require.Equal(t, 0, mine[0].Rank)
	require.Equal(t, "table", mine[0].Matched)

	for _, m := range all {
		require.NotEqual(t, "hidden", m.Name)
	}

	secret, err := pgcatalog.Search(ctx, db, "secret", nil, 100)
	require.NoError(t, err)
	for _, m := range secret {
		require.False(t, m.Schema == describeSchema && m.Name == "b", "unselectable column must not match")
	}

	byComment, err := pgcatalog.Search(ctx, db, "padded", nil, 100)
	require.NoError(t, err)
	require.Equal(t, 4, byComment[0].Rank)
	require.Equal(t, "comment", byComment[0].Matched)

	byColumn, err := pgcatalog.Search(ctx, db, "label", nil, 100)
	require.NoError(t, err)
	require.Equal(t, 3, byColumn[0].Rank)
	require.Equal(t, "column label", byColumn[0].Matched)

	var paged []pgcatalog.Match
	var cursor *pgcatalog.SearchCursor
	for range len(all) + 1 {
		page, err := pgcatalog.Search(ctx, db, "a", cursor, 1)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		require.Len(t, page, 1)
		paged = append(paged, page[0])
		cursor = &pgcatalog.SearchCursor{Rank: page[0].Rank, Schema: page[0].Schema, Name: page[0].Name}
	}
	require.Equal(t, all, paged)
}

func TestSearchTreatsWildcardsAsText(t *testing.T) {
	db := describeFixture(t)
	got, err := pgcatalog.Search(context.Background(), db, "%", nil, 100)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestListAccess(t *testing.T) {
	db := describeFixture(t)
	acc, err := pgcatalog.ListAccess(context.Background(), db)
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
	require.Equal(t, []string{describeSchema + ".hidden"}, mine(acc.NotGranted))
	require.NotContains(t, acc.Read, describeSchema+".p1")
}

func TestStructureLinesChangeOnAddColumn(t *testing.T) {
	url := os.Getenv("BASALTDB_TEST_POSTGRES_URL")
	db := describeFixture(t)
	ctx := context.Background()
	before, err := pgcatalog.StructureLines(ctx, db)
	require.NoError(t, err)
	require.True(t, slices.IsSorted(before))
	require.Contains(t, before, describeSchema+".a:TABLE")
	for _, l := range before {
		require.NotContains(t, l, describeSchema+".hidden")
		require.NotContains(t, l, "secret_note:text")
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
