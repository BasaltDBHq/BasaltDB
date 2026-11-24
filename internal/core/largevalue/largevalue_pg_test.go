package largevalue_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// vectorsFile holds the shared vectors the engine and the pages run.
const vectorsFile = "../../../api/mcp/values/large-value.json"

type vector struct {
	Name   string          `json:"name"`
	Value  json.RawMessage `json:"value"`
	Text   string          `json:"text"`
	Bytes  int64           `json:"bytes"`
	SHA256 string          `json:"sha256"`
	Column string          `json:"column"`
	Cost   int64           `json:"cost"`
}

// TestSharedVectorsMatchPostgres: Postgres measures each vector's text,
// bytes, sha256 and cost exactly as the shared file says.
func TestSharedVectorsMatchPostgres(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(vectorsFile)
	require.NoError(t, err)
	var file struct {
		Vectors []vector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.Len(t, file.Vectors, 3)
	db := guardtest.New(t)
	text := largevalue.TextOf("$1::jsonb")
	sql := fmt.Sprintf(`SELECT %s, %s, %s, %s`, text, largevalue.BytesOf(text), largevalue.SHA256Of(text), largevalue.CostOf("($1::jsonb)::text", "$2::text"))
	for _, v := range file.Vectors {
		var got vector
		require.NoError(t, db.Admin.QueryRow(context.Background(), sql, string(v.Value), v.Column).
			Scan(&got.Text, &got.Bytes, &got.SHA256, &got.Cost), v.Name)
		require.Equal(t, v.Text, got.Text, v.Name)
		require.Equal(t, v.Bytes, got.Bytes, v.Name)
		require.Equal(t, v.SHA256, got.SHA256, v.Name)
		require.Equal(t, v.Cost, got.Cost, v.Name)
		sum := sha256.Sum256([]byte(v.Text))
		require.Equal(t, hex.EncodeToString(sum[:]), v.SHA256, "%s: the hash is SHA-256 of the text", v.Name)
	}
}

// image is one lv_out row.
type image struct {
	Ord   int64
	Part  string
	Img   map[string]any
	Large []largevalue.Entry
}

// elide runs Elide over src and returns item 1's images by ord.
func elide(t *testing.T, db *guardtest.DB, src string) map[int64]image {
	t.Helper()
	// Plain SQL: the CTE under test.
	rows, err := db.Admin.Query(context.Background(), largevalue.With+largevalue.Elide(src)+`
		SELECT ord, part, img, large_values FROM lv_out ORDER BY ord`)
	require.NoError(t, err)
	out := map[int64]image{}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (image, error) {
		var i image
		var large []byte
		err := r.Scan(&i.Ord, &i.Part, &i.Img, &large)
		if err == nil && large != nil {
			err = json.Unmarshal(large, &i.Large)
		}
		return i, err
	})
	require.NoError(t, err)
	for _, i := range list {
		out[i.Ord] = i
	}
	return out
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestElideLeavesOutAValueOverOneMiB: the value is absent from its image
// (never null), named with its column, size and hash; the rest is kept.
func TestElideLeavesOutAValueOverOneMiB(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	big := strings.Repeat("x", 2<<20)
	got := elide(t, db, `SELECT 1 AS item, 1 AS ord, 'KEY' AS part, '{"id": 1}'::jsonb AS img
		UNION ALL SELECT 1, 2, 'BEFORE', jsonb_build_object('id', 1, 'body', repeat('x', 2097152))
		UNION ALL SELECT 1, 3, 'AFTER', '{"id": 1, "body": "small"}'::jsonb
		UNION ALL SELECT 1, 4, 'AFTER', NULL`)
	require.Len(t, got, 3, "a NULL image has no row")
	require.Equal(t, map[string]any{"id": float64(1)}, got[1].Img)
	require.Nil(t, got[1].Large)
	require.Equal(t, map[string]any{"id": float64(1)}, got[2].Img, "body is absent, not null")
	require.Equal(t, []largevalue.Entry{{In: "BEFORE", Column: "body", Bytes: int64(len(big)), SHA256: sha(big)}}, got[2].Large)
	require.Equal(t, map[string]any{"id": float64(1), "body": "small"}, got[3].Img)
}

// TestElideCountsEscapesInTheCost: 1,000,000 '<' are under 1 MiB of text
// but cost about 7 MB, so each value is left out.
func TestElideCountsEscapesInTheCost(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	lt := strings.Repeat("<", 1000000)
	cols := make([]string, 0, 7)
	for i := range 7 {
		cols = append(cols, fmt.Sprintf("'c%d', repeat('<', 1000000)", i))
	}
	got := elide(t, db, `SELECT 1 AS item, 1 AS ord, 'AFTER' AS part, jsonb_build_object(`+strings.Join(cols, ", ")+`) AS img`)
	require.Empty(t, got[1].Img)
	require.NotNil(t, got[1].Img, "the image is kept, with no value left in it")
	require.Len(t, got[1].Large, 7)
	for i, e := range got[1].Large {
		require.Equal(t, largevalue.Entry{In: "AFTER", Column: fmt.Sprintf("c%d", i), Bytes: 1000000, SHA256: sha(lt)}, e)
	}
}

// TestElideLeavesOutAWholeImagePastEightMiB: values under 1 MiB each that
// add up past 8 MiB leave the next image out whole, with one entry over
// its jsonb text; a later small image is still kept.
func TestElideLeavesOutAWholeImagePastEightMiB(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	five := `jsonb_build_object('a', repeat('x', 1000000), 'b', repeat('x', 1000000), 'c', repeat('x', 1000000),
		'd', repeat('x', 1000000), 'e', repeat('x', 1000000))`
	got := elide(t, db, `SELECT 1 AS item, 1 AS ord, 'BEFORE' AS part, `+five+` AS img
		UNION ALL SELECT 1, 2, 'AFTER', `+five+`
		UNION ALL SELECT 1, 3, 'KEY', '{"id": 2}'::jsonb`)
	require.Len(t, got[1].Img, 5, "the first image fits")
	require.Nil(t, got[1].Large)
	require.Nil(t, got[2].Img, "the second takes the item over 8 MiB: left out whole")
	var text string
	require.NoError(t, db.Admin.QueryRow(context.Background(), `SELECT (`+five+`)::text`).Scan(&text))
	require.Equal(t, []largevalue.Entry{{In: "AFTER", Bytes: int64(len(text)), SHA256: sha(text)}}, got[2].Large)
	require.Equal(t, map[string]any{"id": float64(2)}, got[3].Img, "a later image that fits is kept")
}

// TestElideLeavesOutLargeParamsWhole: a params array with one value over
// 1 MiB is left out whole, with an entry per large parameter by index; a
// large statement is left out too.
func TestElideLeavesOutLargeParamsWhole(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	big := strings.Repeat("y", 1100000)
	stmt := "SELECT '" + big + "'"
	got := elide(t, db, `SELECT 1 AS item, 1 AS ord, 'STATEMENT' AS part, to_jsonb('SELECT ''' || repeat('y', 1100000) || '''') AS img
		UNION ALL SELECT 1, 2, 'PARAMS', jsonb_build_array(1, repeat('y', 1100000), 'z')`)
	require.Nil(t, got[1].Img)
	require.Equal(t, []largevalue.Entry{{In: "STATEMENT", Bytes: int64(len(stmt)), SHA256: sha(stmt)}}, got[1].Large)
	require.Nil(t, got[2].Img)
	one := 1
	require.Equal(t, []largevalue.Entry{{In: "PARAMS", Index: &one, Bytes: int64(len(big)), SHA256: sha(big)}}, got[2].Large)
}

// TestElideLinesSlicesChangeIDs: a line keeps its first 100 changeIds and
// counts the rest; its images are elided like any other.
func TestElideLinesSlicesChangeIDs(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	var line map[string]any
	// Plain SQL: the CTE under test.
	require.NoError(t, db.Admin.QueryRow(context.Background(), largevalue.With+largevalue.ElideLines(`SELECT 1 AS item,
		jsonb_build_object('op', 'UPDATE', 'table', 'public.t', 'key', '{"id": 1}'::jsonb,
			'now', jsonb_build_object('id', 1, 'v', repeat('x', 2000000)), 'set', '{"v": "old"}'::jsonb,
			'action', 'RESTORE', 'conflict', NULL,
			'changeIds', (SELECT jsonb_agg(g::text) FROM generate_series(1, 150) g)) AS line`)+`
		SELECT line FROM lv_lines`).Scan(&line))
	require.Len(t, line["changeIds"], largevalue.MaxChangeIDs)
	require.Equal(t, "1", line["changeIds"].([]any)[0])
	require.InDelta(t, 50, line["moreChangeIds"], 0)
	require.Equal(t, map[string]any{"id": float64(1)}, line["now"])
	require.Equal(t, map[string]any{"v": "old"}, line["set"])
	require.Contains(t, line, "conflict", "the rest of the line is unchanged")
	require.Len(t, line["largeValues"], 1)

	var small map[string]any
	require.NoError(t, db.Admin.QueryRow(context.Background(), largevalue.With+largevalue.ElideLines(`SELECT 1 AS item,
		'{"op": "DELETE", "key": {"id": 1}, "now": null, "changeIds": ["a"]}'::jsonb AS line`)+`
		SELECT line FROM lv_lines`).Scan(&small))
	require.Equal(t, map[string]any{"op": "DELETE", "key": map[string]any{"id": float64(1)}, "now": nil, "changeIds": []any{"a"}}, small,
		"a small line is unchanged")
}

// TestElideCostsAValueByItsJSONText: 140,000 '"' cost under 1 MiB counted
// over their characters, but twice that as the image's JSON text carries
// them (each one escaped as \"), so the value is left out.
func TestElideCostsAValueByItsJSONText(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	quotes := strings.Repeat(`"`, 140000)
	got := elide(t, db, `SELECT 1 AS item, 1 AS ord, 'AFTER' AS part, jsonb_build_object('id', 1, 'q', repeat('"', 140000)) AS img`)
	require.Equal(t, map[string]any{"id": float64(1)}, got[1].Img)
	require.Equal(t, []largevalue.Entry{{In: "AFTER", Column: "q", Bytes: 140000, SHA256: sha(quotes)}}, got[1].Large)
}
