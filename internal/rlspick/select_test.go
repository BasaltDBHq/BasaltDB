package rlspick

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var sample = []Entry{
	{"us.transactions", 898}, {"global.user_router", 7}, {"global.family_registry", 4}, {"us.activities", 53},
}

func TestNewChecksEverythingGroupedBySchema(t *testing.T) {
	t.Parallel()
	m := New(sample)
	c, n := m.Counts()
	require.Equal(t, 4, c)
	require.Equal(t, 4, n)
	require.Equal(t, []string{"global.family_registry", "global.user_router", "us.activities", "us.transactions"}, m.Checked())
}

func TestToggleTableAndSchema(t *testing.T) {
	t.Parallel()
	m := New(sample)
	m.Down() // global.family_registry
	m.Toggle()
	c, _ := m.Counts()
	require.Equal(t, 3, c)
	require.NotContains(t, m.Checked(), "global.family_registry")

	// a on a table row flips its schema: not all checked, so all get checked.
	m.ToggleSchema()
	c, _ = m.Counts()
	require.Equal(t, 4, c)
	// again: all checked, so none.
	m.ToggleSchema()
	require.Equal(t, []string{"us.activities", "us.transactions"}, m.Checked())

	// Space on a schema row flips the schema.
	m.Up()
	m.Toggle()
	c, _ = m.Counts()
	require.Equal(t, 4, c)
}

func TestOpenCloseMovesCursor(t *testing.T) {
	t.Parallel()
	m := New(sample)
	m.Down()
	m.Close() // on a table: closes global, cursor on the schema
	require.Len(t, m.visible(), 2)
	m.Down() // us (collapsed)
	m.ToggleSchema()
	require.Equal(t, []string{"global.family_registry", "global.user_router"}, m.Checked())
	m.Open()
	require.Len(t, m.visible(), 4)
}

func TestClear(t *testing.T) {
	t.Parallel()
	m := New(sample)
	m.Clear()
	require.Empty(t, m.Checked())
}

func TestViewShowsCountsAndCollapsedHint(t *testing.T) {
	t.Parallel()
	m := New([]Entry{{"global.a", 8}, {"us.b", 2000}})
	v := m.View(0, 0)
	require.Contains(t, v[0], "› [x] global")
	require.Contains(t, v[0], "1 table")
	require.Contains(t, v[2], "us  (collapsed, → to open)")
	require.Contains(t, v[2], "2,000 rows")
	require.Equal(t, "2 of 2 checked · Enter to confirm", v[len(v)-1])
}

func TestParseKeys(t *testing.T) {
	t.Parallel()
	keys, rest := ParseKeys([]byte("\x1b[A\x1b[B\x1b[C\x1b[D a\r"))
	require.Equal(t, []Key{KeyUp, KeyDown, KeyRight, KeyLeft, KeySpace, KeySchema, KeyEnter}, keys)
	require.Empty(t, rest)
	_, rest = ParseKeys([]byte("a\x1b["))
	require.Equal(t, []byte("\x1b["), rest)
}

func TestRunDrivesTheModel(t *testing.T) {
	t.Parallel()
	m := New(sample)
	var out bytes.Buffer
	// down, space (uncheck family_registry), enter.
	err := Run(bytes.NewReader([]byte("\x1b[B \r")), &out, m, []string{"header"}, 80, 24)
	require.NoError(t, err)
	require.Equal(t, 3, len(m.Checked()))
	require.Contains(t, out.String(), "3 of 4 checked")
	require.Contains(t, out.String(), "\x1b[?25h")
}

func TestRunCtrlCAndEOFCancel(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"\x03", " "} {
		var out bytes.Buffer
		err := Run(bytes.NewReader([]byte(in)), &out, New(sample), nil, 80, 24)
		require.ErrorIs(t, err, ErrCanceled)
		require.Contains(t, out.String(), "\x1b[?25h", "cursor restored")
	}
}

func TestParseList(t *testing.T) {
	t.Parallel()
	p, err := ParseList("us.*, global.user_router")
	require.NoError(t, err)
	require.Equal(t, []Pattern{{"us", ""}, {"global", "user_router"}}, p)
	require.Equal(t, "us.*", p[0].String())
	for _, bad := range []string{"", "us", "us.", ".t", "a.b,,c.d", "us.*,"} {
		_, err := ParseList(bad)
		require.Error(t, err, bad)
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()
	p, _ := ParseList("us.*,global.user_router")
	picked, unknown := Match(sample, p)
	require.Equal(t, []bool{true, true, false, true}, picked)
	require.Empty(t, unknown)

	p, _ = ParseList("us.nope,eu.*,global.user_router")
	picked, unknown = Match(sample, p)
	require.Equal(t, []bool{false, true, false, false}, picked)
	require.Equal(t, []Pattern{{"us", "nope"}, {"eu", ""}}, unknown)
}

func TestParseAnswer(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "  ", "all", "ALL", "all-rows"} {
		a, err := ParseAnswer(s)
		require.NoError(t, err)
		require.True(t, a.All, s)
	}
	a, err := ParseAnswer("none")
	require.NoError(t, err)
	require.True(t, a.None)
	a, err = ParseAnswer("us.*")
	require.NoError(t, err)
	require.Len(t, a.Patterns, 1)
	_, err = ParseAnswer("yes please")
	require.ErrorIs(t, err, ErrAnswer)
}
