package wiretime

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestText(t *testing.T) {
	cases := map[string]string{
		"2026-11-12 14:08:04.513958+02":       "2026-11-12T12:08:04.513958Z",
		"2026-11-12T14:08:04.513958+02:00":    "2026-11-12T12:08:04.513958Z",
		"2026-11-10 06:02:11+00":              "2026-11-10T06:02:11Z",
		"2026-11-10 06:02:11.500000+00":       "2026-11-10T06:02:11.5Z",
		"2026-11-10 01:30:00-05:30":           "2026-11-10T07:00:00Z",
		"2026-01-01 00:10:00+05:53:28":        "2025-12-31T18:16:32Z",
		"2026-12-31 23:00:00-02":              "2027-01-01T01:00:00Z",
		"2026-11-10T06:02:11Z":                "",
		"2026-11-10 06:02:11":                 "",
		"2026-11-10T06:02:11":                 "",
		"infinity":                            "",
		"2026-13-10 06:02:11+00":              "",
		"2026-11-10 25:02:11+00":              "",
		"0044-03-15 00:00:00+00 BC":           "",
		"note: 2026-11-10 06:02:11+02 (late)": "",
		"9999-12-31 23:00:00-02":              "",
	}
	for in, want := range cases {
		got, ok := Text(in)
		if want == "" {
			require.False(t, ok, in)
			require.Equal(t, in, got)
			continue
		}
		require.True(t, ok, in)
		require.Equal(t, want, got, in)
	}
}

func TestJSON(t *testing.T) {
	in := json.RawMessage(`{"a":"2026-11-12T14:08:04+02:00","b":["2026-11-12T14:08:04.25-01:00",12345678901234567890,"x"],"c":{"d":"<&>"},"e":"2026-11-12T14:08:04"}`)
	got := JSON(in)
	require.JSONEq(t, `{"a":"2026-11-12T12:08:04Z","b":["2026-11-12T15:08:04.25Z",12345678901234567890,"x"],"c":{"d":"<&>"},"e":"2026-11-12T14:08:04"}`, string(got))
	require.Contains(t, string(got), "<&>")

	same := json.RawMessage(`{ "a": 1.50 }`)
	require.Equal(t, string(same), string(JSON(same)))
	bad := json.RawMessage(`{nope`)
	require.Equal(t, string(bad), string(JSON(bad)))
	require.Nil(t, JSON(nil))
}

// Inside stored values only to_jsonb's shape is rewritten.
func TestJSONLeavesOtherShapesAlone(t *testing.T) {
	for _, in := range []string{`"2026-11-10 06:02:11+02"`, `"2026-11-10T06:02:11+02"`, `"2026-11-10 06:02:11+02:00"`, `"2026-11-10T06:02:11Z"`} {
		require.Equal(t, in, string(JSON(json.RawMessage(in))), in)
	}
	require.Equal(t, `"2026-11-10T04:02:11Z"`, string(JSON(json.RawMessage(`"2026-11-10T06:02:11+02:00"`))))
	require.Equal(t, `"2026-11-10T04:02:11Z"`, string(JSON(json.RawMessage(`"2026-11-10T06:02:11+02:00:00"`))))
}

func TestMap(t *testing.T) {
	m := map[string]any{"t": "2026-11-12T14:08:04+02:00", "n": nil, "l": []any{"2026-11-12T14:08:04+02:00"}}
	Map(m)
	require.Equal(t, "2026-11-12T12:08:04Z", m["t"])
	require.Equal(t, []any{"2026-11-12T12:08:04Z"}, m["l"])
	require.Nil(t, Map(nil))
}

// Fields rewrites the timestamps in the named fields of a revert line only:
// numbers keep their spelling, other fields their text, and a line with
// nothing to rewrite comes back as given.
func TestFields(t *testing.T) {
	t.Parallel()
	text := `{"op": "UPDATE", "key": {"id": 1}, "now": {"at": "2026-11-12T14:08:04+02:00"}, "set": {"n": 12345678901234567890, "at": "2026-11-12T14:00:00.5+02:00"}, "resource": "public.leads", "note": "2026-11-12T14:08:04+02:00"}`
	var shown map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(Fields(text, "key", "now", "set")), &shown))
	require.JSONEq(t, `{"at":"2026-11-12T12:08:04Z"}`, string(shown["now"]))
	require.JSONEq(t, `{"at":"2026-11-12T12:00:00.5Z","n":12345678901234567890}`, string(shown["set"]))
	require.Contains(t, string(shown["set"]), "12345678901234567890")
	require.JSONEq(t, `{"id":1}`, string(shown["key"]))
	require.JSONEq(t, `"2026-11-12T14:08:04+02:00"`, string(shown["note"]), "a field not named is left alone")
	require.JSONEq(t, `"public.leads"`, string(shown["resource"]))

	plain := `{"op": "DELETE", "key": {"id": 1}, "now": {"at": "2026-11-12T12:08:04Z"}}`
	require.Equal(t, plain, Fields(plain, "key", "now", "set"), "nothing to rewrite: the text as given")
	require.Equal(t, "not json", Fields("not json", "key"))
}
