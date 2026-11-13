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

func TestMap(t *testing.T) {
	m := map[string]any{"t": "2026-11-12T14:08:04+02:00", "n": nil, "l": []any{"2026-11-12T14:08:04+02:00"}}
	Map(m)
	require.Equal(t, "2026-11-12T12:08:04Z", m["t"])
	require.Equal(t, []any{"2026-11-12T12:08:04Z"}, m["l"])
	require.Nil(t, Map(nil))
}
