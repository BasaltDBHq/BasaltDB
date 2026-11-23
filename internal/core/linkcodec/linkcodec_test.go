package linkcodec_test

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// pgLines are lines as Postgres's jsonb text prints them, covering every
// kind of value format 2 carries.
func pgLines() []string {
	return []string{
		`{"op": "DELETE", "key": {"id": 3}, "old": {"id": 3, "name": "Café ✓ lead", "status": "open"}, "set": null, "table": "public.leads", "cascaded": false}`,
		`{"op": "DELETE", "key": {"id": 5}, "old": {"id": 5, "note": "note 5 — 日本 🚀", "lead_id": 3}, "set": null, "table": "public.lead_notes", "cascaded": true}`,
		`{"op": "DELETE", "key": {"id": 6}, "old": {"id": 6, "note": "tab\there \"quoted\" back\\slash \u0001", "lead_id": 3}, "set": null, "table": "public.lead_notes", "cascaded": true}`,
		`{"op": "DELETE", "table": "public.note_tags", "rowHash": "abab", "cascaded": true, "redacted": true}`,
		`{"op": "UPDATE", "key": {"id": 9}, "old": {"id": 9, "big": 9007199254740993, "doc": {"a": [1, 2], "b": null}, "tags": ["x", "y"], "price": 1.50, "empty": {}, "neg": -42, "flag": true}, "set": {"price": 2.00}, "table": "public.items", "cascaded": false}`,
		`{"op": "INSERT", "key": null, "old": null, "set": {}, "table": "public.empty", "cascaded": false}`,
		`{"op":"INSERT","not":"jsonb spacing"}`,
		`{"op": "UPDATE", "key": {"id": 1}, "now": null, "set": {"id": 1}, "table": "public.leads", "action": "SKIP", "cascaded": false, "conflict": "ROW_GONE", "sqlState": null, "changeIds": ["0193a4c2-7d1e-7c3a-9f00-0000000000e1", "0193a4c2-7d1e-7c3a-9f00-0000000000e2"]}`,
	}
}

func roundTrip(t *testing.T, lines []string) []string {
	t.Helper()
	raw, err := json.Marshal(linkcodec.Compact(lines))
	require.NoError(t, err)
	var c linkcodec.Lines
	require.NoError(t, json.Unmarshal(raw, &c))
	got, err := c.Rebuild(len(lines))
	require.NoError(t, err)
	return got
}

func TestCompactRoundTrip(t *testing.T) {
	t.Parallel()
	lines := pgLines()
	require.Equal(t, lines, roundTrip(t, lines))
}

func TestCompactSharesShapes(t *testing.T) {
	t.Parallel()
	lines := pgLines()
	c := linkcodec.Compact(lines)
	require.Len(t, c.Lines, len(lines))
	require.Len(t, c.Shapes, len(lines)-2, "the two lead_notes lines share a shape; the odd spacing travels as text")
	require.True(t, c.Lines[6].Verbatim, "a line that does not rebuild exactly travels as its text")
	require.Equal(t, c.Lines[1].Shape, c.Lines[2].Shape)
}

func TestCompactIsShorter(t *testing.T) {
	t.Parallel()
	lines := make([]string, 0, 50)
	for i := range 50 {
		lines = append(lines, strings.ReplaceAll(pgLines()[1], `"id": 5`, `"id": `+strings.Repeat("1", i%9+1)))
	}
	v1, err := linkcodec.Encode(linkcodec.Format1, map[string]any{"lines": lines})
	require.NoError(t, err)
	v2, err := linkcodec.Encode(linkcodec.Format2, linkcodec.Compact(lines))
	require.NoError(t, err)
	require.Less(t, len(v2), len(v1))
}

func TestRebuildRefuses(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, json, detail string }{
		{"no lines", `[[], []]`, "no lines"},
		{"too many lines", `[[], ["a", "b", "c", "d"]]`, "4 lines"},
		{"shapes missing", `[null, ["a"]]`, "shapes, lines"},
		{"one element", `[["a"]]`, "shapes, lines"},
		{"an object", `{"shapes": [], "lines": ["a"]}`, "shapes, lines"},
		{"more shapes than lines", `[[["a"], ["b"]], [[0, 1]]]`, "shapes"},
		{"unused shape", `[[["a"]], ["x"]]`, "unused"},
		{"shape out of range", `[[["a"]], [[1, 1]]]`, "shape 1"},
		{"negative shape", `[[["a"]], [[-1, 1]]]`, "shape"},
		{"too few values", `[[["a", "b"]], [[0, 1]]]`, "values"},
		{"too many values", `[[["a"]], [[0, 1, 2]]]`, "values"},
		{"empty shape", `[[[]], [[0]]]`, "entries"},
		{"bad entry", `[[[1]], [[0, 1]]]`, "entry"},
		{"bad object entry", `[[[["a", "b"]]], [[0, 1]]]`, "entry"},
		{"object entry of three", `[[[["a", ["b"], 1]]], [[0, 1]]]`, "entry"},
		{"fraction", `[[["a"]], [[0, 1.5]]]`, "integer"},
		{"unsafe integer", `[[["a"]], [[0, 9007199254740992]]]`, "integer"},
		{"negative zero", `[[["a"]], [[0, -0]]]`, "integer"},
		{"value object", `[[["a"]], [[0, {"x": "1"}]]]`, "raw"},
		{"raw not a string", `[[["a"]], [[0, {"raw": 1}]]]`, "raw"},
		{"line neither", `[[], [1]]`, "line"},
		{"empty line array", `[[], [[]]]`, "line"},
		{"too deep", `[[["a"]], [[0, ` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `]]]`, "deep"},
		{"too long", `[[["` + strings.Repeat("n", 400_000) + `"]], [[0, 1], [0, 1], [0, 1]]]`, "MiB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var c linkcodec.Lines
			err := json.Unmarshal([]byte(tc.json), &c)
			if err == nil {
				_, err = c.Rebuild(3)
			}
			require.Error(t, err)
			require.ErrorContains(t, err, tc.detail)
		})
	}
}

func TestRebuildNumbersAsThePagesDo(t *testing.T) {
	t.Parallel()
	var c linkcodec.Lines
	require.NoError(t, json.Unmarshal([]byte(`[[["a", "b", "c"]], [[0, 1.0, 1e2, -7]]]`), &c))
	got, err := c.Rebuild(1)
	require.NoError(t, err)
	require.Equal(t, []string{`{"a": 1, "b": 100, "c": -7}`}, got, "JSON.parse reads 1.0 as 1; Go must rebuild the same text")
}

func deflate(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestDecodeRefuses(t *testing.T) {
	t.Parallel()
	good := deflate(t, []byte(`{"a": 1}`))
	cases := []struct{ name, payload, detail string }{
		{"not base64url", "@@@", "base64url"},
		{"line break inside", passkey.Bytes(good).String()[:4] + "\n" + passkey.Bytes(good).String()[4:], "base64url"},
		{"not deflate", passkey.Bytes("plain json").String(), "deflate"},
		{"junk after deflate", passkey.Bytes(append(append([]byte{}, good...), "junk"...)).String(), "after"},
		{"json after json", passkey.Bytes(deflate(t, []byte(`{"a": 1} {"a": 2}`))).String(), "after"},
		{"unknown field", passkey.Bytes(deflate(t, []byte(`{"a": 1, "b": 2}`))).String(), "unknown field"},
		{"not utf-8", passkey.Bytes(deflate(t, []byte("{\"a\": 1, \"s\": \"\xff\"}"))).String(), "UTF-8"},
		{"inflation bomb", passkey.Bytes(deflate(t, []byte(`{"a": 1, "s": "`+strings.Repeat(" ", 2<<20)+`"}`))).String(), "inflates past"},
		{"too long", strings.Repeat("A", linkcodec.MaxFragmentLen+1), "longer than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var v struct {
				A int `json:"a"`
			}
			err := linkcodec.Decode(tc.payload, &v)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.detail)
		})
	}
	var v struct {
		A int `json:"a"`
	}
	require.NoError(t, linkcodec.Decode(passkey.Bytes(good).String(), &v))
	require.Equal(t, 1, v.A)
}

func TestSplit(t *testing.T) {
	t.Parallel()
	for _, frag := range []string{"#1.abc", "1.abc", "#2.abc", "2.abc"} {
		format, payload, err := linkcodec.Split(frag)
		require.NoError(t, err, frag)
		require.Equal(t, strings.TrimPrefix(frag, "#")[:2], format)
		require.Equal(t, "abc", payload)
	}
	for _, frag := range []string{"", "#", "3.abc", "s=abc", "1"} {
		_, _, err := linkcodec.Split(frag)
		require.ErrorContains(t, err, "must start with", frag)
	}
}

// FuzzCompactRoundTrip: any lines of UTF-8 text come back exactly.
func FuzzCompactRoundTrip(f *testing.F) {
	for _, l := range pgLines() {
		f.Add(l, `{"a": 1}`)
	}
	f.Add(`{"a": {"b": "\u0000"}}`, `[1, 2]`)
	f.Add(`{"a": 01}`, `{"a" : 1}`)
	f.Fuzz(func(t *testing.T, a, b string) {
		if !utf8.ValidString(a) || !utf8.ValidString(b) {
			t.Skip("Postgres prints UTF-8")
		}
		lines := []string{a, b}
		require.Equal(t, lines, roundTrip(t, lines))
	})
}

// fuzzMaxLines is the most lines a revert link carries.
const fuzzMaxLines = 1000

// FuzzRebuild: whatever a link carries, rebuilding never panics, and what
// rebuilds stays within its limits and compacts to the same lines.
func FuzzRebuild(f *testing.F) {
	raw, err := json.Marshal(linkcodec.Compact(pgLines()))
	require.NoError(f, err)
	f.Add(string(raw))
	f.Add(`[[["a", ["b", ["c"]]]], [[0, [1, [2]], {"raw": "x"}], "v"]]`)
	f.Add(`[[["a"]], [[0, 1e400]]]`)
	f.Fuzz(func(t *testing.T, text string) {
		var c linkcodec.Lines
		if json.Unmarshal([]byte(text), &c) != nil {
			return
		}
		lines, err := c.Rebuild(fuzzMaxLines)
		if err != nil {
			return
		}
		total := 0
		for _, l := range lines {
			total += len(l)
		}
		require.LessOrEqual(t, total, linkcodec.MaxLinesBytes)
		if utf8.ValidString(strings.Join(lines, "")) {
			require.Equal(t, lines, roundTrip(t, lines))
		}
	})
}

// TestEncodeRequestRefusesWhatAPageCannotDecode: a request whose texts
// rebuild past 1 MiB, or whose JSON inflates past 1 MiB, is
// ErrRequestTooLarge, never a fragment the page would refuse; one just
// under both encodes and decodes.
func TestEncodeRequestRefusesWhatAPageCannotDecode(t *testing.T) {
	t.Parallel()
	binding := `{"kind": "APPROVE"}`
	_, err := linkcodec.EncodeRequest(binding, []string{strings.Repeat("x", linkcodec.MaxLinesBytes)}, nil)
	require.ErrorIs(t, err, linkcodec.ErrRequestTooLarge, "texts past 1 MiB")

	// Under 1 MiB of text, but every '"' takes two bytes in the JSON.
	_, err = linkcodec.EncodeRequest(binding, []string{strings.Repeat(`"`, 600000)}, nil)
	require.ErrorIs(t, err, linkcodec.ErrRequestTooLarge, "JSON past 1 MiB")

	frag, err := linkcodec.EncodeRequest(binding, []string{strings.Repeat("x", 500000)}, nil)
	require.NoError(t, err)
	var got []string
	_, err = linkcodec.DecodeRequest(frag, 1, func(b string, lines []string, _ []passkey.Bytes) struct{} {
		got = append([]string{b}, lines...)
		return struct{}{}
	})
	require.NoError(t, err)
	require.Equal(t, []string{binding, strings.Repeat("x", 500000)}, got)
}
