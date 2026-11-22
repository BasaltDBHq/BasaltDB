package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pii/classify"
)

func TestVisibleTextEscapesWhatHidesOrReordersText(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"0001\u202e":      "0001<U+202E>",
		"\u202e1000":      "<U+202E>1000",
		"a\u200bb":        "a<U+200B>b",
		"a\u009bb":        "a<U+009B>b",
		"a\nb\tc\x1b[31m": "a<U+000A>b<U+0009>c<U+001B>[31m",
		"a\u00a0b\u2028c": "a<U+00A0>b<U+2028>c",
		"filler\u3164":    "filler<U+3164>",
		"bad \xff byte":   "bad <0xFF> byte",
		// Variation selectors: U+FE0F, U+E0100, Mongolian U+180B.
		"a\xef\xb8\x8fb":     "a<U+FE0F>b",
		"a\xf3\xa0\x84\x80b": "a<U+E0100>b",
		"a\xe1\xa0\x8bb":     "a<U+180B>b",
		// Combining marks: two in a row show, the rest are escaped.
		"e\xcc\x81":              "e\xcc\x81",
		"0" + "\xcd\x93\xcd\x93": "0\xcd\x93\xcd\x93",
		"0" + "\xcd\x93\xcd\x93\xcd\x93x\xcd\x93": "0\xcd\x93\xcd\x93<U+0353>x\xcd\x93",
		"0" + strings.Repeat("\xcd\x93", 300):     "0\xcd\x93\xcd\x93" + strings.Repeat("<U+0353>", 298),
		"note 5 — 日本 🚀 José":                      "note 5 — 日本 🚀 José",
	} {
		require.Equal(t, want, visibleText(in), "%q", in)
	}
}

// ESC, OSC, C1 and bidi characters in a table or column name, or a reason,
// reach the terminal as <U+XXXX> in the classify review (CWE-150).
func TestClassifyReviewEscapesNamesAndReasons(t *testing.T) {
	t.Parallel()
	hostile := "x\x1b[2Ky\x1b]0;owned\x07\u009b\u202e"
	col := classify.ReviewColumn{}
	col.Column.Name = hostile
	col.Suggestion = classify.Suggestion{Class: guard.ClassIdentifier, EntityType: guard.EntityEmail, Reason: "looks like " + hostile}
	needs := col
	needs.Suggestion.NeedsReview = true
	var out bytes.Buffer
	for _, narrow := range []int{0, 40} {
		out.Reset()
		printTable(&out, classify.ReviewTable{Table: "crm." + hostile, Columns: []classify.ReviewColumn{col, needs}}, narrow)
		got := out.String()
		require.NotContains(t, got, "\x1b")
		require.NotContains(t, got, "\x07")
		require.NotContains(t, got, "\u009b")
		require.NotContains(t, got, "\u202e")
		require.Contains(t, got, "x<U+001B>[2Ky<U+001B>]0;owned<U+0007><U+009B><U+202E>")
	}
}

// classify --check prints the column's full name: escaped too.
func TestClassifyChecksEscapeColumnNames(t *testing.T) {
	t.Parallel()
	col := classify.ReviewColumn{}
	col.Column.Schema, col.Column.Table, col.Column.Name = "crm", "leads", "x\x1b[2Ky\u202e"
	var out bytes.Buffer
	printChecks(&out, []classify.ReviewTable{{Table: "crm.leads", Columns: []classify.ReviewColumn{col}}},
		map[string]classify.CheckResult{col.Column.FullName(): {Sampled: 3}})
	require.NotContains(t, out.String(), "\x1b")
	require.NotContains(t, out.String(), "\u202e")
	require.Contains(t, out.String(), "x<U+001B>[2Ky<U+202E>")
}
