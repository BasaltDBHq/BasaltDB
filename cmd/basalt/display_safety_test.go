package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
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

func TestShortLinkOnlyFromThisItemsLocalPage(t *testing.T) {
	t.Parallel()
	const local = "http://localhost:18787"
	id := uuid.MustParse("0190a3f2-7c1e-7000-8000-000000000001")
	other := uuid.MustParse("0190a3f2-7c1e-7000-8000-000000000002")
	long := local + "/approvals/" + id.String() + "#2.abc"
	page := local + "/approvals/" + id.String() + "#s="
	for name, answer := range map[string]string{
		"foreign origin":   "https://evil.example/approvals/" + id.String() + "#s=" + fakeSecret,
		"lookalike origin": local + ".evil.example/approvals/" + id.String() + "#s=" + fakeSecret,
		"wrong kind":       local + "/reverts/" + id.String() + "#s=" + fakeSecret,
		"wrong id":         local + "/approvals/" + other.String() + "#s=" + fakeSecret,
		"no secret":        local + "/approvals/" + id.String(),
		"long link":        local + "/approvals/" + id.String() + "#2.abc",
		"short secret":     page + "c2VjcmV0",
		"secret with more": page + fakeSecret + "&next=https://evil.example",
		"secret with crlf": page + fakeSecret[:11] + "\r\n" + fakeSecret[11:],
		"trailing newline": page + fakeSecret + "\n",
		"padded secret":    page + fakeSecret + "==",
		"non-zero tail":    page + fakeSecret[:21] + "h",
	} {
		h := newFakeHost(t)
		h.issueURL = answer
		var stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
		c.host = h
		got := linkPages{local: local}.short(c, id, "binding", long)
		require.Equal(t, long, got, name)
		require.Contains(t, stderr.String(), "the engine gave no short link", name)
		require.NotContains(t, stderr.String(), answer, name)
	}

	h := newFakeHost(t)
	var stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
	c.host = h
	require.Equal(t, page+fakeSecret, linkPages{local: local}.short(c, id, "binding", long), "the item's own short link")
	require.Empty(t, stderr.String())

	h.issueErr = errors.New("engine answered 500: \x1b]8;;https://evil.example\x1b\\click\u202e\r\nbasalt: approved")
	got := linkPages{local: local}.short(c, id, "binding", long)
	require.Equal(t, long, got)
	require.Equal(t, "basalt: the engine gave no short link (engine answered 500: ?]8;;https://evil.example?\\click???basalt: approved); using the long link\n",
		stderr.String(), "the engine's message is shown with its control characters replaced")
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
