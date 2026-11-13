package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/revert"
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

func TestRevertLinesShowHiddenCharactersAsEscapes(t *testing.T) {
	t.Parallel()
	conflict := "CHANGED_AFTER"
	restore := revert.Line{
		Op: "UPDATE", Table: "public.le\u200bads", Key: json.RawMessage("{\"id\": \"0001\u202e\"}"),
		Now: json.RawMessage(`{"code": "1000"}`), Set: json.RawMessage("{\"code\": \"0001\u202e\u009b\"}"),
		Action: revert.ActionRestore,
	}
	got := revertLineText(restore)
	require.Equal(t, `restore    public.le<U+200B>ads {"id": "0001<U+202E>"}: code: "1000" -> "0001<U+202E><U+009B>"`, got)
	skip := restore
	skip.Action, skip.Conflict = revert.ActionSkip, &conflict
	require.Equal(t, `skip       public.le<U+200B>ads {"id": "0001<U+202E>"}: CHANGED_AFTER`, revertLineText(skip))
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
		got := linkPages{local: local}.short(c, "approvals", id, "binding", long)
		require.Equal(t, long, got, name)
		require.Contains(t, stderr.String(), "the engine gave no short link", name)
		require.NotContains(t, stderr.String(), answer, name)
	}

	h := newFakeHost(t)
	var stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
	c.host = h
	require.Equal(t, page+fakeSecret, linkPages{local: local}.short(c, "approvals", id, "binding", long), "the item's own short link")
	require.Empty(t, stderr.String())

	h.issueErr = errors.New("engine answered 500: \x1b]8;;https://evil.example\x1b\\click\u202e\r\nbasalt: approved")
	got := linkPages{local: local}.short(c, "approvals", id, "binding", long)
	require.Equal(t, long, got)
	require.Equal(t, "basalt: the engine gave no short link (engine answered 500: ?]8;;https://evil.example?\\click???basalt: approved); using the long link\n",
		stderr.String(), "the engine's message is shown with its control characters replaced")
}

// basalt log's text output shows a row's timestamptz values as RFC 3339 UTC.
func TestLogTextShowsTimestampsAsUTC(t *testing.T) {
	t.Parallel()
	line := rowLine(ledger.RowChange{
		Table: "public.leads", Op: "UPDATE",
		Key:    map[string]any{"id": 1.0},
		Before: map[string]any{"updated_at": "2026-11-12T14:08:04.513958+02:00"},
		After:  map[string]any{"updated_at": "2026-11-12T14:11:27+02:00"},
	}, false)
	require.Contains(t, line, "2026-11-12T12:11:27Z")
	require.NotContains(t, line, "+02:00")
	full := rowLine(ledger.RowChange{
		Table: "public.leads", Op: "UPDATE", Key: map[string]any{"id": 1.0},
		Before: map[string]any{"updated_at": "2026-11-12T14:08:04+02:00"}, After: map[string]any{"updated_at": "2026-11-12T14:11:27+02:00"},
	}, true)
	require.NotContains(t, full, "+02:00")
	require.Contains(t, full, "2026-11-12T12:08:04Z")
}
