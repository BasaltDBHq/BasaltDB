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

	"github.com/basaltdbhq/basaltdb/internal/revert"
)

func TestVisibleTextEscapesWhatHidesOrReordersText(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"0001\u202e":         "0001<U+202E>",
		"\u202e1000":         "<U+202E>1000",
		"a\u200bb":           "a<U+200B>b",
		"a\u009bb":           "a<U+009B>b",
		"a\nb\tc\x1b[31m":    "a<U+000A>b<U+0009>c<U+001B>[31m",
		"a\u00a0b\u2028c":    "a<U+00A0>b<U+2028>c",
		"filler\u3164":       "filler<U+3164>",
		"bad \xff byte":      "bad <0xFF> byte",
		"note 5 — 日本 🚀 José": "note 5 — 日本 🚀 José",
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
