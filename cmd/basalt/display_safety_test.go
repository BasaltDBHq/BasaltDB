package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
