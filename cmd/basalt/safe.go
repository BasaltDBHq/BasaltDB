package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// printableLabel replaces every control character, line break and
// non-ASCII byte of text from the database with "?", so it is safe in a
// message.
func printableLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r >= 0x7f {
			return '?'
		}
		return r
	}, s)
}

// visibleText shows text an agent wrote (values, table names) as it is,
// except the characters that hide text or change how it reads: controls
// (C0, DEL, C1, line breaks), format characters (bidi controls such as
// U+202E, zero-width characters), line and paragraph separators, spaces
// other than U+0020, every default-ignorable character (variation
// selectors such as U+FE0F, U+E0100 and U+180B, Hangul fillers), and each
// combining mark after the first maxMarks in a row. Each shows as
// <U+XXXX>, and a byte that is not UTF-8 as <0xNN>, so 0001 with a U+202E
// in it cannot read as 1000. The web pages escape the same way
// (web/lib/codec.js, visibleText).
//
// Right-to-left letters stay as they are: a terminal shows characters in
// the order they come or reorders them by its own rules, and the CLI cannot
// isolate them reliably (an isolate such as U+2066 shows as a stray glyph
// on a terminal without bidi support).
func visibleText(s string) string {
	return escapeText(s, "")
}

// terminalText is visibleText for text of several lines (an error, a
// problem's message): line feeds and tabs stay as they are, every other
// character visibleText escapes is escaped, so text from the database or
// an agent cannot move the cursor, clear lines, set the window title or
// write the clipboard (ESC, CSI, OSC, BEL, DEL and the C1 controls).
func terminalText(s string) string {
	return escapeText(s, "\n\t")
}

// escapeText escapes what visibleText escapes, except the characters in
// keep.
func escapeText(s, keep string) string {
	var b strings.Builder
	marks := 0
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		first := s[0]
		s = s[size:]
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "<0x%02X>", first)
			marks = 0
			continue
		}
		if hiddenRune(r) && !strings.ContainsRune(keep, r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			marks = 0
			continue
		}
		marks = nextMarks(marks, r)
		if marks > maxMarks {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// maxMarks is how many combining marks in a row show as marks; the rest are
// escaped, so a stack of hundreds cannot paint over the lines around it.
const maxMarks = 2

func nextMarks(marks int, r rune) int {
	if unicode.Is(unicode.M, r) {
		return marks + 1
	}
	return 0
}

// mongolianSelectors are the Mongolian free variation selectors, default
// ignorable whether or not unicode.Variation_Selector lists them.
var mongolianSelectors = &unicode.RangeTable{R16: []unicode.Range16{
	{Lo: mongolianFVS1, Hi: mongolianFVS3, Stride: 1},
	{Lo: mongolianFVS4, Hi: mongolianFVS4, Stride: 1},
}}

// The Mongolian free variation selectors FVS1 to FVS3 and FVS4.
const (
	mongolianFVS1 = 0x180b
	mongolianFVS3 = 0x180d
	mongolianFVS4 = 0x180f
)

func hiddenRune(r rune) bool {
	if r == ' ' {
		return false
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs,
		unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector, mongolianSelectors)
}
