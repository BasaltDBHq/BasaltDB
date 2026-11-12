package pii

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// foldedView is the text detectors see: the original folded the way values
// are normalized (NFKC, case folding, NFKC), so a full-width or differently
// cased value is found by the same patterns and n-grams as its plain form.
// It is built one normalization segment at a time, and pieces maps each
// segment's folded bytes back to its original bytes.
type foldedView struct {
	text   string
	pieces []foldPiece // segment starts, plus a closing entry at both ends
}

// foldPiece is where one segment starts in the original and in the folded text.
type foldPiece struct{ orig, fold int }

// foldForDetection builds the folded view of s. With shapes set it builds the
// view the shape detectors (emails, phones) see instead: also without
// combining marks and with every decimal digit as its ASCII digit
// (shapeForm), so a mark on a digit or a non-ASCII digit cannot split a
// number. The dictionary keeps the plain folded view, where marks stay part
// of their word ("Jose\u0301" is still "josé").
func foldForDetection(s string, shapes bool) foldedView {
	var b strings.Builder
	b.Grow(len(s))
	caser := cases.Fold()
	pieces := make([]foldPiece, 0, len(s)+1)
	for pos := 0; pos < len(s); {
		n := norm.NFKC.NextBoundaryInString(s[pos:], true)
		if n <= 0 {
			n = len(s) - pos
		}
		pieces = append(pieces, foldPiece{orig: pos, fold: b.Len()})
		writeFolded(&b, &caser, s[pos:pos+n], shapes)
		pos += n
	}
	pieces = append(pieces, foldPiece{orig: len(s), fold: b.Len()})
	return foldedView{text: b.String(), pieces: pieces}
}

// writeFolded writes one segment folded. ASCII takes a fast path: NFKC leaves
// it alone and folding is lower case. Ignorable characters write nothing, as
// in Normalize: their segment keeps its piece, so a span found across one
// maps back over it ("ali\u200bce@corp.ee" is one address).
func writeFolded(b *strings.Builder, caser *cases.Caser, seg string, shapes bool) {
	if len(seg) == 1 && seg[0] < utf8.RuneSelf {
		c := seg[0]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
		return
	}
	if shapes {
		b.WriteString(shapeForm(caser, seg))
		return
	}
	b.WriteString(nfkcCasefold(caser, strings.Map(dropIgnorable, seg)))
}

// shapeForm is the shape detectors' form of a segment: ignorables dropped,
// NFKC (so a mark that composes with its letter stays part of it, and "é"
// written either way is the same letter), then the combining marks (Mn, Me)
// left over dropped, before and after case folding (folding can turn a mark
// into a letter, as U+0345 into "ι"), then every decimal digit (Nd) as its
// ASCII digit and every dash and full stop as its ASCII form (shapePunct).
func shapeForm(caser *cases.Caser, seg string) string {
	s := strings.Map(dropIgnorableOrMark, norm.NFKC.String(strings.Map(dropIgnorable, seg)))
	return strings.Map(shapePunct, strings.Map(dropIgnorableOrMark, nfkcCasefold(caser, s)))
}

// shapePunct maps, for strings.Map, a decimal digit of any script to its
// ASCII digit (asciiDigit), every dash (Pd: hyphen, non-breaking hyphen, en
// and em dash, …) and the minus sign U+2212 to '-', and the ideographic full
// stops (U+3002, U+FF0E, U+FF61), which IDNA reads as a domain's dots, to '.'.
// NFKC leaves these dashes and U+3002 alone, so a phone written with them, or
// an address with an ideographic dot, would otherwise be cut short.
func shapePunct(r rune) rune {
	switch {
	case r < utf8.RuneSelf:
		return r
	case r == minusSign || unicode.Is(unicode.Pd, r):
		return '-'
	case isFullStop(r):
		return '.'
	}
	return asciiDigit(r)
}

// minusSign is U+2212, written for '-' by some editors and locales.
const minusSign = '\u2212'

// isFullStop reports the ideographic full stops: U+3002, U+FF0E, U+FF61.
func isFullStop(r rune) bool { return r == '\u3002' || r == '\uff0e' || r == '\uff61' }

// dropIgnorableOrMark removes ignorable characters and combining marks, for
// strings.Map.
func dropIgnorableOrMark(r rune) rune {
	if isIgnorable(r) || unicode.In(r, unicode.Mn, unicode.Me) {
		return -1
	}
	return r
}

// asciiDigit maps a decimal digit of any script to its ASCII digit, for
// strings.Map. Unicode encodes every set of decimal digits as ten contiguous
// code points from zero to nine, and sets that follow each other without a
// gap are whole sets too, so the distance from the start of the run, modulo
// ten, is the digit's value.
func asciiDigit(r rune) rune {
	if r < utf8.RuneSelf || !unicode.Is(unicode.Nd, r) {
		return r
	}
	start := r
	for unicode.Is(unicode.Nd, start-1) {
		start--
	}
	return '0' + (r-start)%decimalDigits
}

// decimalDigits is how many digits a set of decimal digits holds.
const decimalDigits = 10

// original maps a span of the folded text to the original bytes it came from.
// A span that starts or ends inside a segment's folded output (one character
// can fold to several) widens to the whole segment, so it never covers less
// of the original than was found.
func (v foldedView) original(sp Span) (int, int) {
	return v.pieces[v.pieceAt(sp.Start)].orig, v.pieces[v.pieceAt(sp.End-1)+1].orig
}

// pieceAt is the index of the segment whose folded bytes hold offset i: the
// last piece starting at or before i (empty pieces start where the next one does).
func (v foldedView) pieceAt(i int) int {
	return sort.Search(len(v.pieces), func(k int) bool { return v.pieces[k].fold > i }) - 1
}
