package pii

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

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
	case isDash(r):
		return '-'
	case isFullStop(r):
		return '.'
	}
	return asciiDigit(r)
}

// minusSign is U+2212, written for '-' by some editors and locales.
const minusSign = '\u2212'

// isDash reports a dash (Pd) or the minus sign.
func isDash(r rune) bool { return r == minusSign || unicode.Is(unicode.Pd, r) }

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
