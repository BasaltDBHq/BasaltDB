package pii

import "strings"

// cardGroup is the digit group of a card number written in groups
// ("4111 1111 1111 1111", "4111-1111-1111-1111").
const cardGroup = 4

// maxCardGroups is the most groups a grouped card number has: four of four
// digits and a last of up to three (19 digits).
const maxCardGroups = 5

// The American Express and Diners Club layouts: 4-6-5 and 4-6-4.
const (
	cardWideGroup   = 6
	amexLastGroup   = 5
	dinersLastGroup = 4
)

// CardDetector finds payment card numbers by shape: 13 to 19 digits, written
// without separators or in groups split by one space or one dash (the same one
// throughout: 4-4-4-4, 4-4-4-4-3, 4-4-4-1, or 4-6-5 and 4-6-4), that pass
// ValidCardNumber (a known issuer range and the Luhn check). A run of more
// than 19 digits is an id, not a card. Every card is an OTHER span, so it gets
// a pii1_ token; card columns are SECRET (M51-6) and never reach the
// dictionary, so in free text this pattern is the only defense.
type CardDetector struct{}

func (CardDetector) shapes() {}

// Detect returns the card spans in text. No ASCII letter or digit may touch a
// number on either side, so a run of hex ("a4111111111111111f") is no card. A
// number right after a '+' with at most 15 digits is a phone's to take
// ("+4915112345678"), not a card's.
func (CardDetector) Detect(text string) []Span {
	var out []Span
	for i := 0; i < len(text); i++ {
		if !isASCIIDigit(text[i]) || asciiAlnumAt(text, i-1) {
			continue
		}
		n := cardAt(text[i:])
		if n == 0 || (i > 0 && text[i-1] == '+' && asciiDigits(text[i:i+n]) <= maxPhoneDigits) {
			continue
		}
		out = append(out, Span{Start: i, End: i + n, Type: EntityOther})
		i += n - 1
	}
	return out
}

// cardAt is the length of the card number at the start of s, or 0.
func cardAt(s string) int {
	first := digitRun(s)
	if first >= minCardDigits && first <= maxCardDigits && !asciiAlnumAt(s, first) && ValidCardNumber(s[:first]) {
		return first
	}
	if first != cardGroup || len(s) <= first || (s[first] != ' ' && s[first] != '-') {
		return 0
	}
	return groupedCardAt(s, s[first])
}

// groupedCardAt is the length of the grouped card number at the start of s,
// with groups split by sep, or 0. It reads up to maxCardGroups groups and takes
// the longest run of them that is a card layout and a valid number, so a card
// followed by more digits ("4111 1111 1111 1111 22") is still found.
func groupedCardAt(s string, sep byte) int {
	var lens, ends []int
	digits := 0
	for pos := 0; len(lens) < maxCardGroups; {
		n := digitRun(s[pos:])
		if n == 0 {
			break
		}
		lens = append(lens, n)
		digits += n
		ends = append(ends, pos+n)
		pos += n
		if digits > maxCardDigits || pos+1 >= len(s) || s[pos] != sep || !isASCIIDigit(s[pos+1]) {
			break
		}
		pos++
	}
	for k := len(lens); k > 0; k-- {
		if !cardLayout(lens[:k]) || asciiAlnumAt(s, ends[k-1]) {
			continue
		}
		if ValidCardNumber(stripSeparator(s[:ends[k-1]], sep)) {
			return ends[k-1]
		}
	}
	return 0
}

// cardLayout reports a layout cards are written in: groups of four and a last
// group of one to four, 13 to 19 digits in all; or 4-6-5 and 4-6-4.
func cardLayout(lens []int) bool {
	total := 0
	for _, n := range lens {
		total += n
	}
	if total < minCardDigits || total > maxCardDigits {
		return false
	}
	if len(lens) == 3 && lens[0] == cardGroup && lens[1] == cardWideGroup &&
		(lens[2] == amexLastGroup || lens[2] == dinersLastGroup) {
		return true
	}
	for _, n := range lens[:len(lens)-1] {
		if n != cardGroup {
			return false
		}
	}
	return lens[len(lens)-1] <= cardGroup
}

// digitRun is the number of ASCII digits s starts with.
func digitRun(s string) int {
	n := 0
	for n < len(s) && isASCIIDigit(s[n]) {
		n++
	}
	return n
}

func stripSeparator(s string, sep byte) string {
	return strings.ReplaceAll(s, string(sep), "")
}

// ibanCountry is the length of an IBAN's country code.
const ibanCountry = 2

// IBANDetector finds IBANs by shape: a country code with IBANs, two check
// digits, then letters and digits up to that country's IBAN length, written
// without spaces or in groups of four split by one space, in any case, that
// pass ValidIBAN (mod-97). No ASCII letter or digit may touch it on either
// side. IBANs are OTHER spans (M5.1 plan, section 1).
type IBANDetector struct{}

func (IBANDetector) shapes() {}

// Detect returns the IBAN spans in text.
func (IBANDetector) Detect(text string) []Span {
	var out []Span
	for i := 0; i+ibanHead <= len(text); i++ {
		if !isASCIILetter(text[i]) || asciiAlnumAt(text, i-1) {
			continue
		}
		n := ibanAt(text[i:])
		if n == 0 {
			continue
		}
		out = append(out, Span{Start: i, End: i + n, Type: EntityOther})
		i += n - 1
	}
	return out
}

// ibanAt is the length of the IBAN at the start of s, or 0. A space may stand
// after every fourth character, never twice in a row or at the end.
func ibanAt(s string) int {
	want := IBANLength(s[:ibanCountry])
	if want == 0 {
		return 0
	}
	var b strings.Builder
	pos := 0
	for b.Len() < want && pos < len(s) {
		c := s[pos]
		if c == ' ' && b.Len()%cardGroup == 0 && b.Len() > 0 && pos+1 < len(s) && isASCIIAlnum(s[pos+1]) {
			pos++
			continue
		}
		if !isASCIIAlnum(c) {
			return 0
		}
		b.WriteByte(c)
		pos++
	}
	if b.Len() < want || asciiAlnumAt(s, pos) || !ValidIBAN(b.String()) {
		return 0
	}
	return pos
}
