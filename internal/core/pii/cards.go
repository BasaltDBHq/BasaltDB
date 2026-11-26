package pii

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

// ibanCountry is the length of an IBAN's country code.
const ibanCountry = 2

// cardForm is the normal form of a CARD: its ASCII digits alone, after the
// shape view (so digits of any script count), whatever separates them.
func cardForm(value string) string {
	caser := cases.Fold()
	return strings.Map(keepASCIIDigit, shapeForm(&caser, value))
}

// ibanForm is the normal form of an IBAN: its letters and digits alone, in
// upper case, after the shape view.
func ibanForm(value string) string {
	caser := cases.Fold()
	return strings.ToUpper(strings.Map(keepASCIIAlnum, shapeForm(&caser, value)))
}

func keepASCIIDigit(r rune) rune {
	if r < utf8.RuneSelf && isASCIIDigit(byte(r)) {
		return r
	}
	return -1
}

func keepASCIIAlnum(r rune) rune {
	if r < utf8.RuneSelf && isASCIIAlnum(byte(r)) {
		return r
	}
	return -1
}

// tokenType is the type a value is tokenized as: an OTHER value written only
// with digits, spaces and dashes that is a valid card number is a CARD, and
// one written only with letters, digits, spaces and dashes that is a valid
// IBAN is an IBAN, so a card or IBAN stored in an OTHER column gets the token
// the patterns give it in text, however either is spaced. Every other value
// keeps t.
func tokenType(t EntityType, value string) EntityType {
	if t != EntityOther {
		return t
	}
	caser := cases.Fold()
	bare := strings.Map(dropSeparator, strings.TrimSpace(shapeForm(&caser, value)))
	switch {
	case bare == strings.Map(keepASCIIDigit, bare) && ValidCardNumber(bare):
		return EntityCard
	case bare == strings.Map(keepASCIIAlnum, bare) && ValidIBAN(bare):
		return EntityIBAN
	}
	return t
}

// dropSeparator removes spaces and dashes, for strings.Map.
func dropSeparator(r rune) rune {
	if r == ' ' || r == '-' {
		return -1
	}
	return r
}
