package pii

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nyaruka/phonenumbers"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Normalize maps equal values written differently to the same text, so they
// get the same token and the same dictionary hash. Every type is NFKC first
// (full-width and other compatibility forms become their plain letters and
// digits; NFKC includes NFC); then EMAIL is trimmed and lower-cased, PHONE becomes E.164 through
// libphonenumber (phoneRegion, ISO 3166 alpha-2, is used for a number written
// without +cc), and every other type takes the generic form. The result is
// deterministic for a given Unicode version (Go's and golang.org/x/text's).
func Normalize(t EntityType, value, phoneRegion string) string {
	switch t {
	case EntityEmail:
		return normalizeEmail(value)
	case EntityPhone:
		e164, _ := normalizePhone(value, phoneRegion)
		return e164
	case EntityPersonName, EntityAddress, EntityOther:
		return GenericForm(value)
	case EntityCard:
		return cardForm(value)
	case EntityIBAN:
		return ibanForm(value)
	}
	return GenericForm(value)
}

// normalizeEmail drops ignorables, then NFKC, trims, lower-cases and NFKC
// again, and writes every dash and the minus sign as '-' and the ideographic
// full stops as '.', as the detectors see them: "a‐b@corp。ee" is
// "a-b@corp.ee" (IDNA reads the full stops as a domain's dots).
func normalizeEmail(value string) string {
	value = strings.Map(dropIgnorable, value)
	s := norm.NFKC.String(strings.ToLower(strings.TrimSpace(norm.NFKC.String(value))))
	return strings.Map(emailPunct, s)
}

// emailPunct maps a dash or the minus sign to '-' and an ideographic full stop
// to '.', for strings.Map.
func emailPunct(r rune) rune {
	switch {
	case r < utf8.RuneSelf:
		return r
	case isDash(r):
		return '-'
	case isFullStop(r):
		return '.'
	}
	return r
}

// normalizePhone returns the E.164 form and the country calling code (0 when
// the number could not be parsed: a local number with no region, or not a
// number). An unparsed value keeps a leading + and its letters and digits, so
// distinct inputs stay distinct.
func normalizePhone(value, region string) (string, int32) {
	// The shape form, as the phone detector saw it: no marks, ASCII digits.
	caser := cases.Fold()
	value = iddAsPlus(strings.TrimSpace(shapeForm(&caser, value)))
	region = strings.ToUpper(strings.TrimSpace(region))
	if e164, cc, ok := parseE164(value, region); ok {
		return e164, cc
	}
	// Parse the cleaned form too, so the fallback is stable: normalizing it
	// again takes exactly this path and gives the same text.
	clean := iddAsPlus(norm.NFKC.String(phoneFallback(value)))
	if e164, cc, ok := parseE164(clean, region); ok {
		return e164, cc
	}
	return clean, 0
}

// parseE164 accepts libphonenumber's E.164 form only when the number is
// possible and the form parses back to itself: for some impossible numbers
// (a run of zeros) libphonenumber is not idempotent, and a normal form must be.
func parseE164(value, region string) (string, int32, bool) {
	num, err := phonenumbers.Parse(value, region)
	if err != nil || num.GetCountryCode() == 0 || !phonenumbers.IsPossibleNumber(num) {
		return "", 0, false
	}
	e164 := phonenumbers.Format(num, phonenumbers.E164)
	again, err := phonenumbers.Parse(e164, "")
	if err != nil || phonenumbers.Format(again, phonenumbers.E164) != e164 {
		return "", 0, false
	}
	return e164, num.GetCountryCode(), true
}

// iddAsPlus writes a leading "00", the international prefix most of the
// world dials, as "+", so "0044 7700 900123" is the number "+44 7700 900123"
// whatever the column's region (libphonenumber reads "00" only for regions
// that dial it). It runs on the cleaned form too, where separators are gone
// ("0-0-44…"), so the fallback never starts with "00" and stays stable.
func iddAsPlus(value string) string {
	if rest, ok := strings.CutPrefix(value, iddPrefix); ok {
		return "+" + rest
	}
	return value
}

func phoneFallback(value string) string {
	var b strings.Builder
	if strings.HasPrefix(value, "+") {
		b.WriteByte('+')
	}
	for _, r := range value {
		if unicode.IsDigit(r) || unicode.IsLetter(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// GenericForm is the form names, addresses and other identifiers are compared
// in, and the form free-text word n-grams are looked up by: NFKC, Unicode case
// folding, NFKC again (folding can leave a sequence that composes), that is
// NFKC_Casefold apart from the ignorables, which are dropped next; then every
// run of characters that are not letters, digits or marks becomes one space,
// with no space at either end. Format characters (zero-width space, joiners)
// are dropped, so they neither split a word nor join two.
func GenericForm(value string) string {
	// A Caser is stateful, so each call takes its own.
	caser := cases.Fold()
	// Ignorable characters go before normalizing, not after: a format
	// character between two combining marks (combining class 0) keeps NFKC
	// from reordering them, so dropping it afterwards would leave the marks out
	// of canonical order and the next normalization would reorder them
	// ("\u07e4\u0740\u0600\u05a4").
	s := nfkcCasefold(&caser, strings.Map(dropIgnorable, value))
	var b strings.Builder
	b.Grow(len(s))
	gap := false
	for _, r := range s {
		switch {
		case unicode.IsMark(r) && (gap || b.Len() == 0):
			// A mark that follows no word character starts no word.
			gap = true
		case isWordRune(r):
			if gap && b.Len() > 0 {
				b.WriteByte(' ')
			}
			gap = false
			b.WriteRune(r)
		case isIgnorable(r):
			// None reach here (dropped above, and folding makes none); kept
			// transparent rather than a separator should that ever change.
		default:
			gap = true
		}
	}
	return b.String()
}

// isWordRune is a letter, digit or combining mark. Marks count so a mark that
// does not compose with its base (the dot of a folded 'İ') stays in its word.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
}

// nfkcCasefold is NFKC, case folding, NFKC. golang.org/x/text's folding swaps
// Cherokee upper and lower case in both directions, so folding twice would undo
// it; Unicode's CaseFolding.txt folds Cherokee to upper case, and that is
// restored here, which keeps the result stable when folded again.
func nfkcCasefold(caser *cases.Caser, s string) string {
	folded := caser.String(norm.NFKC.String(s))
	if strings.IndexFunc(folded, isCherokee) >= 0 {
		folded = strings.Map(func(r rune) rune {
			if isCherokee(r) {
				return unicode.ToUpper(r)
			}
			return r
		}, folded)
	}
	return norm.NFKC.String(folded)
}

func isCherokee(r rune) bool { return unicode.Is(unicode.Cherokee, r) }

// isIgnorable reports the characters that are dropped before anything else,
// for every type and in the text detectors see: format characters (zero-width
// space and joiners, soft hyphen, word joiner, BOM, bidi controls),
// variation selectors and the other default-ignorable code points (Hangul
// fillers, the combining grapheme joiner, the unassigned ignorable ranges).
// This is Unicode's Default_Ignorable_Code_Point, which NFKC_Casefold removes,
// plus the few format characters it leaves out. Invisible inside a value, any
// of them would otherwise split the value so no detector saw it.
func isIgnorable(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}

// dropIgnorable removes ignorable characters, for strings.Map.
func dropIgnorable(r rune) rune {
	if isIgnorable(r) {
		return -1
	}
	return r
}

// iddPrefix is the international dialing prefix most of the world writes
// instead of "+" ("0044 7700 900123").
const iddPrefix = "00"
