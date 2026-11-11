package pii

import (
	"strings"
	"unicode"

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
	}
	return GenericForm(value)
}

func normalizeEmail(value string) string {
	return norm.NFKC.String(strings.ToLower(strings.TrimSpace(norm.NFKC.String(value))))
}

// normalizePhone returns the E.164 form and the country calling code (0 when
// the number could not be parsed: a local number with no region, or not a
// number). An unparsed value keeps a leading + and its letters and digits, so
// distinct inputs stay distinct.
func normalizePhone(value, region string) (string, int32) {
	value = strings.TrimSpace(norm.NFKC.String(value))
	region = strings.ToUpper(strings.TrimSpace(region))
	if e164, cc, ok := parseE164(value, region); ok {
		return e164, cc
	}
	// Parse the cleaned form too, so the fallback is stable: normalizing it
	// again takes exactly this path and gives the same text.
	clean := phoneFallback(value)
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
	s := nfkcCasefold(&caser, value)
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
		case unicode.Is(unicode.Cf, r):
			// Transparent: neither a word character nor a separator.
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
