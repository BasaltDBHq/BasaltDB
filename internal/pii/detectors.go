package pii

import (
	"regexp"
	"unicode"
	"unicode/utf8"
)

// minPhoneDigits and maxPhoneDigits bound what the phone pattern accepts
// (E.164 allows at most 15 digits).
const (
	minPhoneDigits = 8
	maxPhoneDigits = 15
)

// maxNGram is the longest word n-gram looked up in the dictionary.
const maxNGram = 4

// maxSeparatorLen is the longest run of non-word characters (in runes) allowed
// between the words of one n-gram ("Alice Tamm", "Tamm, Alice", `"Alice","Tamm"`).
const maxSeparatorLen = 3

// phoneCore is a phone shape: +cc and up to five digit groups, or a US
// "(202) 555-0143".
const phoneCore = `\+\d{1,3}[ .\-]?\(?\d{1,4}\)?(?:[ .\-]?\d{2,4}){1,4}|\(\d{3}\) ?\d{3}[ .\-]\d{4}`

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
	// phoneRe ends on a word boundary: without it, leftmost-first matching
	// stops inside a number written without spaces and leaves its last digits.
	phoneRe = regexp.MustCompile(`(?:` + phoneCore + `)\b`)
	// phoneWholeRe checks that a cut-down match is still a phone by itself.
	phoneWholeRe = regexp.MustCompile(`^(?:` + phoneCore + `)$`)
)

// commonWords are single words that are also names or ordinary words; a
// dictionary value that is one of them is matched only inside a longer n-gram
// (the design's common-word rule), so ordinary sentences are not garbled.
var commonWords = map[string]bool{
	"will": true, "may": true, "rose": true, "june": true, "april": true, "mark": true,
	"bill": true, "grace": true, "hope": true, "joy": true, "faith": true, "art": true,
	"amber": true, "summer": true, "dawn": true, "max": true, "page": true, "lane": true,
}

// PatternDetectors are the shape detectors, in the order they must run:
// emails, then phones. Phones run on what emails left, so a number inside an
// address is never cut out of it, and a second pass over tokenized text sees
// the same stretches the first did.
func PatternDetectors() []Detector { return []Detector{EmailDetector{}, PhoneDetector{}} }

// EmailDetector finds email addresses by shape, known or not.
type EmailDetector struct{}

// Detect returns the email spans in text.
func (EmailDetector) Detect(text string) []Span {
	matches := emailRe.FindAllStringIndex(text, -1)
	out := make([]Span, 0, len(matches))
	for _, m := range matches {
		out = append(out, Span{Start: m[0], End: m[1], Type: EntityEmail})
	}
	return out
}

// PhoneDetector finds phone numbers by shape (+cc, or a US "(202) 555-0143"),
// known or not, with minPhoneDigits to maxPhoneDigits digits.
type PhoneDetector struct{}

// Detect returns the phone spans in text.
func (PhoneDetector) Detect(text string) []Span {
	var out []Span
	for _, m := range phoneRe.FindAllStringIndex(text, -1) {
		if end, ok := phoneEnd(text[m[0]:m[1]]); ok {
			out = append(out, Span{Start: m[0], End: m[0] + end, Type: EntityPhone})
		}
	}
	return out
}

// phoneEnd is the length of the longest prefix of a pattern match that is a
// phone by itself: the whole match, or, when the match holds more than
// maxPhoneDigits digits (a phone followed by another number), the longest
// prefix that ends on a digit before a separator. Keeping the prefix rather
// than dropping the match makes the result the same whether or not a token
// follows the number (a second pass over tokenized text).
func phoneEnd(match string) (int, bool) {
	for end := len(match); end > 0; end-- {
		if end < len(match) && (!isASCIIDigit(match[end-1]) || isASCIIDigit(match[end])) {
			continue
		}
		n := asciiDigits(match[:end])
		if n > maxPhoneDigits {
			continue
		}
		if n < minPhoneDigits {
			return 0, false
		}
		if phoneWholeRe.MatchString(match[:end]) {
			return end, true
		}
	}
	return 0, false
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func asciiDigits(s string) int {
	n := 0
	for i := range len(s) {
		if isASCIIDigit(s[i]) {
			n++
		}
	}
	return n
}

// Dictionary is what the dictionary detector looks hashes up in: the engine's
// keyed-hash dictionary of known values. Implementations must be safe for
// concurrent use.
type Dictionary interface {
	// Lookup finds a generic-form hash (Keys.GenericHash) and returns its type.
	Lookup(h Hash) (EntityType, bool)
	// Contains reports whether a typed-form hash (Keys.TypedHash) is known for t.
	Contains(t EntityType, h Hash) bool
}

// DictionaryDetector finds known values in free text: word n-grams (up to
// maxNGram words) whose generic form is in the dictionary, longest first.
type DictionaryDetector struct {
	keys        *Keys
	dict        Dictionary
	phoneRegion string
}

// NewDictionaryDetector returns a detector over dict, hashing with keys.
func NewDictionaryDetector(keys *Keys, dict Dictionary, phoneRegion string) *DictionaryDetector {
	if keys == nil || dict == nil {
		panic("pii.NewDictionaryDetector: keys and dictionary required")
	}
	return &DictionaryDetector{keys: keys, dict: dict, phoneRegion: phoneRegion}
}

// Detect returns the dictionary n-gram hits in text.
func (d *DictionaryDetector) Detect(text string) []Span {
	ws := splitWords(text)
	var out []Span
	for i := 0; i < len(ws); {
		n, typ := d.longestHit(text, ws, i)
		if n == 0 {
			i++
			continue
		}
		out = append(out, Span{Start: ws[i].start, End: ws[i+n-1].end, Type: typ})
		i += n
	}
	return out
}

// FinalScan counts known values still in text, outside existing tokens:
// n-gram hits plus email and phone patterns whose typed form is in the
// dictionary. Run on tokenized text it must be zero; anything else means a
// value would leave, and the caller fails closed.
func (d *DictionaryDetector) FinalScan(text string) int {
	hits := 0
	for _, seg := range freeSegments(len(text), existingTokens(text)) {
		part := text[seg.Start:seg.End]
		hits += len(d.Detect(part))
		hits += d.typedHits(part, emailRe, EntityEmail)
		hits += d.typedHits(part, phoneRe, EntityPhone)
	}
	return hits
}

func (d *DictionaryDetector) typedHits(text string, re *regexp.Regexp, t EntityType) int {
	hits := 0
	for _, m := range re.FindAllString(text, -1) {
		if d.dict.Contains(t, d.keys.TypedHash(t, m, d.phoneRegion)) {
			hits++
		}
	}
	return hits
}

func (d *DictionaryDetector) longestHit(text string, ws []word, i int) (int, EntityType) {
	for n := min(maxNGram, len(ws)-i); n >= 1; n-- {
		if !tightlyJoined(text, ws[i:i+n]) {
			continue
		}
		form := GenericForm(text[ws[i].start:ws[i+n-1].end])
		// An empty form (only format characters) is never a value.
		if form == "" || (n == 1 && commonWords[form]) {
			continue
		}
		if typ, ok := d.dict.Lookup(d.keys.hash(genericHashPrefix + form)); ok {
			return n, typ
		}
	}
	return 0, ""
}

type word struct{ start, end int }

// splitWords finds runs of word characters. Format characters (zero-width
// space, joiners) continue a word, matching GenericForm, which drops them.
func splitWords(s string) []word {
	var ws []word
	start := -1
	for i, r := range s {
		inWord := isWordRune(r) || unicode.Is(unicode.Cf, r)
		switch {
		case inWord && start < 0:
			start = i
		case !inWord && start >= 0:
			ws = append(ws, word{start, i})
			start = -1
		}
	}
	if start >= 0 {
		ws = append(ws, word{start, len(s)})
	}
	return ws
}

func tightlyJoined(s string, ws []word) bool {
	for j := 1; j < len(ws); j++ {
		if utf8.RuneCountInString(s[ws[j-1].end:ws[j].start]) > maxSeparatorLen {
			return false
		}
	}
	return true
}
