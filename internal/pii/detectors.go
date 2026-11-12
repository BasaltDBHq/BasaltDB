package pii

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nyaruka/phonenumbers"
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

// phoneSep is what may stand between the groups of a phone number: a run of
// up to maxPhoneSpaces spaces (the shape view writes every Unicode space as
// ' ', but a tab stays a tab, so a table row is not one number), one line
// break, or one '.', '-' or '/'. The shape view writes every dash (Pd) and the
// minus sign as '-'. separatorsOK limits a number to one line break and one
// '/'. The bound keeps every match short (maxPhoneMatchLen), so the search
// runs over short windows.
const phoneSep = `(?: {1,4}|\r\n|\n|\r|[./\-])`

// phoneWindow is how much text one phone search reads, and phoneOverlap how
// far apart two windows start from the end of the previous one: more than the
// longest match (with its follower, under 64 bytes), so a match that starts
// before the overlap ends inside its window. A short input lets Go's regexp
// use its backtracker, several times faster than its NFA over the whole text.
const (
	phoneWindow  = 1024
	phoneOverlap = 64
)

// phoneCore is a phone shape: an international prefix ("+" or "00"), the
// country code and up to five digit groups of one to four digits, or a US
// "(202) 555-0143". A group of one digit counts ("… 45 6"), so a number never
// leaves its last digit behind; a lone digit after a number ("… 456 7 items")
// is taken into the token, which only covers more.
const phoneCore = `(?:\+|00)\d{1,3}` + phoneSep + `?\(?\d{1,4}\)?(?:` + phoneSep + `?\d{1,4}){1,4}|\(\d{3}\) *\d{3}` + phoneSep + `\d{4}`

// iddPrefix is the international dialing prefix most of the world writes
// instead of "+" ("0044 7700 900123").
const iddPrefix = "00"

// The email local part (RFC 5322 dot-atoms and quoted strings, each word on
// either side of a '.' one or the other: "bob"."smith", bob."smith").
//
//   - emailFirst: what an unquoted word starts with: a letter, mark, digit or
//     one of "._%+-!#$&*^~". "'/=?`{|}" usually quote or delimit an address
//     ('bob@corp.ee', |bob@corp.ee|), so they cannot start it.
//   - emailInner: what follows, the RFC 5322 atom characters but '\”.
//   - emailApos: a '\” counts only between two letters or digits
//     (bob.o'connor), so email='bob@corp.ee' keeps its quote.
//   - emailQuoted: a quoted string of any length, any character escaped,
//     line breaks included, so no quoted local part is left whole.
//
// EmailDetector then cuts the local part after its last '=', '/', '?' or ':'
// (outside quotes): a key, a query or a path glued to an address
// (?email=bob@corp.ee, /users/bob@corp.ee) is left out of its token.
const (
	emailAlnum  = `[\p{L}\p{M}\p{N}]`
	emailFirst  = "[\\p{L}\\p{M}\\p{N}._%+\\-!#$&*^~]"
	emailInner  = "[\\p{L}\\p{M}\\p{N}._%+\\-!#$&*^~/=?`{|}]"
	emailApos   = emailAlnum + `(?:'` + emailAlnum + `)+`
	emailAtom   = `(?:` + emailFirst + `|` + emailApos + `)(?:` + emailInner + `|` + emailApos + `)*`
	emailQuoted = `"(?:[^"\\]|\\[\s\S])*"`
	emailWord   = `(?:` + emailAtom + `|` + emailQuoted + `)`
	emailLocal  = emailWord + `(?:\.` + emailWord + `)*`
)

var (
	// emailRe takes internationalized addresses: letters, marks and digits of
	// any script in the local part and the domain, and a letter or punycode
	// ("xn--") top-level domain. The local part also takes the other RFC 5322
	// atom characters and quoted strings (emailLocal). Detection runs on
	// folded text, so case does not matter. Go's regexp is RE2: a match takes
	// linear time whatever the text, so no input backtracks catastrophically.
	emailRe = regexp.MustCompile(emailLocal + `@[\p{L}\p{M}\p{N}\-]+(?:\.[\p{L}\p{M}\p{N}\-]+)*\.(?:xn--[a-z0-9\-]+|[\p{L}\p{M}]{2,})`)
	// phoneRe's group 1 is the number. It must be followed by a non-digit or
	// the end, so leftmost-first matching cannot stop inside a number written
	// without spaces; any character may follow, so a number glued to letters
	// ("x123", "ext2", "_") is still found. The follower is not part of the span.
	phoneRe = regexp.MustCompile(`(` + phoneCore + `)(?:$|[^0-9])`)
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

func (EmailDetector) shapes() {}

// Detect returns the email spans in text. A span takes in ASCII letters and
// digits glued to the end of the address ("a@corp.com2024"), so a token never
// sits against them: a token is only recognized again when nothing
// alphanumeric touches it.
func (EmailDetector) Detect(text string) []Span {
	var out []Span
	// The search goes on from the end of each widened span, so the next
	// address is matched on what is left, as a second pass would see it.
	for pos := 0; pos < len(text); {
		m := emailRe.FindStringIndex(text[pos:])
		if m == nil {
			break
		}
		end := pos + m[1]
		for asciiAlnumAt(text, end) {
			end++
		}
		start := pos + m[0]
		out = append(out, Span{Start: start + localCut(text[start:pos+m[1]]), End: end, Type: EntityEmail})
		pos = end
	}
	return out
}

// localCut is where the address in match starts: after the last '=', '/',
// '?' or ':' of its local part outside quotes, or 0. A local part that would
// be left empty is kept whole.
func localCut(match string) int {
	at := strings.LastIndexByte(match, '@')
	cut, quoted := 0, false
	for i := 0; i < at; i++ {
		switch c := match[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && strings.IndexByte("=/?:", c) >= 0:
			cut = i + 1
		}
	}
	if cut == at {
		return 0
	}
	return cut
}

// PhoneDetector finds phone numbers by shape (+cc or 00cc, or a US
// "(202) 555-0143"), known or not, with minPhoneDigits to maxPhoneDigits
// digits.
type PhoneDetector struct{}

func (PhoneDetector) shapes() {}

// Detect returns the phone spans in text. Each number is matched without the
// character that follows it, and the search goes on from the end of the
// number, so that character can start the next number ("…0143+1 202…").
func (PhoneDetector) Detect(text string) []Span {
	var out []Span
	for pos := 0; pos < len(text); {
		w := min(len(text), pos+phoneWindow)
		m := phoneRe.FindStringSubmatchIndex(text[pos:w])
		found := len(m) > 0
		if w < len(text) && (!found || pos+m[0] > w-phoneOverlap) {
			// No match that surely ends inside this window: go on from the
			// match found near its end, or from where the next window must
			// start to see every match the overlap could cut.
			next := w - phoneOverlap
			if found {
				next = pos + m[0]
			}
			pos = max(next, pos+1)
			continue
		}
		if !found {
			break
		}
		start, end := pos+m[2], pos+m[3]
		n, ok := phoneEnd(text[start:end])
		if !ok || (isIDDMatch(text[start:end]) && asciiAlnumAt(text, start-1)) || beforeDatePart(text, start+n) {
			// A match that is no phone (a date, an id, a long number), or a
			// "00" glued to letters or digits, covers no number: search again
			// from its next character, so a number inside or after it is
			// still found, as a second pass would find it once a token
			// stands before it.
			pos = start + 1
			continue
		}
		out = append(out, Span{Start: start, End: start + n, Type: EntityPhone})
		// A number cut short (more digits followed it) is followed by the
		// rest of the match, which may hold a "00" number: search on from the
		// cut, as a second pass, seeing the token there, would.
		pos = start + n
	}
	return out
}

// beforeDatePart reports a number followed by '/' and a digit, or by '/' at
// the end of the text: one part of a slash-joined run ("+12/11/2026") that
// separatorsOK turned away whole. The end of the text counts because a token
// may stand there after a first pass ("+00000000/0+00000000" leaves
// "+00000000/" before a token), so both passes agree.
func beforeDatePart(text string, end int) bool {
	return end < len(text) && text[end] == '/' && (end+1 == len(text) || isASCIIDigit(text[end+1]))
}

// isIDDMatch reports a match written with the "00" prefix instead of "+".
func isIDDMatch(match string) bool { return strings.HasPrefix(match, iddPrefix) }

// phoneEnd is the length of the longest prefix of a pattern match that is a
// phone by itself: the whole match, or, when the match holds more than
// maxPhoneDigits digits (a phone followed by another number), the longest
// prefix that ends on a digit before a separator. Keeping the prefix rather
// than dropping the match makes the result the same whether or not a token
// follows the number (a second pass over tokenized text). A "00" number is a
// digit run as often as a phone (an id, an order number), so it counts only
// when libphonenumber finds a valid number with "+" in its place, and its
// "00" counts as no digits.
func phoneEnd(match string) (int, bool) {
	idd := isIDDMatch(match)
	for end := len(match); end > 0; end-- {
		// A cut ends on a digit before a separator other than '/': a number
		// is not cut out of a date ("+30 2026/11/12").
		if end < len(match) && (!isASCIIDigit(match[end-1]) || isASCIIDigit(match[end]) || match[end] == '/') {
			continue
		}
		n := asciiDigits(match[:end])
		if idd {
			n -= len(iddPrefix)
		}
		if n > maxPhoneDigits {
			continue
		}
		if n < minPhoneDigits {
			return 0, false
		}
		if phoneWholeRe.MatchString(match[:end]) && separatorsOK(match[:end]) && (!idd || validIDD(match[:end])) {
			return end, true
		}
	}
	return 0, false
}

// separatorsOK limits what a number may hold besides spaces, dots and
// dashes: one line break (lines of figures are not one number) and one '/',
// after another separator ("+49 89/1234 5678"), so a date ("+12/11/2026",
// "+30 2026/11/12") is no phone.
func separatorsOK(number string) bool {
	breaks := strings.Count(number, "\n") + strings.Count(number, "\r") - strings.Count(number, "\r\n")
	if breaks > 1 {
		return false
	}
	slash := strings.IndexByte(number, '/')
	if slash < 0 {
		return true
	}
	return strings.Count(number, "/") == 1 && strings.ContainsAny(number[:slash], " .-\r\n()")
}

// validIDD reports whether a "00" number is a valid number with "+" in place
// of its "00". Valid, not only possible: a possible number is a matter of
// length (seven digits are a possible US number), which too many ids pass.
func validIDD(match string) bool {
	digits := asciiDigitsOf(match[len(iddPrefix):])
	if !possibleLength(digits) {
		return false
	}
	num, err := phonenumbers.Parse("+"+digits, "")
	return err == nil && phonenumbers.IsValidNumber(num)
}

// maxCountryCodeLen is the longest country calling code (E.164).
const maxCountryCodeLen = 3

// possibleLength is a cheap first check of the digits after "+": their
// country code (the first one to three digits that name one, as
// libphonenumber reads it) is known and the rest has a length that country
// dials (not only locally). It spares parsing most digit runs, so a text full
// of "00" ids (a hex dump, "0044 0044 …") stays fast. A national number
// written with its trunk '0' ("0044 020 …") is checked without it; one that
// still starts with '0' after that is none.
func possibleLength(digits string) bool {
	for n := 1; n <= min(maxCountryCodeLen, len(digits)-1); n++ {
		cc, err := strconv.ParseInt(digits[:n], 10, 32)
		if err != nil || phonenumbers.GetRegionCodeForCountryCode(int(cc)) == phonenumbers.UNKNOWN_REGION {
			continue
		}
		national := strings.TrimPrefix(digits[n:], "0")
		if national == "" || national[0] == '0' {
			return false
		}
		nn, err := strconv.ParseUint(national, 10, 64)
		if err != nil {
			return false
		}
		cc32 := int32(cc)
		reason := phonenumbers.IsPossibleNumberWithReason(&phonenumbers.PhoneNumber{CountryCode: &cc32, NationalNumber: &nn})
		return reason == phonenumbers.IS_POSSIBLE
	}
	return false
}

// asciiDigitsOf is s without everything but its ASCII digits.
func asciiDigitsOf(s string) string {
	var b strings.Builder
	for i := range len(s) {
		if isASCIIDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
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
	// Contains reports whether a typed-form hash (Keys.TypedHash) is known for
	// t. The tokenizer finds emails and phones by shape whether known or not;
	// basalt classify --check and the engine use the typed form.
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
		out = append(out, Span{Start: phoneStart(text, ws[i].start, typ), End: ws[i+n-1].end, Type: typ})
		i += n
	}
	return out
}

// phoneStart widens a PHONE hit over the '+' written before it. Words hold
// no '+', so the n-gram "1 202 555 0143" starts after it; taken in, the value
// is "+1 202 555 0143", which normalizes to the same E.164 number as the
// phone detector's match, so both give one token (with its "+1 " prefix) and
// no '+' is left behind.
func phoneStart(text string, start int, typ EntityType) int {
	if typ == EntityPhone && start > 0 && text[start-1] == '+' {
		return start - 1
	}
	return start
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
// space, joiners) continue a word, matching GenericForm, which drops them. A
// combining mark continues a word but never starts one, as in GenericForm: a
// spacing accent ("\u00a8") folds to a space and a mark, and the mark must
// not stick to the next name.
func splitWords(s string) []word {
	var ws []word
	start := -1
	for i, r := range s {
		inWord := isWordRune(r) || isIgnorable(r)
		if start < 0 && unicode.IsMark(r) {
			inWord = false
		}
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
