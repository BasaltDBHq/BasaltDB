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
const phoneCore = `(?:\+|00)\d{1,3}` + phoneSep + `?\(?\d{1,4}\)?(?:` + phoneSep + `?\d{1,4}){1,4}|\(\d{3}\) {0,4}\d{3}` + phoneSep + `\d{4}`

// iddPrefix is the international dialing prefix most of the world writes
// instead of "+" ("0044 7700 900123").
const iddPrefix = "00"

// The email local part (RFC 5322 dot-atoms and quoted strings, each word on
// either side of a '.' one or the other: "bob"."smith", bob."smith").
//
//   - emailFirst: what an unquoted word starts with: a letter, mark, digit or
//     one of "._%+-!#$&*^~". "'/=?`{|}" usually quote or delimit an address
//     ('bob@corp.ee', |bob@corp.ee|), so they cannot start it.
//   - emailInner: what follows, the RFC 5322 atom characters but the
//     apostrophe.
//   - emailApos: an apostrophe, or two (SQL's escaped one: o”connor), counts
//     only after a letter or digit, and before one or at the end of the
//     word (bob.o'connor, bob'@corp.ee), so email='bob@corp.ee' keeps its
//     quote.
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
	emailApos   = emailAlnum + `(?:''?` + emailAlnum + `)*''?`
	emailAtom   = `(?:` + emailFirst + `|` + emailApos + `)(?:` + emailInner + `|` + emailApos + `)*`
	emailQuoted = `"(?:[^"\\]|\\[\s\S])*"`
	emailWord   = `(?:` + emailAtom + `|` + emailQuoted + `)`
	emailLocal  = emailWord + `(?:\.` + emailWord + `)*` + emailComment + `?`
	// emailComment is an RFC 5322 comment right before the '@'
	// (bob(work)@corp.ee); it goes into the token.
	emailComment = `(?:\([^()\r\n]{0,64}\))`
	// emailDomain is a host name with a letter or punycode ("xn--") top-level
	// domain, or an address literal (admin@[192.168.0.10], [ipv6:…]).
	emailDomain = `(?:[\p{L}\p{M}\p{N}\-]+(?:\.[\p{L}\p{M}\p{N}\-]+)*\.(?:xn--[a-z0-9\-]+|[\p{L}\p{M}]{2,})|\[[\p{L}\p{N}.:\-]{1,64}\])`
)

var (
	// emailRe takes internationalized addresses: letters, marks and digits of
	// any script in the local part and the domain, and a letter or punycode
	// ("xn--") top-level domain. The local part also takes the other RFC 5322
	// atom characters and quoted strings (emailLocal). Detection runs on
	// folded text, so case does not matter. Go's regexp is RE2: a match takes
	// linear time whatever the text, so no input backtracks catastrophically.
	emailRe = regexp.MustCompile(emailLocal + `@` + emailDomain)
	// phoneRe's group 1 is the number. It must be followed by a non-digit or
	// the end, so leftmost-first matching cannot stop inside a number written
	// without spaces; any character may follow, so a number glued to letters
	// ("x123", "ext2", "_") is still found. The follower is not part of the span.
	phoneRe = regexp.MustCompile(`(` + phoneCore + `)(?:$|[^0-9])`)
	// phoneWholeRe checks that a cut-down match is still a phone by itself.
	phoneWholeRe = regexp.MustCompile(`^(?:` + phoneCore + `)$`)
)

// PatternDetectors are the shape detectors, in the order they must run:
// emails, IBANs, cards, then phones. Each runs on what the earlier ones left,
// so a number inside an address is never cut out of it, an IBAN group that
// looks like a phone ("DE89 3704 0044 0532 0130 00") stays in its IBAN, and a
// card after a country code ("+1 4111 1111 1111 1111") is not cut into a phone
// and a leftover group. Cards and IBANs touch no ASCII letter or digit, so
// they take nothing a phone glued to them would need. A second pass over
// tokenized text sees the same stretches the first did.
func PatternDetectors() []Detector {
	return []Detector{EmailDetector{}, IBANDetector{}, CardDetector{}, PhoneDetector{}}
}

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
		start += localCut(text[start : pos+m[1]])
		if isGitRemote(text, start, pos+m[1]) {
			pos = end
			continue
		}
		out = append(out, Span{Start: start, End: end, Type: EntityEmail})
		pos = end
	}
	return out
}

// gitUser is the user of an SSH git remote (git@github.com:org/repo.git).
const gitUser = "git@"

// isGitRemote reports an SSH git remote rather than an address: the user
// "git", and the host followed by ':' and a path. "git" names no person, and
// rewriting remotes would break every repository an agent works in.
func isGitRemote(text string, start, end int) bool {
	return strings.HasPrefix(text[start:end], gitUser) && end+1 < len(text) && text[end] == ':' &&
		!unicode.IsSpace(rune(text[end+1]))
}

// localCut is where the address in match starts: after the last '=', '/',
// '?' or ':' of its local part outside quotes and comments, or 0. A local
// part that would be left empty is kept whole.
func localCut(match string) int {
	at := strings.LastIndexByte(match, '@')
	cut, quoted, comment := 0, false, false
	for i := 0; i < at; i++ {
		switch c := match[i]; {
		case quoted && c == '\\':
			i++
		case !comment && c == '"':
			quoted = !quoted
		case !quoted && (c == '(' || c == ')'):
			comment = c == '('
		case !quoted && !comment && strings.IndexByte("=/?:", c) >= 0:
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
	prevEnd := -1
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
		evidence := func(n int) bool { return plusNumberIsAPhone(text, start, start+n) }
		n, ok := phoneEnd(text[start:end], end < len(text) && text[end] == '/', evidence)
		if !ok || (isIDDMatch(text[start:end]) && asciiAlnumAt(text, start-1)) || gluedToANumber(text, start, start+n, prevEnd) {
			// A match that is no phone (a date, an id, a long number), or a
			// "00" glued to letters or digits, covers no number: search again
			// from its next character, so a number inside or after it is
			// still found, as a second pass would find it once a token
			// stands before it.
			pos = start + 1
			continue
		}
		out = append(out, Span{Start: start, End: start + n, Type: EntityPhone})
		prevEnd = start + n
		// A number cut short (more digits followed it) is followed by the
		// rest of the match, which may hold a "00" number: search on from the
		// cut, as a second pass, seeing the token there, would.
		pos = start + n
	}
	return out
}

// gluedToANumber reports a "+" number written without separators right after
// a digit, or after a '.' that follows a digit, as in a version's build
// metadata (1.0.0+20130313144700). After a word ("Tel.+44…", "Nr.+49…") it is
// a phone. So is one where only letters and digits, and then maybe a '.',
// stand between it and the phone before it ("+447700900456+447700900457",
// "+44…456.+44…"): that phone's token takes the letters and digits in, so a
// second pass sees this number right after the token. prevEnd is where the
// phone before ends, or -1.
func gluedToANumber(text string, start, end, prevEnd int) bool {
	if start == 0 || text[start] != '+' || asciiDigits(text[start:end]) != end-start-1 {
		return false
	}
	before := start
	if text[start-1] == '.' {
		before--
	}
	if before == 0 || !isASCIIDigit(text[before-1]) {
		return false
	}
	return prevEnd < 0 || prevEnd > before || !allASCIIAlnum(text[prevEnd:before])
}

func allASCIIAlnum(s string) bool {
	for i := range len(s) {
		if !isASCIIAlnum(s[i]) {
			return false
		}
	}
	return true
}

// plusNumberIsAPhone reports whether the number at text[start:end] has the
// evidence a "+" number needs to be a phone (owner decision EV-1): its digits
// are a valid number, as libphonenumber reads them, or a possible one with a
// phone word next to it (hasPhoneWordNear). Shape alone took signed figures
// for phones ("score +12 3456 7890 points"). Numbers written with "00" or in
// the US form are not "+" numbers and need no more evidence than their shape.
// The check reads only the text around the number up to the claimed spans on
// either side, and a second pass claims more of that text, never less, so it
// rejects what the first one did.
func plusNumberIsAPhone(text string, start, end int) bool {
	if text[start] != '+' {
		return true
	}
	num, err := phonenumbers.Parse("+"+asciiDigitsOf(text[start:end]), "")
	if err != nil || !phonenumbers.IsPossibleNumber(num) {
		return false
	}
	return phonenumbers.IsValidNumber(num) || hasPhoneWordNear(text, start, end)
}

// phoneWords are words that mark a number next to them as a phone, in English
// and Indonesian, lower case (the shape view folds case).
var phoneWords = map[string]bool{
	"tel": true, "telp": true, "telephone": true, "telepon": true, "phone": true, "phones": true,
	"ph": true, "mobile": true, "mob": true, "cell": true, "cellphone": true, "hp": true,
	"handphone": true, "ponsel": true, "wa": true, "whatsapp": true, "call": true, "fax": true,
	"sms": true, "hubungi": true,
}

// Where hasPhoneWordNear looks for a phone word: the phoneWordsBefore nearest
// words in the phoneWordReachBefore bytes before a number, and the first word
// in the phoneWordReachAfter bytes after it. A word is a run of ASCII letters;
// digits and punctuation between are skipped, so a label still counts across
// a list of numbers ("phones: +44 …, +44 …") or a JSON key ("phone_number":).
// The reach bounds the work per number.
const (
	phoneWordsBefore     = 3
	phoneWordReachBefore = 64
	phoneWordReachAfter  = 32
)

// hasPhoneWordNear reports a phone word next to the number at text[start:end]
// ("tel +44 …", "call me at +44 …", "+44 … (WA)").
func hasPhoneWordNear(text string, start, end int) bool {
	before := letterWords(text[max(0, start-phoneWordReachBefore):start])
	for i := len(before) - 1; i >= 0 && i >= len(before)-phoneWordsBefore; i-- {
		if phoneWords[before[i]] {
			return true
		}
	}
	after := letterWords(text[end:min(len(text), end+phoneWordReachAfter)])
	return len(after) > 0 && phoneWords[after[0]]
}

// letterWords are the runs of ASCII letters in s, in order.
func letterWords(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') })
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
// with a separator in it and when its length is one its country dials
// (possibleIDD), and its "00" counts as no digits. A number whose only
// separator is one '.' is a signed decimal (+48.858370), not a phone. A "+"
// number also needs evidence (plusNumberIsAPhone), told by evidence for the
// prefix of each length; a prefix without it is passed over for a shorter
// one, so a phone followed by a lone group ("+1 202 555 0143 99") is still
// found, without the group. slashNext says a '/' follows the match.
func phoneEnd(match string, slashNext bool, evidence func(n int) bool) (int, bool) {
	idd := isIDDMatch(match)
	for end := len(match); end > 0; end-- {
		// A cut ends on a digit before a separator, and before a '/' only
		// when no '/' comes earlier: a number is not cut out of a date
		// ("+30 2026/11/12"), but "+44 20 7946 0958/12/26" keeps its number.
		if end < len(match) && (!isASCIIDigit(match[end-1]) || isASCIIDigit(match[end])) {
			continue
		}
		if slashAfterSlash(match[:end], (end < len(match) && match[end] == '/') || (end == len(match) && slashNext)) {
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
		if phoneWholeRe.MatchString(match[:end]) && separatorsOK(match[:end]) && !isDecimal(match[:end]) && (!idd || possibleIDD(match[:end])) && evidence(end) {
			return end, true
		}
	}
	return 0, false
}

// slashAfterSlash reports a number that holds a '/' and ends right before
// another: a part of a slash-joined run. Whether the second '/' is inside the
// match or follows it does not matter, so a second pass, which sees a token
// after the '/' rather than digits, decides the same.
func slashAfterSlash(number string, slashNext bool) bool {
	return slashNext && strings.IndexByte(number, '/') >= 0
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

// minDottedPhoneDigits is how many digits a number written with one '.' needs
// to be a phone rather than a signed decimal: a coordinate has up to eight
// (+48.858370, possible for Poland), a phone with its country code ten or
// more (+44.7700900123, +1.2025550143).
const minDottedPhoneDigits = 10

// isDecimal reports a signed decimal: a number whose one separator is a
// single '.', and whose digits are too few for a phone or, read after "+",
// no possible number (+48.858370, +0.00012345). Otherwise it is a phone
// written with a dot (+44.7700900123).
func isDecimal(number string) bool {
	if !isDotted(number) {
		return false
	}
	digits := asciiDigitsOf(strings.TrimPrefix(number, iddPrefix))
	return len(digits) < minDottedPhoneDigits || !possibleLength(digits)
}

// isDotted reports a number whose one separator is a single '.'.
func isDotted(number string) bool {
	seps := strings.Map(func(r rune) rune {
		if r == '+' || isASCIIDigit(byte(r)) {
			return -1
		}
		return r
	}, number)
	return seps == "."
}

// possibleIDD reports whether a "00" number holds a separator (a run of
// digits starting "00" is an id: 00491711234567) and is a possible number
// with "+" in place of its "00". Possible, not valid, so a number in a range
// libphonenumber does not list (0044 7700 900123) is found as its "+" form is.
func possibleIDD(match string) bool {
	rest := match[len(iddPrefix):]
	digits := asciiDigitsOf(rest)
	return len(digits) < len(rest) && possibleLength(digits)
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

// Detect returns the dictionary n-gram hits in text. Without the original
// text it cannot see capitals, so a single common word is matched only after
// a title (nameCue); the tokenizer calls detectView instead.
func (d *DictionaryDetector) Detect(text string) []Span {
	return d.detect(text, func(int, int) bool { return false })
}

// detectView is Detect over the folded view of orig, reading capitals from
// orig: a word is capitalized when the first letter it came from is upper or
// title case.
func (d *DictionaryDetector) detectView(view foldedView, orig string) []Span {
	return d.detect(view.text, func(start, end int) bool {
		from, to := view.original(Span{Start: start, End: end})
		return startsWithCapital(orig[from:to])
	})
}

// startsWithCapital reports whether the first letter of s is upper or title case.
func startsWithCapital(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return unicode.IsUpper(r) || unicode.IsTitle(r)
		}
	}
	return false
}

// detect finds the hits in text (folded); capital reports whether the word at
// [start, end) of text is capitalized in the original.
func (d *DictionaryDetector) detect(text string, capital func(start, end int) bool) []Span {
	ws := splitWords(text)
	var out []Span
	for i := 0; i < len(ws); {
		n, typ := d.longestHit(text, ws, i, capital)
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

func (d *DictionaryDetector) longestHit(text string, ws []word, i int, capital func(start, end int) bool) (int, EntityType) {
	for n := min(maxNGram, len(ws)-i); n >= 1; n-- {
		if !tightlyJoined(text, ws[i:i+n]) {
			continue
		}
		form := GenericForm(text[ws[i].start:ws[i+n-1].end])
		// An empty form (only format characters) is never a value. A single
		// common word is one only with a name cue.
		if form == "" || (n == 1 && isCommonWord(form) && !nameCue(text, ws, i, capital)) {
			continue
		}
		if typ, ok := d.dict.Lookup(d.keys.hash(genericHashPrefix + form)); ok {
			return n, typ
		}
	}
	return 0, ""
}

// nameTitles are the titles that make the word after them a name ("Mr.
// Brown"), in generic form.
var nameTitles = map[string]bool{"mr": true, "mrs": true, "ms": true, "dr": true, "prof": true}

// nameCue reports whether the single common word ws[i] reads as a name
// (owner decisions, PT-10, provisional): a title comes right before it
// ("Mr. Brown", "dr hope"), or it is capitalized and does not start a
// sentence ("ask Hope about it"). A word that starts a sentence ("Price
// called") is not one: the text gives no sign. The start of the text the
// detector sees counts as a sentence start, so a second pass, which sees the
// text cut at the tokens of the first, decides as the first did.
func nameCue(text string, ws []word, i int, capital func(start, end int) bool) bool {
	if i > 0 && nameTitles[text[ws[i-1].start:ws[i-1].end]] && titleGap(text[ws[i-1].end:ws[i].start]) {
		return true
	}
	return capital(ws[i].start, ws[i].end) && !sentenceStart(text[:ws[i].start])
}

// titleGap reports whether gap may stand between a title and a name: an
// optional '.', then one to three spaces.
func titleGap(gap string) bool {
	gap = strings.TrimPrefix(gap, ".")
	return gap != "" && len(gap) <= maxSeparatorLen && strings.Trim(gap, " ") == ""
}

// sentenceOpeners are what may stand between a sentence end and its first
// word: spaces, quotes and opening brackets.
const sentenceOpeners = " \t\"'([{«“‘*_"

// sentenceStart reports whether a word after before starts a sentence: before
// is empty or ends in '.', '!', '?' or a line break, once spaces, quotes and
// opening brackets are trimmed.
func sentenceStart(before string) bool {
	before = strings.TrimRight(before, sentenceOpeners)
	if before == "" {
		return true
	}
	return strings.ContainsRune(".!?\n\r", rune(before[len(before)-1]))
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
