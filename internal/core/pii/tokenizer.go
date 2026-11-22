package pii

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Span is a piece of text a detector found: byte offsets [Start, End) into the
// text it was given, and the entity type of the value there.
type Span struct {
	Start, End int
	Type       EntityType
}

// Detector finds PII in text. Detectors only find spans; the tokenizer makes
// every token, so a third-party detector (the M5.3 plugin port) never sees a
// key or chooses a token. Detect must be safe for concurrent use.
type Detector interface {
	Detect(text string) []Span
}

// Replacement is one value the tokenizer replaced: byte offsets [Start, End)
// into the input of Tokenize, and the token that replaced it. It holds no value.
type Replacement struct {
	Start, End int
	Token      Token
}

// Tokenizer runs a list of detectors over text, in order, and replaces what
// they find with tokens. Text that is already a token is left as it is, and a
// later detector only sees text no earlier detector claimed. Safe for
// concurrent use.
type Tokenizer struct {
	keys        *Keys
	phoneRegion string
	detectors   []Detector
}

// NewTokenizer returns a tokenizer that makes tokens with keys and runs the
// detectors in the order given (the default list: PatternDetectors, then
// NewDictionaryDetector). phoneRegion normalizes phones written without +cc
// ("" when unknown).
func NewTokenizer(keys *Keys, phoneRegion string, detectors ...Detector) *Tokenizer {
	if keys == nil || len(detectors) == 0 {
		panic("pii.NewTokenizer: keys and at least one detector required")
	}
	for _, d := range detectors {
		if d == nil {
			panic("pii.NewTokenizer: nil detector")
		}
	}
	return &Tokenizer{keys: keys, phoneRegion: phoneRegion, detectors: slices.Clone(detectors)}
}

// Tokenize replaces every value the detectors find. It returns the new text and
// the replacements in input order (for counts and the round-trip check; they
// carry offsets and tokens, never values). The output is scanned again with
// every detector (FinalScan) before it is returned. The call fails closed,
// returning nothing rather than a text that may still hold a value, when that
// scan finds anything, or when a detector span is out of range, empty, splits
// a UTF-8 sequence or has an unknown type.
func (tz *Tokenizer) Tokenize(text string) (string, []Replacement, error) {
	found, err := tz.detect(text)
	if err != nil {
		return "", nil, err
	}
	out, reps, err := tz.replace(text, found)
	if err != nil {
		return "", nil, err
	}
	left, err := tz.FinalScan(out)
	if err != nil {
		return "", nil, err
	}
	if left > 0 {
		return "", nil, fmt.Errorf("pii: tokenized text still holds %d detected values; refusing it", left)
	}
	return out, reps, nil
}

// FinalScan counts what the detectors still find in text outside the tokens
// already in it, through the same folded view and claims as Tokenize. Run on
// Tokenize's output it is zero; Tokenize itself fails closed otherwise, and a
// caller runs it on any text that did not come through Tokenize (the proxy's
// last check before a request leaves).
func (tz *Tokenizer) FinalScan(text string) (int, error) {
	found, err := tz.detect(text)
	return len(found), err
}

// detect runs the detectors in order. Each one sees only text no earlier one
// claimed; its spans, mapped back to the original text, are merged where they
// overlap, so nothing any of them found is dropped.
func (tz *Tokenizer) detect(text string) ([]Span, error) {
	claimed := existingTokens(text)
	var found []Span
	for i, d := range tz.detectors {
		spans, err := detectFree(d, text, claimed)
		if err != nil {
			return nil, fmt.Errorf("pii: detector %d: %w", i, err)
		}
		accepted := mergeOverlapping(spans)
		found = append(found, accepted...)
		claimed = mergeSpans(claimed, accepted)
	}
	slices.SortFunc(found, func(a, b Span) int { return cmp.Compare(a.Start, b.Start) })
	widenToBoundaries(text, found, claimed)
	return found, nil
}

// widenToBoundaries grows each found span over the ASCII letters and digits,
// combining marks and ignorable characters touching it, up to the next
// claimed span (a token already in the text or
// another found span). A token is only recognized again when nothing
// alphanumeric touches it (existingTokens), so a token written against
// letters ("0@0.A+12025550143" gives "0@0.Apii1_…") would be read as part of a
// new address next turn. Spans that touch another span stay as they are: back
// to back tokens recognize each other. claimed is sorted and holds found.
func widenToBoundaries(text string, found, claimed []Span) {
	for i := range found {
		k, _ := slices.BinarySearchFunc(claimed, found[i].Start, func(c Span, start int) int { return cmp.Compare(c.Start, start) })
		lo, hi := 0, len(text)
		if k > 0 {
			lo = claimed[k-1].End
		}
		if k+1 < len(claimed) {
			hi = claimed[k+1].Start
		}
		for found[i].Start > lo {
			n := widenLeft(text[lo:found[i].Start])
			if n == 0 {
				break
			}
			found[i].Start -= n
		}
		for found[i].End < hi {
			n := widenRight(text[found[i].End:hi])
			if n == 0 {
				break
			}
			found[i].End += n
		}
		// The next span is bounded by this one as widened.
		claimed[k] = found[i]
	}
}

func (tz *Tokenizer) replace(text string, found []Span) (string, []Replacement, error) {
	if len(found) == 0 {
		return text, nil, nil
	}
	reps := make([]Replacement, 0, len(found))
	var b strings.Builder
	last := 0
	for _, sp := range found {
		tok, err := tz.keys.MakeToken(sp.Type, text[sp.Start:sp.End], tz.phoneRegion)
		if err != nil {
			return "", nil, err
		}
		b.WriteString(text[last:sp.Start])
		b.WriteString(tok.Surface())
		last = sp.End
		reps = append(reps, Replacement{Start: sp.Start, End: sp.End, Token: tok})
	}
	b.WriteString(text[last:])
	return b.String(), reps, nil
}

// detectFree runs d on the folded view (foldForDetection) of each stretch of
// text outside claimed (sorted, disjoint) and returns its spans as offsets into
// text. A span is checked against the folded text it was found in, then mapped
// back to the original characters it came from.
func detectFree(d Detector, text string, claimed []Span) ([]Span, error) {
	var out []Span
	for _, seg := range freeSegments(len(text), claimed) {
		view := foldForDetection(text[seg.Start:seg.End], wantsShapes(d))
		for _, sp := range d.Detect(view.text) {
			if err := checkSpan(view.text, sp); err != nil {
				return nil, err
			}
			start, end := view.original(sp)
			out = append(out, Span{Start: seg.Start + start, End: seg.Start + end, Type: sp.Type})
		}
	}
	return out, nil
}

func checkSpan(text string, sp Span) error {
	if sp.Start < 0 || sp.End > len(text) || sp.Start >= sp.End {
		return fmt.Errorf("span [%d,%d) outside a text of %d bytes", sp.Start, sp.End, len(text))
	}
	if !utf8.RuneStart(text[sp.Start]) || (sp.End < len(text) && !utf8.RuneStart(text[sp.End])) {
		return fmt.Errorf("span [%d,%d) splits a character", sp.Start, sp.End)
	}
	if !sp.Type.Valid() {
		return fmt.Errorf("span [%d,%d) has unknown entity type %q", sp.Start, sp.End, sp.Type)
	}
	return nil
}

// freeSegments are the non-empty stretches of [0, n) outside claimed.
func freeSegments(n int, claimed []Span) []Span {
	var segs []Span
	pos := 0
	for _, c := range claimed {
		if c.Start > pos {
			segs = append(segs, Span{Start: pos, End: c.Start})
		}
		pos = max(pos, c.End)
	}
	if pos < n {
		segs = append(segs, Span{Start: pos, End: n})
	}
	return segs
}

// mergeOverlapping joins overlapping spans into one that covers all of them,
// with the type of the one that starts first (then the longest). Spans that
// only touch stay apart. Overlaps happen when two values widen into the one
// character between them (a "\u00bc" folds to "1\u20444"), so dropping either
// would let a value through.
func mergeOverlapping(spans []Span) []Span {
	slices.SortFunc(spans, func(a, b Span) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End))
	})
	var out []Span
	for _, sp := range spans {
		if n := len(out); n > 0 && sp.Start < out[n-1].End {
			out[n-1].End = max(out[n-1].End, sp.End)
			continue
		}
		out = append(out, sp)
	}
	return out
}

func mergeSpans(a, b []Span) []Span {
	out := append(slices.Clone(a), b...)
	slices.SortFunc(out, func(x, y Span) int { return cmp.Compare(x.Start, y.Start) })
	return out
}

// tokenRe finds token surfaces already in the text (a history re-sent next
// turn), so they are never tokenized again. Any key version (pii2_) counts. An
// email token's domain is matched literally (only the domains MakeToken
// writes). Boundaries are checked in existingTokens; a phone token's "+cc "
// prefix is added there too.
var tokenRe = regexp.MustCompile(`pii\d+_[A-Z2-7]{12}(?:@(?:` + tokenDomainsRe() + `))?|(?:Person|Address) [A-Z2-7]{12}`)

// phonePrefixRe is the "+cc " a phone token starts with, just before its id.
var phonePrefixRe = regexp.MustCompile(`\+\d{1,3} $`)

// maxPhonePrefixLen is the longest "+cc " prefix: "+" and three digits and a space.
const maxPhonePrefixLen = 5

func tokenDomainsRe() string {
	domains := append([]string{redactedDomain}, slices.Collect(maps.Keys(commonMailProviders))...)
	// Longest first, so no domain stops inside a longer one.
	slices.SortFunc(domains, func(a, b string) int { return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b)) })
	for i, d := range domains {
		domains[i] = regexp.QuoteMeta(d)
	}
	return strings.Join(domains, "|")
}

// existingTokens finds the tokens in text. A token counts only when no ASCII
// letter or digit touches it on either side, so "xpii1_ABCDEFGHIJKL@corp.com"
// (an address that merely contains a token shape) is not skipped. Tokens
// written back to back count as boundaries for each other: on the left only a
// token already accepted does, on the right any token shape that starts there.
func existingTokens(text string) []Span {
	matches := tokenRe.FindAllStringIndex(text, -1)
	out := make([]Span, 0, len(matches))
	for i, m := range matches {
		prevEnd := -1
		if len(out) > 0 {
			prevEnd = out[len(out)-1].End
		}
		start := withPhonePrefix(text, m[0], prevEnd)
		leftOK := !asciiAlnumAt(text, start-1) || prevEnd == start
		rightOK := !asciiAlnumAt(text, m[1]) || (i+1 < len(matches) && matches[i+1][0] == m[1])
		if leftOK && rightOK {
			out = append(out, Span{Start: start, End: m[1]})
		}
	}
	return out
}

// withPhonePrefix moves start back over a "+cc " prefix when one is there and
// nothing alphanumeric touches it, or the token accepted before it ends right
// there (prevEnd, -1 when there is none: "a@b.cc+447700900456" tokenizes to an
// email token and a phone token back to back). Otherwise the token starts at
// its id.
func withPhonePrefix(text string, start, prevEnd int) int {
	before := text[max(0, start-maxPhonePrefixLen):start]
	loc := phonePrefixRe.FindStringIndex(before)
	if loc == nil {
		return start
	}
	ps := start - len(before) + loc[0]
	if asciiAlnumAt(text, ps-1) && ps != prevEnd {
		return start
	}
	return ps
}

// asciiAlnumAt reports whether text[i] is an ASCII letter or digit (false
// outside text).
func asciiAlnumAt(text string, i int) bool {
	if i < 0 || i >= len(text) {
		return false
	}
	return isASCIIAlnum(text[i])
}

func isASCIIAlnum(c byte) bool {
	return isASCIIDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// shapeDetector marks the built-in shape detectors (EmailDetector,
// PhoneDetector, CardDetector, IBANDetector), which see the shape view: no
// combining marks, ASCII digits, every dash as '-'.
type shapeDetector interface{ shapes() }

func wantsShapes(d Detector) bool {
	_, ok := d.(shapeDetector)
	return ok
}

// widenLeft is the byte length of the last character of s when a span may
// take it in: an ASCII letter or digit, a combining mark or an ignorable
// character (the shape view drops the last two, so a keycap or a zero-width
// space at a number's edge would otherwise be left beside its token).
func widenLeft(s string) int {
	r, n := utf8.DecodeLastRuneInString(s)
	if n == 0 || !widensOver(r) {
		return 0
	}
	return n
}

// widenRight is widenLeft for the first character of s.
func widenRight(s string) int {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 || !widensOver(r) {
		return 0
	}
	return n
}

func widensOver(r rune) bool {
	if r < utf8.RuneSelf {
		return isASCIIAlnum(byte(r))
	}
	return isIgnorable(r) || unicode.In(r, unicode.Mn, unicode.Me)
}
