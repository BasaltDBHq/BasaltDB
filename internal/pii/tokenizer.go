package pii

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
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
// carry offsets and tokens, never values). A detector span that is out of
// range, empty, splits a UTF-8 sequence or has an unknown type fails the whole
// call: nothing is returned rather than a text that may still hold a value.
func (tz *Tokenizer) Tokenize(text string) (string, []Replacement, error) {
	claimed := existingTokens(text)
	var found []Span
	for i, d := range tz.detectors {
		spans, err := detectFree(d, text, claimed)
		if err != nil {
			return "", nil, fmt.Errorf("pii: detector %d: %w", i, err)
		}
		accepted := nonOverlapping(spans)
		found = append(found, accepted...)
		claimed = mergeSpans(claimed, accepted)
	}
	slices.SortFunc(found, func(a, b Span) int { return cmp.Compare(a.Start, b.Start) })
	return tz.replace(text, found)
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
		view := foldForDetection(text[seg.Start:seg.End])
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

// nonOverlapping keeps, among overlapping spans, the one that starts first and
// then the longest.
func nonOverlapping(spans []Span) []Span {
	slices.SortFunc(spans, func(a, b Span) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End))
	})
	var out []Span
	end := 0
	for _, sp := range spans {
		if len(out) > 0 && sp.Start < end {
			continue
		}
		out = append(out, sp)
		end = sp.End
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
// written back to back form one run, checked at its two ends.
func existingTokens(text string) []Span {
	matches := tokenRe.FindAllStringIndex(text, -1)
	out := make([]Span, 0, len(matches))
	for i := 0; i < len(matches); {
		j := i
		for j+1 < len(matches) && matches[j+1][0] == matches[j][1] {
			j++
		}
		start := withPhonePrefix(text, matches[i][0])
		if !asciiAlnumAt(text, start-1) && !asciiAlnumAt(text, matches[j][1]) {
			for k := i; k <= j; k++ {
				out = append(out, Span{Start: matches[k][0], End: matches[k][1]})
			}
			out[len(out)-(j-i+1)].Start = start
		}
		i = j + 1
	}
	return out
}

// withPhonePrefix moves start back over a "+cc " prefix when one is there and
// nothing alphanumeric touches it; otherwise the token starts at its id.
func withPhonePrefix(text string, start int) int {
	before := text[max(0, start-maxPhonePrefixLen):start]
	loc := phonePrefixRe.FindStringIndex(before)
	if loc == nil {
		return start
	}
	ps := start - len(before) + loc[0]
	if asciiAlnumAt(text, ps-1) {
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
