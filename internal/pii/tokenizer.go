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

// detectFree runs d on each stretch of text outside claimed (sorted, disjoint)
// and returns its spans as offsets into text.
func detectFree(d Detector, text string, claimed []Span) ([]Span, error) {
	var out []Span
	for _, seg := range freeSegments(len(text), claimed) {
		part := text[seg.Start:seg.End]
		for _, sp := range d.Detect(part) {
			if err := checkSpan(part, sp); err != nil {
				return nil, err
			}
			out = append(out, Span{Start: seg.Start + sp.Start, End: seg.Start + sp.End, Type: sp.Type})
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
// writes), and no word boundary is required around a token, so tokens written
// back to back, or glued to other text, are all found.
var tokenRe = regexp.MustCompile(`(?:\+\d{1,3} )?pii\d+_[A-Z2-7]{12}(?:@(?:` + tokenDomainsRe() + `))?|(?:Person|Address) [A-Z2-7]{12}`)

func tokenDomainsRe() string {
	domains := append([]string{redactedDomain}, slices.Collect(maps.Keys(commonMailProviders))...)
	// Longest first, so no domain stops inside a longer one.
	slices.SortFunc(domains, func(a, b string) int { return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b)) })
	for i, d := range domains {
		domains[i] = regexp.QuoteMeta(d)
	}
	return strings.Join(domains, "|")
}

func existingTokens(text string) []Span {
	matches := tokenRe.FindAllStringIndex(text, -1)
	out := make([]Span, 0, len(matches))
	for _, m := range matches {
		out = append(out, Span{Start: m[0], End: m[1]})
	}
	return out
}
