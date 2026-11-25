package pii

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// Thresholds of the M5.1 plan, section 3.
const (
	// sampleShare is the share of sampled values (percent) a validator must
	// pass to win.
	sampleShare = 80
	// nameShare is the share of values starting with a first name.
	nameShare = 50
	// freeTextLen is the mean length (characters) above which spaced text
	// is free text.
	freeTextLen = 40
	// spacedShare is the share of free-text values that hold a space.
	spacedShare = 50
	// wideLengthSpread: digit runs whose lengths differ by this much are
	// amounts or counts, not identifiers.
	wideLengthSpread = 4
	// longShare is the share (percent) of numbers of minPhoneDigits or more
	// digits that makes a number column an identifier to review.
	longShare = 10
	// minSequentialValues is the fewest distinct values that make a sequence.
	minSequentialValues = 5
	// sequentialSpan: distinct integers whose range is at most this many
	// times their count are sequential (an id or a counter).
	sequentialSpan = 2
	// maxSequentialDigits keeps the span arithmetic in uint64.
	maxSequentialDigits = 18
	percent             = 100
)

// Reasons that carry no count.
const (
	reasonKey        = "KEY:internal id"
	reasonSequential = "KEY:sequential values"
	reasonDecimals   = "SHAPE:decimals or signs"
	reasonCodes      = "SHAPE:codes only, no spaces"
	reasonNoValues   = "SAMPLE:no values"
)

// internalID reports whether a column is an id the database makes: an
// identity or serial column, or an integer key whose values all have fewer
// than minPhoneDigits digits. Any other key (a text key, a foreign key
// holding phone numbers, a long integer key) is judged like any column.
func internalID(col Column, k piistore.Kind, values []string) bool {
	if col.Generated {
		return true
	}
	if !col.Key || k != piistore.KindInt {
		return false
	}
	return !slices.ContainsFunc(values, func(v string) bool { return len(strings.TrimLeft(strings.TrimSpace(v), "-")) >= minPhoneDigits })
}

// Suggestion is the class suggested for a column and why.
type Suggestion struct {
	Class, EntityType string
	// Reason holds names and counts only, never a value.
	Reason string
	// NeedsReview marks the protected guess for an ambiguous column.
	NeedsReview bool
	// PhoneRegion is the region the column's numbers parse as (PHONE only;
	// "" when none could be inferred).
	PhoneRegion string
}

// Options are the run's settings.
type Options struct {
	// PhoneRegion is the --phone-region for every PHONE column ("" infers it
	// per column).
	PhoneRegion string
	// CallingCodes are the +cc prefixes seen in the database's samples,
	// which weight region inference.
	CallingCodes map[int32]int
}

// Rank orders classes by how much they protect: SECRET, IDENTIFIER,
// FREE_TEXT, PUBLIC, then UNCLASSIFIED.
func Rank(class string) int {
	return slices.Index([]string{guardmodel.ClassUnclassified, guardmodel.ClassPublic, guardmodel.ClassFreeText, guardmodel.ClassIdentifier, guardmodel.ClassSecret}, class)
}

// Suggest scores one column: a sample validator that passes on enough
// values wins, unless the name asks for a more protective class; then the
// name rules; then keys and the shape of numbers. Ambiguous numbers come out
// IDENTIFIER OTHER for review, never PUBLIC.
func Suggest(col Column, s Sample, opts Options) Suggestion {
	k := col.Kind
	hit, named := matchName(col.Name, k)
	switch {
	case !Sampled(k):
		if named {
			return fromName(hit)
		}
		return Suggestion{Class: guardmodel.ClassPublic, Reason: "TYPE:" + col.DataType}
	case s.Unavailable != "":
		return unsampled(hit, named, "SAMPLE:"+s.Unavailable)
	}
	if len(s.Values) == 0 {
		if !named && internalID(col, k, nil) {
			return Suggestion{Class: guardmodel.ClassPublic, Reason: reasonKey}
		}
		return unsampled(hit, named, reasonNoValues)
	}
	if named && hit.qualified && hit.class != guardmodel.ClassSecret && shortCodes(s.Values) {
		named = false // email_status holding verified, pending: about the value, not the value
	}
	if v, ok := validate(k, s.Values, hit, named, opts); ok {
		return v
	}
	if named {
		return byName(hit, s.Values, opts)
	}
	return byShape(col, k, s.Values, opts)
}

func fromName(hit nameHit) Suggestion {
	return Suggestion{Class: hit.class, EntityType: hit.entity, Reason: "NAME:" + hit.word}
}

// unsampled is the suggestion for a column with no values to look at: its
// name's, or the protected guess for review (values may come later).
func unsampled(hit nameHit, named bool, reason string) Suggestion {
	if named {
		s := fromName(hit)
		s.Reason += "; " + reason
		return s
	}
	return Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, Reason: reason, NeedsReview: true}
}

// validate runs the sample validators in order, the most protective first.
func validate(k piistore.Kind, values []string, hit nameHit, named bool, opts Options) (Suggestion, bool) {
	n := len(values)
	enough := func(c int) bool { return c*percent >= sampleShare*n }
	count := func(f func(string) bool) int {
		c := 0
		for _, v := range values {
			if f(v) {
				c++
			}
		}
		return c
	}
	sampled := func(label string, c int) string { return fmt.Sprintf("SAMPLE:%s %d/%d", label, c, n) }
	type check struct {
		label, class, entity string
		valid                func(string) bool
	}
	for _, ch := range []check{
		{"CARD", guardmodel.ClassSecret, "", validCard},
		{"NIK", guardmodel.ClassSecret, "", validNIK},
		{"IBAN", guardmodel.ClassIdentifier, guardmodel.EntityOther, validIBAN},
		{"EMAIL", guardmodel.ClassIdentifier, guardmodel.EntityEmail, validEmail},
	} {
		if c := count(ch.valid); enough(c) {
			return withName(Suggestion{Class: ch.class, EntityType: ch.entity, Reason: sampled(ch.label, c)}, hit, named), true
		}
	}
	namedPhone := named && hit.entity == guardmodel.EntityPhone
	if namedPhone || enough(count(func(v string) bool { _, ok := phoneShape(v, false); return ok })) {
		r := inferRegion(values, namedPhone, opts.PhoneRegion, opts.CallingCodes)
		if enough(r.valid) {
			s := Suggestion{
				Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: r.region,
				Reason: sampled("PHONE", r.valid) + regionNote(r, n),
			}
			return withName(s, hit, named), true
		}
	}
	// Runs of bare digits that are valid phones, with no name to say so:
	// protected as phones, for a person to confirm (a block of consecutive
	// MSISDNs, and keys too, included).
	if !namedPhone && enough(count(bareDigits)) {
		r := inferRegion(values, true, opts.PhoneRegion, opts.CallingCodes)
		if enough(r.valid) {
			s := Suggestion{
				Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: r.region, NeedsReview: true,
				Reason: sampled("PHONE", r.valid) + " bare digits" + regionNote(r, n),
			}
			return withName(s, hit, named), true
		}
	}
	if c := count(validIMEI); enough(c) {
		return withName(Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, Reason: sampled("IMEI", c)}, hit, named), true
	}
	if k != piistore.KindText {
		return Suggestion{}, false
	}
	if c := count(startsWithFirstName); c*percent >= nameShare*n {
		s := Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPersonName, Reason: sampled("PERSON_NAME", c)}
		return withName(s, hit, named), true
	}
	total, spaced := 0, 0
	for _, v := range values {
		total += runeLen(v)
		if hasSpace(v) {
			spaced++
		}
	}
	if total > freeTextLen*n && spaced*percent > spacedShare*n {
		s := Suggestion{Class: guardmodel.ClassFreeText, Reason: fmt.Sprintf("SAMPLE:FREE_TEXT mean %d chars, %d/%d with spaces", total/n, spaced, n)}
		return withName(s, hit, named), true
	}
	return Suggestion{}, false
}

// withName adds the name hit to a sample's suggestion: the sample wins,
// unless the name asks for a more protective class (a column named
// password that holds emails stays SECRET).
func withName(s Suggestion, hit nameHit, named bool) Suggestion {
	if !named {
		return s
	}
	if Rank(hit.class) > Rank(s.Class) {
		out := fromName(hit)
		out.Reason += "; " + s.Reason
		return out
	}
	s.Reason = "NAME:" + hit.word + "; " + s.Reason
	return s
}

func regionNote(r regionResult, n int) string {
	if r.region == "" {
		return ""
	}
	return fmt.Sprintf(", parsed as %s numbers, %d%%", r.region, r.valid*percent/n)
}

// byName is the name rule's suggestion once no validator won. A FREE_TEXT
// name over a column of codes is PUBLIC (notes holding only codes); a PHONE
// name gets its column's region.
func byName(hit nameHit, values []string, opts Options) Suggestion {
	s := fromName(hit)
	switch hit.entity {
	case guardmodel.EntityPhone:
		r := inferRegion(values, true, opts.PhoneRegion, opts.CallingCodes)
		s.PhoneRegion = r.region
		s.Reason += fmt.Sprintf("; SAMPLE:PHONE %d/%d", r.valid, len(values)) + regionNote(r, len(values))
		return s
	case "":
	default:
		return s
	}
	if hit.class == guardmodel.ClassFreeText && !slices.ContainsFunc(values, func(v string) bool { return !codeLike(v) || anyValidator(v) }) {
		return Suggestion{Class: guardmodel.ClassPublic, Reason: s.Reason + "; " + reasonCodes}
	}
	return s
}

// byShape judges a column no validator and no name rule claimed: integers
// that run in sequence are ids, decimals and mixed lengths are amounts and
// counts, and unique numbers of one length are an identifier to review.
func byShape(col Column, k piistore.Kind, values []string, opts Options) Suggestion {
	n := len(values)
	public := func(reason string) Suggestion { return Suggestion{Class: guardmodel.ClassPublic, Reason: reason} }
	allDigits := !slices.ContainsFunc(values, func(v string) bool { return !allASCIIDigits(strings.TrimSpace(v)) })
	var st numberStats
	if allDigits {
		if st = numberShape(values); st.sequential && st.maxLen < minPhoneDigits {
			return public(reasonSequential) // short ids; a long sequence (a block of MSISDNs) meets the gate
		}
	}
	// The one gate before every PUBLIC rule below: a fair share of long
	// digit runs or validator hits makes the column an identifier.
	if s, ok := longValues(values, opts); ok {
		return s
	}
	// Below the gate only: an id the database makes is no name, validator or
	// long-number hit.
	if internalID(col, k, values) {
		return public(reasonKey)
	}
	if allDigits {
		if st.maxLen-st.minLen >= wideLengthSpread {
			return public(fmt.Sprintf("SHAPE:lengths %d to %d, %d of %d long", st.minLen, st.maxLen, st.long, n))
		}
		return public(fmt.Sprintf("SHAPE:short numbers, lengths %d to %d", st.minLen, st.maxLen))
	}
	if slices.ContainsFunc(values, func(v string) bool { return looksNumeric(strings.TrimSpace(v)) }) &&
		!slices.ContainsFunc(values, func(v string) bool { return !looksNumeric(strings.TrimSpace(v)) }) {
		return public(reasonDecimals)
	}
	return public(fmt.Sprintf("SAMPLE:no validator matched %d values", n))
}

// longValues is the gate before every PUBLIC shape rule: when at least
// longShare percent of the values hold a long digit run or pass a validator,
// the column is an identifier for review, a phone when most of those values
// are valid phones. Whatever fills the rest (words, decimals, short numbers,
// codes) never makes it PUBLIC.
func longValues(values []string, opts Options) (Suggestion, bool) {
	n := len(values)
	var long []string
	for _, v := range values {
		if c, ok := longCandidate(v); ok {
			long = append(long, c)
		}
	}
	if len(long)*percent < longShare*n {
		return Suggestion{}, false
	}
	if r := inferRegion(long, true, opts.PhoneRegion, opts.CallingCodes); r.valid*percent >= sampleShare*len(long) {
		return Suggestion{
			Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: r.region, NeedsReview: true,
			Reason: fmt.Sprintf("SAMPLE:PHONE %d/%d of the %d values with long digits", r.valid, len(long), n) + regionNote(r, len(long)),
		}, true
	}
	return Suggestion{
		Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, NeedsReview: true,
		Reason: fmt.Sprintf("SHAPE:%d of %d values hold long digit runs or pass a validator", len(long), n),
	}, true
}

// longCandidate reports whether v holds a digit run of minPhoneDigits digits
// or more (after a leading + or 00 and separators are
// dropped) or passes any validator, and returns the form to try as a phone:
// the value itself when it is phone-shaped, else its first long run.
func longCandidate(v string) (string, bool) {
	if whole, _, ok := strings.Cut(strings.TrimSpace(v), "."); ok && plainDecimal(strings.TrimSpace(v)) {
		return whole, len(whole) >= minPhoneDigits // an amount: only its whole part counts
	}
	if _, ok := shapePhone(v, true); ok {
		return v, true
	}
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "+"), internationalOut)
	if !plainDecimal(s) { // 1125.00 is an amount: its dot joins no groups
		s = strings.Map(func(r rune) rune {
			if strings.ContainsRune(phoneSeparators, r) {
				return -1
			}
			return r
		}, s)
	}
	start := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minPhoneDigits {
			return s[start:i], true
		}
		start = -1
	}
	return v, anyValidator(v)
}

// plainDecimal is digits, one dot and digits (12.50, 1125.00): an amount.
func plainDecimal(s string) bool {
	whole, frac, ok := strings.Cut(s, ".")
	return ok && allASCIIDigits(whole) && allASCIIDigits(frac)
}

// looksNumeric is a signed or decimal number (an amount).
func looksNumeric(v string) bool {
	_, err := strconv.ParseFloat(v, 64)
	return err == nil
}

type numberStats struct {
	distinct, long, minLen, maxLen int
	sequential                     bool
}

func numberShape(values []string) numberStats {
	seen := map[string]bool{}
	st := numberStats{minLen: -1}
	var lo, hi uint64
	ints, started := true, false
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if !seen[v] {
			seen[v] = true
			st.distinct++
		}
		if len(v) >= minPhoneDigits {
			st.long++
		}
		st.minLen = minLen(st.minLen, len(v))
		st.maxLen = max(st.maxLen, len(v))
		if len(v) > maxSequentialDigits || (len(v) > 1 && v[0] == '0') {
			ints = false
			continue
		}
		x, _ := strconv.ParseUint(v, 10, 64) // all digits, at most 18
		if !started {
			lo, hi, started = x, x, true
		}
		lo, hi = min(lo, x), max(hi, x)
	}
	// Sequential is judged on the distinct values, so repeats of one number
	// are not a sequence.
	st.sequential = ints && st.distinct >= minSequentialValues && hi-lo < uint64(sequentialSpan*st.distinct)
	return st
}

func minLen(cur, l int) int {
	if cur < 0 {
		return l
	}
	return min(cur, l)
}
