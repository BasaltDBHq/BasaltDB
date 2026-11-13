package pii_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

func tokenize(t *testing.T, tz *pii.Tokenizer, s string) (string, []pii.Replacement) {
	t.Helper()
	out, reps, err := tz.Tokenize(s)
	require.NoError(t, err)
	return out, reps
}

func TestTokenizeText(t *testing.T) {
	tz := newTokenizer(t)
	in := "Customer Alice Tamm (fixture.alice.tamm@gmail.com, +44 7700 900123) lives at 12 Fixture Lane, Tallinn. " +
		"Mari-Liis   Kask called from +1 202 555 0143. Rose Lepik likes the rose garden; Rose said hi. " +
		"Will may call in May. A stranger, bob@unknown.example, is not in the dictionary."
	out, reps := tokenize(t, tz, in)
	for _, v := range []string{"Alice Tamm", "fixture.alice.tamm", "7700 900123", "Fixture Lane", "Mari-Liis", "202 555", "Rose Lepik", "bob@unknown"} {
		require.NotContains(t, out, v)
	}
	require.Contains(t, out, "the rose garden", "common word alone is not matched")
	require.Contains(t, out, "Will may call in May", "common words untouched")
	require.Contains(t, out, "; Rose said", "a common-word name alone is never a name in free text (DD-1)")
	require.Contains(t, out, "pii1_", "tokens present")
	require.Contains(t, out, "@redacted.invalid", "an unknown domain is not kept")
	require.Len(t, reps, 8) // 2 emails (one not in the dictionary), 2 phones, 3 names, 1 address
	require.Zero(t, finalScan(t, tz, out))
	require.Positive(t, finalScan(t, tz, in))
}

func TestReplacementsPointAtTheInput(t *testing.T) {
	tz := newTokenizer(t)
	in := "Ask Alice Tamm at +44 7700 900123."
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 2)
	require.Equal(t, "Alice Tamm", in[reps[0].Start:reps[0].End])
	require.Equal(t, pii.EntityPersonName, reps[0].Token.Type)
	require.Equal(t, "+44 7700 900123", in[reps[1].Start:reps[1].End])
	require.Equal(t, pii.EntityPhone, reps[1].Token.Type)
	require.Equal(t, "Ask "+reps[0].Token.Surface()+" at "+reps[1].Token.Surface()+".", out)
}

func TestTokenizeIsIdempotentOnTokens(t *testing.T) {
	tz := newTokenizer(t)
	once, _ := tokenize(t, tz, "Mail fixture.alice.tamm@gmail.com or mari.kask@fixture-corp.example, call +44 7700 900123, ask for Alice Tamm at 12 Fixture Lane, Tallinn.")
	twice, reps := tokenize(t, tz, once)
	require.Equal(t, once, twice, "a token in history is never tokenized again")
	require.Empty(t, reps)
}

func TestTokensWrittenBackToBackAreBothKept(t *testing.T) {
	tz := newTokenizer(t)
	in := "pii1_AAAAAAAAAAAA@redacted.invalidpii1_BBBBBBBBBBBB@gmail.comPerson CCCCCCCCCCCC"
	out, reps := tokenize(t, tz, in)
	require.Empty(t, reps)
	require.Equal(t, in, out)
}

// A token glued to letters on its right is not skipped, and the token before
// it still is.
func TestTokensBackToBackWithTrailingLetters(t *testing.T) {
	tz := newTokenizer(t)
	in := "pii1_AAAAAAAAAAAA@redacted.invalidpii1_BBBBBBBBBBBBA00"
	out, reps := tokenize(t, tz, in)
	require.Empty(t, reps)
	require.Equal(t, in, out)
	require.Zero(t, finalScan(t, tz, "xpii1_AAAAAAAAAAAApii1_BBBBBBBBBBBB")) // nothing detectable
	out, reps = tokenize(t, tz, "xpii1_AAAAAAAAAAAApii1_BBBBBBBBBBBB@corp.com")
	require.Len(t, reps, 1, "neither shape is a token, so the address is found whole")
	require.NotContains(t, out, "corp.com")
}

// A token is never written against letters or digits: the span widens over
// them, so the token is recognized next turn and makes no new address.
func TestASpanWidensOverGluedLetters(t *testing.T) {
	tz := newTokenizer(t)
	in := "0@0.A+12025550143"
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, "A+12025550143", in[reps[0].Start:reps[0].End])
	require.Equal(t, "0@0."+reps[0].Token.Surface(), out)
	again, more := tokenize(t, tz, out)
	require.Empty(t, more)
	require.Equal(t, out, again)
}

// A phone token's "+cc " prefix that touches the token before it belongs to
// its token. A detector that flags a stray "+44" shows the prefix is claimed:
// were it left over, the final scan would find it and the call would fail.
func TestAPhonePrefixTouchingAnotherTokenIsClaimed(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), wordSpan("+44", pii.EntityOther))...)
	for _, in := range []string{"a@b.cc+447911123456", "+447911123456+447911123457"} {
		out, reps := tokenize(t, tz, in)
		require.Len(t, reps, 2, in)
		require.Equal(t, reps[0].Token.Surface()+reps[1].Token.Surface(), out, in)
		require.Equal(t, "+44 ", reps[1].Token.Prefix, in)
		again, more := tokenize(t, tz, out)
		require.Empty(t, more, in)
		require.Equal(t, out, again, in)
	}
}

func TestAnAddressGluedToDigitsIsTokenizedWhole(t *testing.T) {
	tz := newTokenizer(t)
	once, reps := tokenize(t, tz, "mail a.b@corp.example2024 now")
	require.Len(t, reps, 1)
	require.Equal(t, "a.b@corp.example2024", "mail a.b@corp.example2024 now"[reps[0].Start:reps[0].End])
	twice, more := tokenize(t, tz, once)
	require.Empty(t, more)
	require.Equal(t, once, twice)
}

// A token shape inside a longer word is not a token: the address around it is
// tokenized, and the final scan does not skip it.
func TestATokenShapeTouchingAlphanumericsIsNotSkipped(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	address := "xpii1_ABCDEFGHIJKL@corp.com"
	d.add(k, pii.EntityEmail, address)
	d.add(k, pii.EntityPersonName, "Person ABCDEFGHIJKLz")
	dd := pii.NewDictionaryDetector(k, d, "")
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), dd)...)
	for _, in := range []string{address, "pii1_ABCDEFGHIJKLM@corp.com", "Person ABCDEFGHIJKLz"} {
		out, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, in)
		require.Equal(t, in, in[reps[0].Start:reps[0].End], in)
		require.NotEqual(t, in, out)
	}
	require.Positive(t, finalScan(t, tz, "send to "+address), "not skipped as a token")
	out, _ := tokenize(t, tz, "send to "+address)
	require.Zero(t, finalScan(t, tz, out))
}

func TestAPhoneTokenPrefixIsClaimedOnlyWithABoundary(t *testing.T) {
	tz := newTokenizer(t)
	for _, in := range []string{"call +44 pii1_AAAAAAAAAAAA now", "x+44 pii1_AAAAAAAAAAAA"} {
		out, reps := tokenize(t, tz, in)
		require.Empty(t, reps, in)
		require.Equal(t, in, out)
	}
}

func TestTokenizeIsDeterministicAcrossTurns(t *testing.T) {
	tz := newTokenizer(t)
	a, _ := tokenize(t, tz, "Alice Tamm wrote from fixture.alice.tamm@gmail.com")
	b, _ := tokenize(t, tz, "alice   tamm wrote from Fixture.Alice.Tamm@Gmail.com")
	require.Equal(t, a, b)
}

func TestTokenizeFindsNFDTextAndKeepsOffsetsOnTheInput(t *testing.T) {
	tz := newTokenizer(t)
	in := "Visit Pa\u0308rnu mnt 99, Tallinn today"
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, pii.EntityAddress, reps[0].Token.Type)
	require.Equal(t, "Pa\u0308rnu mnt 99, Tallinn", in[reps[0].Start:reps[0].End])
	require.Equal(t, "Visit "+reps[0].Token.Surface()+" today", out)
}

func TestTokenizeNGramsDoNotJoinAcrossWideGaps(t *testing.T) {
	tz := newTokenizer(t)
	out, reps := tokenize(t, tz, "Alice      Tamm")
	require.Empty(t, reps)
	require.Equal(t, "Alice      Tamm", out)
}

func TestTokenizeTypedFormFindsAPhoneWrittenDifferently(t *testing.T) {
	tz := newTokenizer(t)
	in := "call +447911123456 now"
	require.Equal(t, 1, finalScan(t, tz, in), "a phone written without spaces is found")
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, "+447911123456", in[reps[0].Start:reps[0].End], "the whole number, not a prefix")
	require.Equal(t, "call "+reps[0].Token.Surface()+" now", out)
}

func TestTokenizeLocalPhoneWithARegion(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPhone, "+62 812 3456 7890")
	dd := pii.NewDictionaryDetector(k, d, "ID")
	tz := pii.NewTokenizer(k, "ID", append(pii.PatternDetectors(), dd)...)
	in := "WA +62 812-3456-7890"
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	local := mustToken(t, k, pii.EntityPhone, "0812 3456 7890", "ID")
	require.Equal(t, local, reps[0].Token, "free text and a local-format column agree")
	require.Equal(t, "WA "+local.Surface(), out)
}

// fakeDetector stands in for a third-party detector on the list (the M5.3 port).
type fakeDetector struct{ spans func(string) []pii.Span }

func (f fakeDetector) Detect(s string) []pii.Span { return f.spans(s) }

func wordSpan(word string, typ pii.EntityType) fakeDetector {
	return fakeDetector{spans: func(s string) []pii.Span {
		i := strings.Index(s, word)
		if i < 0 {
			return nil
		}
		return []pii.Span{{Start: i, End: i + len(word), Type: typ}}
	}}
}

// Detectors see the folded text (lower case), so the fake ones search for it.
func TestDetectorsRunInOrderAndBasaltMakesEveryToken(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), wordSpan("zed qux", pii.EntityPersonName), wordSpan("qux", pii.EntityOther))...)
	in := "hello Zed Qux, z@corp.example"
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 2, "the later detector's overlapping span is dropped")
	require.Equal(t, mustToken(t, k, pii.EntityEmail, "z@corp.example", ""), reps[1].Token)
	require.Equal(t, mustToken(t, k, pii.EntityPersonName, "Zed Qux", ""), reps[0].Token)
	require.Equal(t, "hello "+reps[0].Token.Surface()+", "+reps[1].Token.Surface(), out)
}

func TestLaterDetectorsSeeOnlyUnclaimedText(t *testing.T) {
	k := newKeys(t, testMaster)
	var seen []string
	spy := fakeDetector{spans: func(s string) []pii.Span { seen = append(seen, s); return nil }}
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), spy)...)
	_, _ = tokenize(t, tz, "a z@corp.example b pii1_AAAAAAAAAAAA c")
	require.GreaterOrEqual(t, len(seen), 3)
	require.Equal(t, []string{"a ", " b ", " c"}, seen[:3], "the first pass; the final scan follows")
}

func TestOverlappingSpansFromOneDetectorAreMerged(t *testing.T) {
	k := newKeys(t, testMaster)
	d := fakeDetector{spans: func(s string) []pii.Span {
		if s != "abcdefgh" {
			return nil // the final scan of the output
		}
		return []pii.Span{
			{Start: 2, End: 5, Type: pii.EntityOther},
			{Start: 0, End: 3, Type: pii.EntityOther},
			{Start: 0, End: 4, Type: pii.EntityOther},
			{Start: 6, End: 8, Type: pii.EntityOther},
		}
	}}
	_, reps := tokenize(t, pii.NewTokenizer(k, "", d), "abcdefgh")
	require.Len(t, reps, 2)
	require.Equal(t, [2]int{0, 6}, [2]int{reps[0].Start, reps[0].End}, "overlaps cover all of their text, widened to the next span")
	require.Equal(t, [2]int{6, 8}, [2]int{reps[1].Start, reps[1].End})
}

func TestAnInvalidSpanFailsClosed(t *testing.T) {
	k := newKeys(t, testMaster)
	bad := []pii.Span{
		{Start: -1, End: 2, Type: pii.EntityOther},
		{Start: 0, End: 99, Type: pii.EntityOther},
		{Start: 3, End: 3, Type: pii.EntityOther},
		{Start: 0, End: 2, Type: pii.EntityType("NOPE")},
		{Start: 1, End: 3, Type: pii.EntityOther}, // starts inside the 'é'
	}
	for _, sp := range bad {
		d := fakeDetector{spans: func(string) []pii.Span { return []pii.Span{sp} }}
		out, reps, err := pii.NewTokenizer(k, "", d).Tokenize("éabc")
		require.Error(t, err, "%+v", sp)
		require.Empty(t, out)
		require.Empty(t, reps)
	}
}

// A detector that still matches the tokenized text fails the call: the
// output is rescanned with every detector before it is returned.
func TestTokenizeFailsClosedWhenTheOutputStillMatches(t *testing.T) {
	k := newKeys(t, testMaster)
	always := fakeDetector{spans: func(s string) []pii.Span {
		if s == "" {
			return nil
		}
		return []pii.Span{{Start: 0, End: 1, Type: pii.EntityOther}}
	}}
	out, reps, err := pii.NewTokenizer(k, "", always).Tokenize("a b")
	require.ErrorContains(t, err, "still holds")
	require.Empty(t, out)
	require.Empty(t, reps)
}

func TestNewTokenizerPanicsWithoutDeps(t *testing.T) {
	k := newKeys(t, testMaster)
	require.Panics(t, func() { pii.NewTokenizer(nil, "", pii.PatternDetectors()...) })
	require.Panics(t, func() { pii.NewTokenizer(k, "") })
	require.Panics(t, func() { pii.NewDictionaryDetector(nil, newMapDict(), "") })
	require.Panics(t, func() { pii.NewDictionaryDetector(k, nil, "") })
}

func TestAPhoneGluedToLettersIsFound(t *testing.T) {
	tz := newTokenizer(t)
	for _, c := range []struct{ in, number string }{
		{"+447911123456x123", "+447911123456x123"}, // widened over the glued letters
		{"+447911123456_", "+447911123456"},
		{"+44 7911 123456ext2", "+44 7911 123456ext2"},
		{"call +44 7911 123456.", "+44 7911 123456"},
		{"+44 7911 123123+1 202 555 0143", "+44 7911 123123"},
	} {
		require.Positive(t, finalScan(t, tz, c.in), c.in)
		out, reps := tokenize(t, tz, c.in)
		require.NotEmpty(t, reps, c.in)
		require.Equal(t, c.number, c.in[reps[0].Start:reps[0].End], c.in)
		require.NotContains(t, out, "911", c.in)
		require.Zero(t, finalScan(t, tz, out), c.in)
	}
}

func TestFullWidthAndCompatibilityFormsAreFound(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPersonName, "Alexandra Jones")
	dd := pii.NewDictionaryDetector(k, d, "")
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), dd)...)
	cases := []struct {
		in, value string
		typ       pii.EntityType
		plain     string
	}{
		{"hi \uff21\uff4c\uff45\uff58\uff41\uff4e\uff44\uff52\uff41 \uff2a\uff4f\uff4e\uff45\uff53!", "\uff21\uff4c\uff45\uff58\uff41\uff4e\uff44\uff52\uff41 \uff2a\uff4f\uff4e\uff45\uff53", pii.EntityPersonName, "Alexandra Jones"},
		{"to \uff41\uff4c\uff49\uff43\uff45@example.com", "\uff41\uff4c\uff49\uff43\uff45@example.com", pii.EntityEmail, "alice@example.com"},
		{"call \uff0b\uff14\uff14\uff17\uff19\uff11\uff11\uff11\uff12\uff13\uff14\uff15\uff16 now", "\uff0b\uff14\uff14\uff17\uff19\uff11\uff11\uff11\uff12\uff13\uff14\uff15\uff16", pii.EntityPhone, "+447911123456"},
		{"ALEXANDRA  jones", "ALEXANDRA  jones", pii.EntityPersonName, "Alexandra Jones"},
		{"\ufb01 alice@ex\u00e4mple.ee", "alice@ex\u00e4mple.ee", pii.EntityEmail, "alice@ex\u00e4mple.ee"},
		{"Ali\u0307ce@xn--exmple-cua.ee", "Ali\u0307ce@xn--exmple-cua.ee", pii.EntityEmail, "ali\u0307ce@xn--exmple-cua.ee"},
	}
	for _, c := range cases {
		out, reps := tokenize(t, tz, c.in)
		require.Len(t, reps, 1, c.in)
		require.Equal(t, c.value, c.in[reps[0].Start:reps[0].End], "spans map back to the original")
		require.Equal(t, mustToken(t, k, c.typ, c.plain, ""), reps[0].Token, c.in)
		require.NotContains(t, out, c.value)
	}
	require.Equal(t, 1, finalScan(t, tz, cases[0].in))
}

func TestFoldedSpansWidenToWholeCharacters(t *testing.T) {
	k := newKeys(t, testMaster)
	// U+FB03 folds to "ffi"; a span over its middle "f" covers the whole ligature.
	d := fakeDetector{spans: func(s string) []pii.Span {
		if s != "a ffi b" {
			return nil // the final scan of the output
		}
		return []pii.Span{{Start: 3, End: 4, Type: pii.EntityOther}}
	}}
	in := "A \ufb03 B"
	_, reps := tokenize(t, pii.NewTokenizer(k, "", d), in)
	require.Len(t, reps, 1)
	require.Equal(t, "\ufb03", in[reps[0].Start:reps[0].End])
}

func TestPhonePatternBounds(t *testing.T) {
	tz := pii.NewTokenizer(newKeys(t, testMaster), "", pii.PatternDetectors()...)
	_, reps := tokenize(t, tz, "codes +1 234 and +44 7911 123123")
	require.Len(t, reps, 1, "under 8 digits is not a phone")

	in := "+44 7911 123123 2026 1234+1 202 555 0143"
	_, reps = tokenize(t, tz, in)
	require.Len(t, reps, 2, "a phone followed by another number keeps the phone")
	require.Equal(t, "+44 7911 123123", in[reps[0].Start:reps[0].End])
	require.Equal(t, "1234+1 202 555 0143", in[reps[1].Start:reps[1].End], "widened over the digits glued to it")
}

func TestTokenizeIsSafeForConcurrentUse(t *testing.T) {
	tz := newTokenizer(t)
	want, _ := tokenize(t, tz, "Alice Tamm, +44 7700 900123")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, _, err := tz.Tokenize("Alice Tamm, +44 7700 900123")
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
	wg.Wait()
}
