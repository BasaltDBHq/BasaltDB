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
	tz, dd := newTokenizer(t)
	in := "Customer Alice Tamm (fixture.alice.tamm@gmail.com, +44 7700 900123) lives at 12 Fixture Lane, Tallinn. " +
		"Mari-Liis   Kask called from +1 202 555 0143. Rose Lepik likes the rose garden; Rose said hi. " +
		"Will may call in May. A stranger, bob@unknown.example, is not in the dictionary."
	out, reps := tokenize(t, tz, in)
	for _, v := range []string{"Alice Tamm", "fixture.alice.tamm", "7700 900123", "Fixture Lane", "Mari-Liis", "202 555", "Rose Lepik", "bob@unknown"} {
		require.NotContains(t, out, v)
	}
	require.Contains(t, out, "the rose garden", "common word alone is not matched")
	require.Contains(t, out, "Will may call in May", "common words untouched")
	require.Contains(t, out, "; Rose said hi", "single common first name stays (design rule)")
	require.Contains(t, out, "pii1_", "tokens present")
	require.Contains(t, out, "@redacted.invalid", "an unknown domain is not kept")
	require.Len(t, reps, 8) // 2 emails (one not in the dictionary), 2 phones, 3 names, 1 address
	require.Zero(t, dd.FinalScan(out))
	require.Positive(t, dd.FinalScan(in))
}

func TestReplacementsPointAtTheInput(t *testing.T) {
	tz, _ := newTokenizer(t)
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
	tz, _ := newTokenizer(t)
	once, _ := tokenize(t, tz, "Mail fixture.alice.tamm@gmail.com or mari.kask@fixture-corp.example, call +44 7700 900123, ask for Alice Tamm at 12 Fixture Lane, Tallinn.")
	twice, reps := tokenize(t, tz, once)
	require.Equal(t, once, twice, "a token in history is never tokenized again")
	require.Empty(t, reps)
}

func TestTokensWrittenBackToBackAreBothKept(t *testing.T) {
	tz, _ := newTokenizer(t)
	once, reps := tokenize(t, tz, "00@0.AA0@0.AA0")
	require.Len(t, reps, 2)
	twice, more := tokenize(t, tz, once)
	require.Empty(t, more)
	require.Equal(t, once, twice)
}

func TestTokenizeIsDeterministicAcrossTurns(t *testing.T) {
	tz, _ := newTokenizer(t)
	a, _ := tokenize(t, tz, "Alice Tamm wrote from fixture.alice.tamm@gmail.com")
	b, _ := tokenize(t, tz, "alice   tamm wrote from Fixture.Alice.Tamm@Gmail.com")
	require.Equal(t, a, b)
}

func TestTokenizeFindsNFDTextAndKeepsOffsetsOnTheInput(t *testing.T) {
	tz, _ := newTokenizer(t)
	in := "Visit Pa\u0308rnu mnt 99, Tallinn today"
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, pii.EntityAddress, reps[0].Token.Type)
	require.Equal(t, "Pa\u0308rnu mnt 99, Tallinn", in[reps[0].Start:reps[0].End])
	require.Equal(t, "Visit "+reps[0].Token.Surface()+" today", out)
}

func TestTokenizeNGramsDoNotJoinAcrossWideGaps(t *testing.T) {
	tz, _ := newTokenizer(t)
	out, reps := tokenize(t, tz, "Alice      Tamm")
	require.Empty(t, reps)
	require.Equal(t, "Alice      Tamm", out)
}

func TestTokenizeTypedFormFindsAPhoneWrittenDifferently(t *testing.T) {
	tz, dd := newTokenizer(t)
	in := "call +447700900456 now"
	require.Equal(t, 1, dd.FinalScan(in), "the typed form is in the dictionary")
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, "+447700900456", in[reps[0].Start:reps[0].End], "the whole number, not a prefix")
	require.Equal(t, "call "+reps[0].Token.Surface()+" now", out)
}

func TestTokenizeLocalPhoneWithARegion(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPhone, "+62 812 3456 7890", "")
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

func TestDetectorsRunInOrderAndBasaltMakesEveryToken(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), wordSpan("Zed Qux", pii.EntityPersonName), wordSpan("Qux", pii.EntityOther))...)
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
	require.Equal(t, []string{"a ", " b ", " c"}, seen)
}

func TestOverlappingSpansFromOneDetectorKeepTheEarliestLongest(t *testing.T) {
	k := newKeys(t, testMaster)
	d := fakeDetector{spans: func(string) []pii.Span {
		return []pii.Span{
			{Start: 2, End: 5, Type: pii.EntityOther},
			{Start: 0, End: 3, Type: pii.EntityOther},
			{Start: 0, End: 4, Type: pii.EntityOther},
			{Start: 6, End: 8, Type: pii.EntityOther},
		}
	}}
	_, reps := tokenize(t, pii.NewTokenizer(k, "", d), "abcdefgh")
	require.Len(t, reps, 2)
	require.Equal(t, [2]int{0, 4}, [2]int{reps[0].Start, reps[0].End})
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

func TestNewTokenizerPanicsWithoutDeps(t *testing.T) {
	k := newKeys(t, testMaster)
	require.Panics(t, func() { pii.NewTokenizer(nil, "", pii.PatternDetectors()...) })
	require.Panics(t, func() { pii.NewTokenizer(k, "") })
	require.Panics(t, func() { pii.NewDictionaryDetector(nil, newMapDict(), "") })
	require.Panics(t, func() { pii.NewDictionaryDetector(k, nil, "") })
}

func TestPhonePatternBounds(t *testing.T) {
	tz := pii.NewTokenizer(newKeys(t, testMaster), "", pii.PatternDetectors()...)
	_, reps := tokenize(t, tz, "codes +1 234 and +44 7700 900123")
	require.Len(t, reps, 1, "under 8 digits is not a phone")

	in := "+44 7700 900123 2026 1234+1 202 555 0143"
	_, reps = tokenize(t, tz, in)
	require.Len(t, reps, 2, "a phone followed by another number keeps the phone")
	require.Equal(t, "+44 7700 900123", in[reps[0].Start:reps[0].End])
	require.Equal(t, "+1 202 555 0143", in[reps[1].Start:reps[1].End])
}

func TestTokenizeIsSafeForConcurrentUse(t *testing.T) {
	tz, _ := newTokenizer(t)
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
