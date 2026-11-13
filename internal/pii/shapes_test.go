package pii_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// patternTokenizer is the tokenizer with the shape detectors only, so a case
// shows what the patterns find by themselves.
func patternTokenizer(t *testing.T) *pii.Tokenizer {
	t.Helper()
	return pii.NewTokenizer(newKeys(t, testMaster), "", pii.PatternDetectors()...)
}

// Each address is found whole and tokenized as one email, the same token as
// its plain spelling.
func TestEmailLocalPartsAreFoundWhole(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	cases := []struct{ name, in, value, plain string }{
		{"apostrophe", "mail bob.o'connor@corp.ee now", "bob.o'connor@corp.ee", "bob.o'connor@corp.ee"},
		{"ampersand", "mail john&jane@corp.ee now", "john&jane@corp.ee", "john&jane@corp.ee"},
		{"bang", "mail zed!x@corp.ee now", "zed!x@corp.ee", "zed!x@corp.ee"},
		{"hash", "mail zed#x@corp.ee now", "zed#x@corp.ee", "zed#x@corp.ee"},
		{"dollar", "mail zed$x@corp.ee now", "zed$x@corp.ee", "zed$x@corp.ee"},
		{"star", "mail zed*x@corp.ee now", "zed*x@corp.ee", "zed*x@corp.ee"},
		{"caret", "mail zed^x@corp.ee now", "zed^x@corp.ee", "zed^x@corp.ee"},
		{"backtick", "mail zed`x@corp.ee now", "zed`x@corp.ee", "zed`x@corp.ee"},
		{"braces", "mail zed{q}@other.com now", "zed{q}@other.com", "zed{q}@other.com"},
		{"bar", "mail zed|x@corp.ee now", "zed|x@corp.ee", "zed|x@corp.ee"},
		{"tilde", "mail zed~x@corp.ee now", "zed~x@corp.ee", "zed~x@corp.ee"},
		{"quoted", `mail "alice"@corp.ee now`, `"alice"@corp.ee`, `"alice"@corp.ee`},
		{"quoted with a space", `mail "alice tamm"@corp.ee now`, `"alice tamm"@corp.ee`, `"alice tamm"@corp.ee`},
		{"quoted with an escape", `mail "a\"b"@corp.ee now`, `"a\"b"@corp.ee`, `"a\"b"@corp.ee`},
		{"ideographic full stop", "mail zed.q@other。com now", "zed.q@other。com", "zed.q@other.com"},
		{"full-width full stop", "mail zed.q@other．com now", "zed.q@other．com", "zed.q@other.com"},
		{"half-width ideographic full stop", "mail zed.q@other｡com now", "zed.q@other｡com", "zed.q@other.com"},
		{"ideographic dot keeps a common provider", "mail zed@gmail。com now", "zed@gmail。com", "zed@gmail.com"},
		{"quote before the address stays", "WHERE email = 'bob@corp.ee'", "bob@corp.ee", "bob@corp.ee"},
		{"bar before the address stays", "| bob@corp.ee |", "bob@corp.ee", "bob@corp.ee"},
		{"brace before the address stays", "{bob@corp.ee}", "bob@corp.ee", "bob@corp.ee"},
		{"unclosed quote stays", `mail "bob@corp.ee now`, "bob@corp.ee", "bob@corp.ee"},
		{"comment", "contact bob(comment)@corp.ee please", "bob(comment)@corp.ee", "bob(comment)@corp.ee"},
		{"comment with a colon", "contact bob(a:b)@corp.ee please", "bob(a:b)@corp.ee", "bob(a:b)@corp.ee"},
		{"IPv4 literal", "contact admin@[192.168.0.10] please", "admin@[192.168.0.10]", "admin@[192.168.0.10]"},
		{"IPv6 literal", "contact admin@[IPv6:2001:db8::1] please", "admin@[IPv6:2001:db8::1]", "admin@[ipv6:2001:db8::1]"},
		{"git user, no path", "mail git@github.com now", "git@github.com", "git@github.com"},
		{"git user, colon then space", "from git@corp.ee: hello", "git@corp.ee", "git@corp.ee"},
		{"another user before a path", "ssh bob@corp.ee:repo.git", "bob@corp.ee", "bob@corp.ee"},
		{"SQL-escaped apostrophe", "WHERE email = 'o''connor@corp.ee'", "o''connor@corp.ee", "o''connor@corp.ee"},
		{"apostrophe before the at sign", "mail bob'@corp.ee now", "bob'@corp.ee", "bob'@corp.ee"},
		{"apostrophes between letters", "mail d'o'brien@corp.ee now", "d'o'brien@corp.ee", "d'o'brien@corp.ee"},
		{"dot-joined quoted words", `mail "bob"."smith"@corp.ee now`, `"bob"."smith"@corp.ee`, `"bob"."smith"@corp.ee`},
		{"atom then quoted word", `mail bob."smith"@corp.ee now`, `bob."smith"@corp.ee`, `bob."smith"@corp.ee`},
		{"quoted then atom", `mail "bob".smith@corp.ee now`, `"bob".smith@corp.ee`, `"bob".smith@corp.ee`},
		{"long quoted word", `mail "` + strings.Repeat("a", 80) + `"@corp.ee now`, `"` + strings.Repeat("a", 80) + `"@corp.ee`, `"` + strings.Repeat("a", 80) + `"@corp.ee`},
		{"quoted with a line break", "mail \"alice\ntamm\"@corp.ee now", "\"alice\ntamm\"@corp.ee", "\"alice\ntamm\"@corp.ee"},
		{"quoted with an escaped line break", "mail \"alice\\\ntamm\"@corp.ee now", "\"alice\\\ntamm\"@corp.ee", "\"alice\\\ntamm\"@corp.ee"},
		{"quoted with a slash and an equals sign", `mail "a/b=c"@corp.ee now`, `"a/b=c"@corp.ee`, `"a/b=c"@corp.ee`},
		{"Unicode hyphen", "mail a\u2010b@corp.ee now", "a\u2010b@corp.ee", "a-b@corp.ee"},
		{"minus sign", "mail a\u2212b@corp.ee now", "a\u2212b@corp.ee", "a-b@corp.ee"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, 1, finalScan(t, tz, c.in))
			out, reps := tokenize(t, tz, c.in)
			require.Len(t, reps, 1)
			require.Equal(t, c.value, c.in[reps[0].Start:reps[0].End], "the whole address")
			want := mustToken(t, k, pii.EntityEmail, c.plain, "")
			require.Equal(t, want, reps[0].Token)
			require.NotContains(t, out, c.value)
			require.Zero(t, finalScan(t, tz, out))
			again, more := tokenize(t, tz, out)
			require.Empty(t, more)
			require.Equal(t, out, again)
		})
	}
}

// A key, a query or a path glued to an address stays out of its token, and
// the address gets the token of its plain spelling. The other side of this
// rule: a local part that itself holds '=', '/' or '?' (zed=x@corp.ee) is
// cut there too, and what comes before the cut stays (Known limits).
func TestContextGluedToAnAddressStaysOut(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	cases := []struct{ in, value, plain string }{
		{"WHERE email='bob@corp.ee'", "bob@corp.ee", "bob@corp.ee"},
		{"GET /x?email=bob@corp.ee&x=1", "bob@corp.ee", "bob@corp.ee"},
		{"see /users/bob@corp.ee/edit", "bob@corp.ee", "bob@corp.ee"},
		{"mailto:bob@corp.ee", "bob@corp.ee", "bob@corp.ee"},
		{"mail zed=x@corp.ee now", "x@corp.ee", "x@corp.ee"},
	}
	for _, c := range cases {
		out, reps := tokenize(t, tz, c.in)
		require.Len(t, reps, 1, c.in)
		require.Equal(t, c.value, c.in[reps[0].Start:reps[0].End], c.in)
		want := mustToken(t, k, pii.EntityEmail, c.plain, "")
		require.Equal(t, want, reps[0].Token, c.in)
		again, more := tokenize(t, tz, out)
		require.Empty(t, more, c.in)
		require.Equal(t, out, again, c.in)
	}
}

func TestTextThatIsNoEmailStaysUntouched(t *testing.T) {
	tz := patternTokenizer(t)
	for _, in := range []string{
		`he said "hello" and left`,
		`"alice"@ nothing`,
		"a@b",
		"zed{q}@other",
		"x = y & z / 2",
		"it's {fine} | a=b ~ c?",
		"git@github.com:org/repo.git",
		"remote: git@gitlab.example.com:group/sub/repo.git (fetch)",
	} {
		out, reps := tokenize(t, tz, in)
		require.Empty(t, reps, "%q", in)
		require.Equal(t, in, out)
	}
}

// Each separator form is one phone, with the token of the plain number.
func TestPhoneSeparatorsAreFound(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	cases := []struct{ name, number, plain string }{
		{"double spaces", "+1  202  555  0143", "+1 202 555 0143"},
		{"four spaces", "+1    202 555 0143", "+1 202 555 0143"},
		{"newline", "+44 7700\n900123", "+44 7700 900123"},
		{"CRLF", "+44 7700\r\n900123", "+44 7700 900123"},
		{"hyphen U+2010", "+44‐7700‐900123", "+44 7700 900123"},
		{"non-breaking hyphen U+2011", "+44‑7700‑900123", "+44 7700 900123"},
		{"en dash", "+44–7700–900123", "+44 7700 900123"},
		{"em dash", "+44—7700—900123", "+44 7700 900123"},
		{"minus sign U+2212", "+44−7700−900123", "+44 7700 900123"},
		{"one slash after a space", "+49 89/1234 5678", "+49 89 1234 5678"},
		{"no-break space", "+44 7700 900123", "+44 7700 900123"},
		{"00 prefix", "0044 20 7946 0958", "+44 20 7946 0958"},
		{"00 prefix, fictional range", "0044 7700 900123", "+44 7700 900123"},
		{"one dot, UK", "+44.7700900123", "+44 7700 900123"},
		{"one dot, US", "+1.2025550143", "+1 202 555 0143"},
		{"one dot, France", "+33.123456789", "+33 1 23 45 67 89"},
		{"00 prefix, Italian leading zero", "0039 06 1234 5678", "+39 06 1234 5678"},
		{"00 prefix with dashes", "001-202-555-0143", "+1 202 555 0143"},
		{"US form with two spaces", "(202)  555-0143", "(202) 555-0143"},
		{"US form with four spaces", "(202)    555-0143", "(202) 555-0143"},
		{"US form with a slash", "(202) 555/0143", "(202) 555-0143"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := "call " + c.number + " now"
			require.Equal(t, 1, finalScan(t, tz, in))
			out, reps := tokenize(t, tz, in)
			require.Len(t, reps, 1)
			require.Equal(t, c.number, in[reps[0].Start:reps[0].End], "the whole number")
			want := mustToken(t, k, pii.EntityPhone, c.plain, "")
			require.Equal(t, want, reps[0].Token)
			require.Equal(t, "call "+want.Surface()+" now", out)
			again, more := tokenize(t, tz, out)
			require.Empty(t, more)
			require.Equal(t, out, again)
		})
	}
}

// Dates, versions, ids and other digit runs are not phones.
func TestPhoneShapesKeepFalsePositivesOut(t *testing.T) {
	tz := patternTokenizer(t)
	for _, in := range []string{
		"released 2026-11-12, patched 2026–11–12",
		"on 12/11/2026 at 10:30",
		"version 1.22.3, build 2026.11.12.0012",
		"order 0012-3456-7890 shipped",
		"id 00123456789 and 0000 0000 0000",
		"uuid 00112233-4455-6677-8899-aabbccddeeff",
		"sku A0044 20 7946 0958",
		"ref 10044 20 7946 0958",
		"range 1–2 and 3−4",
		"total 00 44",
		"+1 234 and 0044 12",
		"delta +30 2026/11/12",
		"date +12/11/2026",
		"7\t+12\t3456\t7890",
		"+100\n250\n3000\n42",
		"+1 202/555/0143",
		"+1202/5550143",
		"version 1.0.0+20130313144700",   // semver build metadata (QA F04)
		"location +48.858370, +2.294481", // coordinates (QA F05)
		"delta +0.00012345 BTC",          // a signed decimal (QA F06)
		"tx 00491711234567 ref",          // a 00 digit run with no separator (QA F15)
		"id 00442079460958",
		"build 2.1+447700900456",
	} {
		out, reps := tokenize(t, tz, in)
		require.Empty(t, reps, "%q", in)
		require.Equal(t, in, out)
	}
}

// The known limits of the phone shapes (the M5.1 plan): these are not found
// by shape. They are pinned so a change to them is a decision, not a drift.
func TestPhoneShapeKnownLimits(t *testing.T) {
	tz := patternTokenizer(t)
	for _, in := range []string{
		"call 00 44 20 7946 0958 now",  // a space after the 00
		"call x0044 20 7946 0958 now",  // 00 touching a letter
		"call +4420794609581234 now",   // digits glued past 15, no separator
		"call +1     202 555 0143 now", // five spaces between groups
		"id:1+447700900123",            // a + number glued to a digit
		"0+447700900123",               // a + number glued to a digit
		"call (202)     555-0143 now",  // five spaces in the US form
	} {
		_, reps := tokenize(t, tz, in)
		require.Empty(t, reps, "%q", in)
	}
}

// Each number is found up to where the text stops being a phone: a trailing
// '/', slash-joined digits after it, a second line break. Tokenizing twice
// gives the same text.
func TestAPhoneBeforeASlashOrALineBreak(t *testing.T) {
	tz := patternTokenizer(t)
	cases := []struct{ in, number string }{
		{"call +44 20 7946 0958/", "+44 20 7946 0958"},
		{"tel: +1 202 555 0143/", "+1 202 555 0143"},
		{"call +44 20 7946 0958/12/26 now", "+44 20 7946 0958"},
		// A number split over two line breaks keeps its last group out
		// (Known limits).
		{"call +44 20\n7946\n0958", "+44 20\n7946"},
		// A number glued to a slash and another number: both are tokens, and
		// the second pass finds nothing more.
		{"+00000000/0+00000000", "+00000000"},
	}
	for _, c := range cases {
		out, reps := tokenize(t, tz, c.in)
		require.NotEmpty(t, reps, "%q", c.in)
		require.Equal(t, c.number, c.in[reps[0].Start:reps[0].End], "%q", c.in)
		again, more := tokenize(t, tz, out)
		require.Empty(t, more, "%q", c.in)
		require.Equal(t, out, again, "%q", c.in)
	}
	// A US number padded across a search window is found the same as on its
	// own, or not at all: never in part.
	for _, pad := range []int{950, 960, 970, 980, 990, 1000} {
		in := strings.Repeat("x ", pad/2) + "(202)    555-0143 end"
		out, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, "pad %d", pad)
		require.Equal(t, "(202)    555-0143", in[reps[0].Start:reps[0].End], "pad %d", pad)
		require.NotContains(t, out, "555", "pad %d", pad)
	}
}

// A "+" number glued to a word, or to the phone before it, is a phone.
func TestAGluedPhoneAfterAWordIsFound(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	cases := []struct {
		in      string
		numbers []string
	}{
		{"Tel.+447700900123", []string{"+447700900123"}},
		{"Nr.+4915112345678", []string{"+4915112345678"}},
		{"+447700900456.+447700900457", []string{"+447700900456", "+447700900457"}},
	}
	for _, c := range cases {
		out, reps := tokenize(t, tz, c.in)
		require.Len(t, reps, len(c.numbers), "%q", c.in)
		for i, n := range c.numbers {
			require.Equal(t, n, c.in[reps[i].Start:reps[i].End], "%q", c.in)
			require.Equal(t, mustToken(t, k, pii.EntityPhone, n, ""), reps[i].Token, "%q", c.in)
		}
		again, more := tokenize(t, tz, out)
		require.Empty(t, more, "%q", c.in)
		require.Equal(t, out, again, "%q", c.in)
	}
}

// Phone shapes still taken for phones although they may be none: a "+"
// number is found by shape alone, whatever libphonenumber says of it (Known
// limits). Pinned so a change is a decision.
func TestPhoneShapeKnownFalsePositives(t *testing.T) {
	tz := patternTokenizer(t)
	for _, in := range []string{
		"score +12 3456 7890 points", // QA F14
		"id 0049 1234 5678",          // a 00 id of a possible length
	} {
		_, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, "%q", in)
	}
}

// A number after a rejected match is still found, as a second pass would
// find it once a token stands before it.
func TestAPhoneAfterARejectedMatchIsFound(t *testing.T) {
	tz := patternTokenizer(t)
	in := "+1 202/555/0143 0044 20 7946 0958"
	_, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, "0044 20 7946 0958", in[reps[0].Start:reps[0].End])
}

// A number found inside a rejected "00" run is still found.
func TestAPhoneAfterARejected00RunIsFound(t *testing.T) {
	tz := patternTokenizer(t)
	in := "0012 (202) 555-0143"
	_, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, "(202) 555-0143", in[reps[0].Start:reps[0].End])
}

// A phone gets one token whether the shape or the dictionary finds it, and
// the dictionary's hit takes in its '+'.
func TestAPhoneHasOneTokenFromTheDictionaryAndTheShape(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPhone, "+1 202 555 0143")
	byDict := pii.NewTokenizer(k, "", pii.NewDictionaryDetector(k, d, ""))
	byShape := pii.NewTokenizer(k, "", pii.PatternDetectors()...)
	want := mustToken(t, k, pii.EntityPhone, "+1 202 555 0143", "")
	require.Equal(t, "+1 ", want.Prefix)
	for _, number := range []string{"+1  202 555 0143", "+1 202 555 0143", "＋1 202 555 0143"} {
		in := "call " + number + " now"
		for name, tz := range map[string]*pii.Tokenizer{"dictionary": byDict, "shape": byShape} {
			out, reps := tokenize(t, tz, in)
			require.Len(t, reps, 1, "%s %q", name, number)
			require.Equal(t, number, in[reps[0].Start:reps[0].End], "%s %q: the '+' is taken in", name, number)
			require.Equal(t, want, reps[0].Token, "%s %q", name, number)
			require.Equal(t, "call "+want.Surface()+" now", out, "%s %q: no '+' left behind", name, number)
			again, more := tokenize(t, tz, out)
			require.Empty(t, more, "%s %q", name, number)
			require.Equal(t, out, again, "%s %q", name, number)
		}
	}
	// Only a phone takes in a '+': a name after one does not.
	d.add(k, pii.EntityPersonName, "Alice Tamm")
	in := "c+Alice Tamm"
	_, reps := tokenize(t, pii.NewTokenizer(k, "", pii.NewDictionaryDetector(k, d, "")), in)
	require.Len(t, reps, 1)
	require.Equal(t, "Alice Tamm", in[reps[0].Start:reps[0].End])
}

// A "00" number normalizes as its "+" form, in any region, and stays stable.
func TestThe00PrefixNormalizesAsPlus(t *testing.T) {
	for _, region := range []string{"", "GB", "US", "ID", "DE"} {
		require.Equal(t, "+447700900123", pii.Normalize(pii.EntityPhone, "0044 7700 900123", region), region)
		require.Equal(t, "+12025550143", pii.Normalize(pii.EntityPhone, "001 202 555 0143", region), region)
	}
	for _, v := range []string{"0-0-12", "00", "00abc", "0000123"} {
		once := pii.Normalize(pii.EntityPhone, v, "")
		require.Equal(t, once, pii.Normalize(pii.EntityPhone, once, ""), "%q", v)
	}
	require.Equal(t, "zed.q@other.com", pii.Normalize(pii.EntityEmail, "Zed.Q@Other。COM", ""))
}

// Long runs of what the patterns take, with no match at their end, take
// linear time (RE2, and every search goes on past what it read): a quadratic
// pass over these would not finish within the test timeout.
func TestLongNearMissesStayFast(t *testing.T) {
	tz := patternTokenizer(t)
	n := sized(1<<15, 1<<12)
	for _, in := range []string{
		strings.Repeat("a'", n) + "@",
		strings.Repeat(`"a`, n) + `"@`,
		"+1" + strings.Repeat(" ", n) + "2",
		strings.Repeat("00 ", n),
		strings.Repeat("0012 ", n),
		strings.Repeat("+1\n", n),
		strings.Repeat("a.", n) + "@corp",
		strings.Repeat(`"a".`, n) + "@corp",
	} {
		_, _, err := tz.Tokenize(in)
		require.NoError(t, err)
	}
}

// A text full of "00" runs that are no phones stays cheap: the length check
// turns them away before libphonenumber parses anything. The budget is
// relative to plain text of the same size, so it holds with -race too: these
// take about 2.5 times as long as plain text, parsing every run took 25 times.
func TestManyRejected00RunsStayCheap(t *testing.T) {
	tz := patternTokenizer(t)
	const maxSlowdown = 8
	size := sized(128<<10, 32<<10)
	// The fastest of three runs, so a pause in one does not fail the test.
	timed := func(unit string) time.Duration {
		in := strings.Repeat(unit, size/len(unit))
		best := time.Duration(math.MaxInt64)
		for range 3 {
			start := time.Now()
			_, _, err := tz.Tokenize(in)
			require.NoError(t, err)
			best = min(best, time.Since(start))
		}
		return best
	}
	plain := timed("abcd ")
	for _, unit := range []string{"0044 ", "0012 ", "0039 0"} {
		require.Less(t, timed(unit), maxSlowdown*plain, "%q", unit)
	}
}
