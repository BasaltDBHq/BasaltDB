package pii_test

import (
	"strings"
	"testing"

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
		{"slash", "mail zed/x@corp.ee now", "zed/x@corp.ee", "zed/x@corp.ee"},
		{"equals", "mail zed=x@corp.ee now", "zed=x@corp.ee", "zed=x@corp.ee"},
		{"question mark", "mail zed?x@corp.ee now", "zed?x@corp.ee", "zed?x@corp.ee"},
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

func TestTextThatIsNoEmailStaysUntouched(t *testing.T) {
	tz := patternTokenizer(t)
	for _, in := range []string{
		`he said "hello" and left`,
		`"alice"@ nothing`,
		"a@b",
		"zed{q}@other",
		"x = y & z / 2",
		"it's {fine} | a=b ~ c?",
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
		{"newline", "+44 7700\n900123", "+44 7700 900123"},
		{"tab and newline", "+44\t7700\r\n900123", "+44 7700 900123"},
		{"hyphen U+2010", "+44‐7700‐900123", "+44 7700 900123"},
		{"non-breaking hyphen U+2011", "+44‑7700‑900123", "+44 7700 900123"},
		{"en dash", "+44–7700–900123", "+44 7700 900123"},
		{"em dash", "+44—7700—900123", "+44 7700 900123"},
		{"minus sign U+2212", "+44−7700−900123", "+44 7700 900123"},
		{"slash", "+1 202/555/0143", "+1 202 555 0143"},
		{"no-break space", "+44 7700 900123", "+44 7700 900123"},
		{"00 prefix", "0044 20 7946 0958", "+44 20 7946 0958"},
		{"00 prefix without spaces", "00442079460958", "+44 20 7946 0958"},
		{"00 prefix with dashes", "001-202-555-0143", "+1 202 555 0143"},
		{"US form with two spaces", "(202)  555-0143", "(202) 555-0143"},
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
	} {
		out, reps := tokenize(t, tz, in)
		require.Empty(t, reps, "%q", in)
		require.Equal(t, in, out)
	}
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
	const n = 1 << 16
	for _, in := range []string{
		strings.Repeat("a'", n) + "@",
		strings.Repeat(`"a`, n) + `"@`,
		"+1" + strings.Repeat(" ", n) + "2",
		strings.Repeat("00 ", n),
		strings.Repeat("0012 ", n),
		strings.Repeat("+1\n", n),
		strings.Repeat("a.", n) + "@corp",
	} {
		_, _, err := tz.Tokenize(in)
		require.NoError(t, err)
	}
}
