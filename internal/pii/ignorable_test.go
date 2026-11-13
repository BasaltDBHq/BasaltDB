package pii_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// hiders are the invisible characters the review used: zero-width space and
// joiner, soft hyphen, word joiner, BOM and right-to-left override.
var hiders = []rune{0x200B, 0x200D, 0x00AD, 0x2060, 0xFEFF, 0x202E}

// ignorables lists every format character, variation selector and other
// default-ignorable code point (Unicode's Default_Ignorable_Code_Point, plus
// the format characters it leaves out).
func ignorables() []rune {
	var out []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) {
			out = append(out, r)
		}
	}
	return out
}

// tokenIDRe matches token ids, whose base32 can spell any short word.
var tokenIDRe = regexp.MustCompile(`pii\d+_[A-Z2-7]{12}|(?:Person|Address) [A-Z2-7]{12}`)

// withoutTokens removes token ids, so a leak check reads only what is left of
// the input.
func withoutTokens(s string) string { return tokenIDRe.ReplaceAllString(s, " ") }

// visible removes every ignorable character, so a leak check sees the text a
// model would read.
func visible(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) {
			return -1
		}
		return r
	}, s)
}

func TestAnInvisibleCharacterInsideAValueDoesNotHideIt(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := newTokenizer(t)
	for _, h := range hiders {
		c := string(h)
		cases := []struct {
			in, plain string
			typ       pii.EntityType
		}{
			{"alice@co" + c + "rp.ee", "alice@corp.ee", pii.EntityEmail},
			{"alice" + c + "@corp.ee", "alice@corp.ee", pii.EntityEmail},
			{"ali" + c + "ce@corp.ee", "alice@corp.ee", pii.EntityEmail},
			{"+4477" + c + "00900456", "+447700900456", pii.EntityPhone},
		}
		for _, tc := range cases {
			require.Positive(t, finalScan(t, tz, tc.in), "%U %q", h, tc.in)
			out, reps := tokenize(t, tz, tc.in)
			require.Len(t, reps, 1, "%U %q", h, tc.in)
			require.Equal(t, tc.in, tc.in[reps[0].Start:reps[0].End], "%U: the whole value", h)
			require.Equal(t, mustToken(t, k, tc.typ, tc.plain, ""), reps[0].Token, "%U: the same token as without it", h)
			require.Equal(t, reps[0].Token.Surface(), out, "%U: nothing of the value is left", h)
		}
	}
}

// Every ignorable character, at every position inside an email, a phone and
// a name, hides nothing.
func TestNoIgnorableCharacterHidesAValue(t *testing.T) {
	tz := newTokenizer(t)
	values := []struct {
		value string
		leaks []string
	}{
		{"fixture.alice.tamm@gmail.com", []string{"fixture", "alice", "tamm"}},
		{"+44 7700 900123", []string{"7700", "900123"}},
		{"Alice Tamm", []string{"alice", "tamm"}},
	}
	chars := ignorables()
	require.Greater(t, len(chars), 4000, "sanity: the tag and variation selector blocks alone are thousands")
	for _, v := range values {
		// One subtest per position, in parallel: about 230,000 calls in all (an eighth of them unless
		// BASALTDB_TEST_FULL=1).
		for i := range len(v.value) + 1 {
			t.Run(fmt.Sprintf("%s/%d", v.value, i), func(t *testing.T) {
				t.Parallel()
				// Each position takes a different eighth of the characters
				// (all of them in a full run), so every one is tried at some
				// position.
				first, step := i%8, 8
				if fullRun() {
					first, step = 0, 1
				}
				for ci := first; ci < len(chars); ci += step {
					r := chars[ci]
					in := v.value[:i] + string(r) + v.value[i:]
					out, _, err := tz.Tokenize(in)
					require.NoError(t, err, "%U at %d of %q", r, i, v.value)
					seen := strings.ToLower(withoutTokens(visible(out)))
					for _, leak := range v.leaks {
						require.NotContains(t, seen, leak, "%U at %d of %q", r, i, v.value)
					}
				}
			})
		}
	}
}
