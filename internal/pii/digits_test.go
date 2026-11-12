package pii_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// inDigits writes the ASCII digits of s with the decimal digits that start at
// zero, keeping every other character.
func inDigits(s string, zero rune) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return zero + (r - '0')
		}
		return r
	}, s)
}

// digitZeros lists the zero of every block of ten decimal digits (Nd).
func digitZeros() []rune {
	var out []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.Is(unicode.Nd, r) && !unicode.Is(unicode.Nd, r-1) {
			for z := r; unicode.Is(unicode.Nd, z); z += 10 {
				out = append(out, z)
			}
		}
	}
	return out
}

func TestMarksAndNonASCIIDigitsDoNotHideAPhone(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := newTokenizer(t)
	plain := mustToken(t, k, pii.EntityPhone, "+447700900456", "")
	for _, in := range []string{
		"+4477\u030100900456",             // a combining acute on a digit
		"+4477009004\u20e356",             // a keycap mark
		"+44 7700 900456\u20e3",           // a keycap at the end
		inDigits("+447700900456", 0x0660), // Arabic-Indic
		inDigits("+447700900456", 0x06F0), // Persian
		inDigits("+447700900456", 0x0966), // Devanagari
	} {
		require.Positive(t, finalScan(t, tz, in), "%q", in)
		out, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, "%q", in)
		require.Equal(t, in, in[reps[0].Start:reps[0].End], "%q: the whole number", in)
		require.Equal(t, plain, reps[0].Token, "%q: the token of the plain number", in)
		require.Equal(t, plain.Surface(), out, "%q", in)
	}
}

func TestEveryDecimalDigitBlockIsAPhone(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := newTokenizer(t)
	plain := mustToken(t, k, pii.EntityPhone, "+44 7700 900456", "")
	zeros := digitZeros()
	require.Greater(t, len(zeros), 60, "sanity: Unicode has dozens of digit blocks")
	for _, z := range zeros {
		in := "call " + inDigits("+44 7700 900456", z) + " now"
		out, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, "%U", z)
		require.Equal(t, plain, reps[0].Token, "%U", z)
		require.Equal(t, "call "+plain.Surface()+" now", out, "%U", z)
	}
}

// Every combining mark (Mn, Me), after every character of a phone and an
// email, hides nothing of either.
func TestNoCombiningMarkHidesAPhoneOrAnEmail(t *testing.T) {
	tz := newTokenizer(t)
	var marks []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.In(r, unicode.Mn, unicode.Me) {
			marks = append(marks, r)
		}
	}
	require.Greater(t, len(marks), 1500)
	values := []struct {
		value string
		leaks []string
	}{
		{"+44 7700 900123", []string{"7700", "900123"}},
		{"fixture.alice.tamm@gmail.com", []string{"fixture", "alice", "tamm"}},
	}
	for _, v := range values {
		for i := 1; i <= len(v.value); i++ {
			t.Run(fmt.Sprintf("%s/%d", v.value, i), func(t *testing.T) {
				t.Parallel()
				for _, m := range marks {
					in := v.value[:i] + string(m) + v.value[i:]
					out, _, err := tz.Tokenize(in)
					require.NoError(t, err, "%U after %d of %q", m, i, v.value)
					seen := strings.ToLower(strings.Map(func(r rune) rune {
						if unicode.In(r, unicode.Mn, unicode.Me) {
							return -1
						}
						return r
					}, withoutTokens(visible(out))))
					for _, leak := range v.leaks {
						require.NotContains(t, seen, leak, "%U after %d of %q", m, i, v.value)
					}
				}
			})
		}
	}
}

// Names keep their marks: the dictionary still matches "José" written with a
// combining accent against its stored form.
func TestNameDetectionKeepsMarks(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPersonName, "José Pérez")
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
	for _, in := range []string{"José Pérez", "Jose\u0301 Pe\u0301rez"} {
		_, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, "%q", in)
	}
	_, reps := tokenize(t, tz, "Jose Perez")
	require.Empty(t, reps, "a name without its accents is another name")
}

// A last group of one digit belongs to the number, ASCII or not.
func TestAOneDigitLastGroupIsPartOfThePhone(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := newTokenizer(t)
	plain := mustToken(t, k, pii.EntityPhone, "+447700900456", "")
	for _, in := range []string{"+44 7700 900 45 6", inDigits("+44 7700 900 45 6", 0x0660)} {
		out, reps := tokenize(t, tz, "call "+in+" now")
		require.Len(t, reps, 1, "%q", in)
		require.Equal(t, plain, reps[0].Token, "%q", in)
		require.Equal(t, "call "+plain.Surface()+" now", out, "%q", in)
	}
}
