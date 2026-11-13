package pii_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// maxScanRune is the end of the range the NFKC test walks (planes 0 to 2).
const maxScanRune = 0x30000

// nfkcChanged lists every character NFKC changes, from U+0000 to U+30000.
func nfkcChanged() []rune {
	var out []rune
	for r := rune(0); r < maxScanRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		if s := string(r); norm.NFKC.String(s) != s {
			out = append(out, r)
		}
	}
	return out
}

// makesWordOrMark reports whether r, folded the way detection folds it (NFKC,
// case folding, NFKC), holds a letter or digit, or starts with a combining
// mark. Glued to a name, such a character changes the word itself ("Tammª" is
// "tamma"; U+037A folds to a space and "ι"), so the name is no longer the same
// text.
func makesWordOrMark(r rune) bool {
	s := norm.NFKC.String(cases.Fold().String(norm.NFKC.String(string(r))))
	if first, _ := utf8.DecodeRuneInString(s); unicode.IsMark(first) {
		return true
	}
	return strings.IndexFunc(s, func(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) }) >= 0
}

// Every character NFKC changes, glued between two values, leaves neither value
// in the output, and tokenizing never fails closed on it.
func TestNoValueLeaksAroundAnyNFKCCharacter(t *testing.T) {
	tz := newTokenizer(t)
	changed := nfkcChanged()
	require.Greater(t, len(changed), 4000, "sanity: NFKC changes thousands of characters")

	type pair struct {
		name, left, right string
		leaks             []string
		skip              func(rune) bool
	}
	pairs := []pair{
		{"emails", "fixture.alice.tamm@gmail.com", "mari.kask@fixture-corp.example", []string{"alice", "mari", "kask"}, nil},
		{"phones", "+44 7700 900123", "+1 202 555 0143", []string{"900123", "555 0143"}, nil},
		{"names", "Alice Tamm", "Jaan Rebane", []string{"Alice", "Tamm", "Jaan", "Rebane"}, makesWordOrMark},
		// Every character, with a space on each side, leaves both names found.
		{"names spaced", "Alice Tamm ", " Jaan Rebane", []string{"Alice", "Tamm", "Jaan", "Rebane"}, nil},
	}
	for _, p := range pairs {
		checked := 0
		for i := 0; i < len(changed); i += stride(8) {
			r := changed[i]
			if p.skip != nil && p.skip(r) {
				continue
			}
			checked++
			in := p.left + string(r) + p.right
			out, _, err := tz.Tokenize(in)
			require.NoError(t, err, "%s around %U", p.name, r)
			for _, v := range p.leaks {
				require.NotContains(t, out, v, "%s around %U", p.name, r)
			}
		}
		t.Logf("%s: %d characters checked", p.name, checked)
	}
}

func TestANameAfterASpacingMarkIsFound(t *testing.T) {
	tz := newTokenizer(t)
	for _, sep := range []string{"¨", "¯", "´", "˘"} {
		in := "Alice Tamm" + sep + "Jaan Rebane"
		out, reps := tokenize(t, tz, in)
		require.Len(t, reps, 2, "%q", sep)
		require.NotContains(t, out, "Jaan", "%q", sep)
	}
}

func TestOverlappingSpansAfterFoldingAreMergedNotDropped(t *testing.T) {
	tz := newTokenizer(t)
	in := "alice@corp.ee¼bob@corp.ee"
	out, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1, "both addresses widen into the one character; they become one token")
	require.Equal(t, in, in[reps[0].Start:reps[0].End])
	require.NotContains(t, out, "bob")
	require.Zero(t, finalScan(t, tz, out))
}

// The generic form of every character, alone and inside a word, is stable when
// normalized again (golang.org/x/text folds Cherokee back and forth).
func TestGenericFormIsStableForEveryCharacter(t *testing.T) {
	for r := rune(0); r < maxScanRune; r += rune(stride(7)) {
		if !utf8.ValidRune(r) {
			continue
		}
		// Alone, inside a word, and as the character between two combining
		// marks of different classes (230 then 220), which must not end up
		// out of canonical order.
		for _, s := range []string{string(r), "a" + string(r) + "b", "a\u0301" + string(r) + "\u0316b"} {
			once := pii.GenericForm(s)
			require.Equal(t, once, pii.GenericForm(once), "%U", r)
		}
	}
}
