package pii_test

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

var fuzzSeeds = []string{
	"Customer Alice Tamm (fixture.alice.tamm@gmail.com, +44 7700 900123)",
	"Jose\u0301 Pe\u0301rez, Pa\u0308rnu mnt 99, Tallinn",
	"İstanbul ΟΔΥΣΣΕΥΣ Straße Ali\u200bce Tamm",
	"pii1_AAAAAAAAAAAA@redacted.invalid +44 pii1_BBBBBBBBBBBB Person CCCCCCCCCCCC",
	"+447700900456 (202) 555-0143 0812-3456-7890",
	"+447700900456x123",
	"+447700900456_",
	"+44 7700 900456ext2",
	"\uff21\uff4c\uff45\uff58\uff41\uff4e\uff44\uff52\uff41 \uff2a\uff4f\uff4e\uff45\uff53 \uff41\uff4c\uff49\uff43\uff45@example.com \uff0b\uff14\uff14\uff17\uff17\uff10\uff10\uff19\uff10\uff10\uff14\uff15\uff16",
	"alice@ex\u00e4mple.ee xpii1_ABCDEFGHIJKL@corp.com",
	"",
}

// Normalizing twice changes nothing, for every type.
func FuzzNormalizeIsIdempotent(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip()
		}
		for _, region := range []string{"", "ID", "US"} {
			for _, typ := range pii.EntityTypes() {
				once := pii.Normalize(typ, s, region)
				require.Equal(t, once, pii.Normalize(typ, once, region), "%s %s %q", typ, region, s)
			}
		}
	})
}

// Tokenize never fails with the built-in detectors, its replacements point at
// the input in order, and tokenizing its output again replaces nothing.
func FuzzTokenizeIsIdempotent(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip()
		}
		tz, _ := newTokenizer(t)
		out, reps, err := tz.Tokenize(s)
		require.NoError(t, err)
		last := 0
		for _, r := range reps {
			require.LessOrEqual(t, last, r.Start)
			require.Less(t, r.Start, r.End)
			last = r.End
		}
		again, more, err := tz.Tokenize(out)
		require.NoError(t, err)
		require.Empty(t, more, "%q -> %q", s, out)
		require.Equal(t, out, again)
	})
}
