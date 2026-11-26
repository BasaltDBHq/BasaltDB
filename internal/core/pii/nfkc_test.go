package pii_test

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

// maxScanRune is the end of the range the NFKC test walks (planes 0 to 2).
const maxScanRune = 0x30000

// The generic form of every character, alone and inside a word, is stable when
// normalized again (golang.org/x/text folds Cherokee back and forth).
func TestGenericFormIsStableForEveryCharacter(t *testing.T) {
	var all []rune
	for r := rune(0); r < maxScanRune; r++ {
		if utf8.ValidRune(r) {
			all = append(all, r)
		}
	}
	for _, r := range sampleRunes(all, 7, blockClass, scriptClass) {
		// Alone, inside a word, and as the character between two combining
		// marks of different classes (230 then 220), which must not end up
		// out of canonical order.
		for _, s := range []string{string(r), "a" + string(r) + "b", "a\u0301" + string(r) + "\u0316b"} {
			once := pii.GenericForm(s)
			require.Equal(t, once, pii.GenericForm(once), "%U", r)
		}
	}
}
