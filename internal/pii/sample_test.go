package pii_test

import (
	"fmt"
	"unicode"
)

// Exhaustive sweeps over characters run on a sample unless fullRun. The
// sample keeps what a fixed stride would drop: the first character of every
// contiguous run, the first of every class key, and a pinned list.

type categoryTable struct {
	name  string
	table *unicode.RangeTable
}

var categoryTables = func() []categoryTable {
	names := []string{"Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me", "Nd", "Nl", "No",
		"Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So", "Zs", "Zl", "Zp", "Cc", "Cf", "Co"}
	out := make([]categoryTable, 0, len(names))
	for _, name := range names {
		out = append(out, categoryTable{name, unicode.Categories[name]})
	}
	return out
}()

func categoryOf(r rune) string {
	for _, c := range categoryTables {
		if unicode.Is(c.table, r) {
			return c.name
		}
	}
	return "Cn"
}

func scriptOf(r rune) string {
	for name, table := range unicode.Scripts {
		if unicode.Is(table, r) {
			return name
		}
	}
	return ""
}

// scriptClass keys a character by general category and script.
func scriptClass(r rune) string { return categoryOf(r) + "/" + scriptOf(r) }

// blockClass keys a character by general category and its 256-character block,
// which is cheap enough to compute for the whole range.
func blockClass(r rune) string { return fmt.Sprintf("%s/%X", categoryOf(r), r>>8) }

// pinnedRunes are always checked: the digits and punctuation the detectors
// care most about, in their fullwidth, superscript and subscript forms.
func pinnedRunes() []rune {
	var out []rune
	for r := rune(0xFF10); r <= 0xFF19; r++ { // fullwidth digits
		out = append(out, r)
	}
	out = append(out, 0x00B9, 0x00B2, 0x00B3)
	for r := rune(0x2070); r <= 0x2079; r++ { // superscript digits
		out = append(out, r)
	}
	for r := rune(0x2080); r <= 0x2089; r++ { // subscript digits
		out = append(out, r)
	}
	return append(out, 0xFF3F, 0xFF20, 0xFF0E, 0xFF0C, 0xFF0B, 0xFF0D) // ＿ ＠ ． ， ＋ －
}

// sampleRunes returns all when fullRun, else every step-th character plus the
// first of each contiguous run, the first of each class, and the pinned ones.
// Order is kept.
func sampleRunes(all []rune, step int, class func(rune) string) []rune {
	if fullRun() {
		return all
	}
	pinned := map[rune]bool{}
	for _, r := range pinnedRunes() {
		pinned[r] = true
	}
	seen := map[string]bool{}
	var out []rune
	for i, r := range all {
		keep := i%step == 0 || pinned[r] || i == 0 || all[i-1] != r-1
		if k := class(r); !seen[k] {
			seen[k] = true
			keep = true
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}
