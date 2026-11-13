package pii_test

import (
	"fmt"
	"sync"
	"unicode"
)

// Exhaustive sweeps over characters run on a sample unless fullRun. The
// sample keeps what a fixed stride would drop: the first character of every
// contiguous run, the first of every class key, and a pinned list.

// charInfo holds the general category and script of every character below
// maxScanRune, filled once from the unicode tables (a lookup per character
// would search every script table).
var charInfo struct {
	once     sync.Once
	category [maxScanRune]string
	script   [maxScanRune]string
}

func loadCharInfo() {
	charInfo.once.Do(func() {
		fill := func(dst *[maxScanRune]string, name string, table *unicode.RangeTable) {
			for _, rg := range table.R16 {
				for r := rune(rg.Lo); r <= rune(rg.Hi) && r < maxScanRune; r += rune(rg.Stride) {
					dst[r] = name
				}
			}
			for _, rg := range table.R32 {
				for r := rune(rg.Lo); r <= rune(rg.Hi) && r < maxScanRune; r += rune(rg.Stride) {
					dst[r] = name
				}
			}
		}
		for name, table := range unicode.Categories {
			if len(name) == 2 { // Lu, Mn, ...; not the one-letter groups
				fill(&charInfo.category, name, table)
			}
		}
		for name, table := range unicode.Scripts {
			fill(&charInfo.script, name, table)
		}
	})
}

// scriptClass keys a character by general category and script.
func scriptClass(r rune) string {
	loadCharInfo()
	return charInfo.category[r] + "/" + charInfo.script[r]
}

// blockClass keys a character by general category and its 256-character block.
func blockClass(r rune) string {
	loadCharInfo()
	return fmt.Sprintf("%s/%X", charInfo.category[r], r>>8)
}

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
// first of each contiguous run, the first of each class under every class
// function, and the pinned ones. Order is kept.
func sampleRunes(all []rune, step int, classes ...func(rune) string) []rune {
	if fullRun() {
		return all
	}
	pinned := map[rune]bool{}
	for _, r := range pinnedRunes() {
		pinned[r] = true
	}
	seen := make([]map[string]bool, len(classes))
	for i := range seen {
		seen[i] = map[string]bool{}
	}
	var out []rune
	for i, r := range all {
		keep := i%step == 0 || pinned[r] || i == 0 || all[i-1] != r-1
		for ci, class := range classes {
			if k := class(r); !seen[ci][k] {
				seen[ci][k] = true
				keep = true
			}
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}
