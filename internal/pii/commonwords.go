package pii

import (
	_ "embed"
	"slices"
	"strings"
	"sync"
)

// commonWordsFile is about 12,000 common English words (12dicts 2+2+3frq,
// frequency tiers 1 to 14; source and notices in words/). It adds about 100 KB
// to the binary; the parsed list is a slice of substrings of it, about 200 KB
// of heap, built on first use.
//
//go:embed words/common-words.txt
var commonWordsFile string

// extraCommonWords are names that are everyday words but are capitalized, so
// left out, in the source list (months), or rarer there than in names.
var extraCommonWords = []string{
	"april", "june", "max", "amber", "dawn", "joy", "faith", "grace", "hope",
	"rose", "will", "may", "mark", "bill", "art", "summer", "page", "lane",
}

// commonWordList is the sorted common-word list in generic form.
var commonWordList = sync.OnceValue(func() []string {
	var words []string
	for line := range strings.Lines(commonWordsFile) {
		w := strings.TrimSpace(line)
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		words = append(words, w)
	}
	words = append(words, extraCommonWords...)
	slices.Sort(words)
	return slices.Compact(words)
})

// isCommonWord reports whether form (a generic form) is a common word. A
// single-word dictionary value that is one is matched only inside a longer
// n-gram (the design's common-word rule), so "the total price" and "park the
// car" are left alone while "Alice Price" is still a name.
func isCommonWord(form string) bool {
	_, ok := slices.BinarySearch(commonWordList(), form)
	return ok
}

// IsCommonWord reports whether value, in its generic form, is one common word:
// a dictionary value that is matched only as part of a full name, never alone.
// basalt classify --check reports such values.
func IsCommonWord(value string) bool { return isCommonWord(GenericForm(value)) }
