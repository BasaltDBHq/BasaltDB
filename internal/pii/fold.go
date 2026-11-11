package pii

import (
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// foldedView is the text detectors see: the original folded the way values
// are normalized (NFKC, case folding, NFKC), so a full-width or differently
// cased value is found by the same patterns and n-grams as its plain form.
// It is built one normalization segment at a time, and pieces maps each
// segment's folded bytes back to its original bytes.
type foldedView struct {
	text   string
	pieces []foldPiece // segment starts, plus a closing entry at both ends
}

// foldPiece is where one segment starts in the original and in the folded text.
type foldPiece struct{ orig, fold int }

// foldForDetection builds the folded view of s.
func foldForDetection(s string) foldedView {
	var b strings.Builder
	b.Grow(len(s))
	caser := cases.Fold()
	pieces := make([]foldPiece, 0, len(s)+1)
	for pos := 0; pos < len(s); {
		n := norm.NFKC.NextBoundaryInString(s[pos:], true)
		if n <= 0 {
			n = len(s) - pos
		}
		pieces = append(pieces, foldPiece{orig: pos, fold: b.Len()})
		writeFolded(&b, &caser, s[pos:pos+n])
		pos += n
	}
	pieces = append(pieces, foldPiece{orig: len(s), fold: b.Len()})
	return foldedView{text: b.String(), pieces: pieces}
}

// writeFolded writes one segment folded. ASCII takes a fast path: NFKC leaves
// it alone and folding is lower case.
func writeFolded(b *strings.Builder, caser *cases.Caser, seg string) {
	if len(seg) == 1 && seg[0] < utf8.RuneSelf {
		c := seg[0]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
		return
	}
	b.WriteString(nfkcCasefold(caser, seg))
}

// original maps a span of the folded text to the original bytes it came from.
// A span that starts or ends inside a segment's folded output (one character
// can fold to several) widens to the whole segment, so it never covers less
// of the original than was found.
func (v foldedView) original(sp Span) (int, int) {
	return v.pieces[v.pieceAt(sp.Start)].orig, v.pieces[v.pieceAt(sp.End-1)+1].orig
}

// pieceAt is the index of the segment whose folded bytes hold offset i: the
// last piece starting at or before i (empty pieces start where the next one does).
func (v foldedView) pieceAt(i int) int {
	return sort.Search(len(v.pieces), func(k int) bool { return v.pieces[k].fold > i }) - 1
}
