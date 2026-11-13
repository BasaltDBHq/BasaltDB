package mcpcontract_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

// The request file and pasted blocks (CONTRACT.md): the constants below are
// the contract's, and the functions are a reference of its rules that the
// shared vectors in links/request-file.json are checked against.
const (
	requestPieceChars = 1800
	requestMaxBlocks  = 10
	requestHashBytes  = 16
)

type requestFileVectors struct {
	PieceChars int                  `json:"pieceChars"`
	MaxBlocks  int                  `json:"maxBlocks"`
	Vectors    []requestFileVector  `json:"vectors"`
	Pastes     []requestPasteCase   `json:"pastes"`
	Files      []requestFileContent `json:"files"`
}

type requestFileVector struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Base     string   `json:"base"`
	Text     string   `json:"text"`
	H        string   `json:"h"`
	Link     string   `json:"link"`
	FileName string   `json:"fileName"`
	Blocks   []string `json:"blocks"`
}

type requestPasteCase struct {
	Name    string   `json:"name"`
	Vector  int      `json:"vector"`
	Pastes  []string `json:"pastes"`
	Text    string   `json:"text"`
	Error   string   `json:"error"`
	Refused []int    `json:"refused"`
}

type requestFileContent struct {
	Name   string `json:"name"`
	Vector int    `json:"vector"`
	File   string `json:"file"`
	Text   string `json:"text"`
	Error  string `json:"error"`
}

func loadRequestFileVectors(t *testing.T) requestFileVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("links", "request-file.json"))
	require.NoError(t, err)
	var v requestFileVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func requestHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(sum[:requestHashBytes])
}

func requestBlocks(text string) []string {
	h := requestHash(text)
	var pieces []string
	for rest := text; rest != ""; {
		n := min(len(rest), requestPieceChars)
		pieces = append(pieces, rest[:n])
		rest = rest[n:]
	}
	if len(pieces) > requestMaxBlocks {
		return nil
	}
	blocks := make([]string, 0, len(pieces))
	for i, p := range pieces {
		blocks = append(blocks, fmt.Sprintf("basalt-request %d/%d %s %d\n%s", i+1, len(pieces), h, len(p), p))
	}
	return blocks
}

var (
	blockHeader = regexp.MustCompile(`(?:^|.* )basalt-request (\d+)/(\d+) ([A-Za-z0-9_-]{22}) (\d+)$`)
	pieceLine   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	pasteBreaks = regexp.MustCompile("\r\n|\n|\r|\u2028")
	quoteMarks  = strings.NewReplacer(">", "", "*", "", "\\", "")
)

// blockAssembler is the page's paste box: it keeps the blocks pasted so far
// for the link's h.
type blockAssembler struct {
	h      string
	n      int
	pieces map[int]string
}

type pastedBlock struct {
	i, n  int
	size  int
	h     string
	piece strings.Builder
	open  bool
}

func cleanLine(line string) string {
	return strings.TrimFunc(quoteMarks.Replace(line), func(r rune) bool { return unicode.Is(unicode.White_Space, r) })
}

// add reads one paste and reports whether the page refuses it: no header,
// or a block it refuses (another h, another count, or a piece shorter than
// its header's length).
func (a *blockAssembler) add(paste string) bool {
	var blocks []*pastedBlock
	var cur *pastedBlock
	for _, line := range pasteBreaks.Split(paste, -1) {
		clean := cleanLine(line)
		if m := blockHeader.FindStringSubmatch(clean); m != nil {
			i, _ := strconv.Atoi(m[1])
			n, _ := strconv.Atoi(m[2])
			size, _ := strconv.Atoi(m[4])
			cur = &pastedBlock{i: i, n: n, size: size, h: m[3], open: true}
			blocks = append(blocks, cur)
			continue
		}
		if cur == nil || !cur.open || cur.piece.Len() >= cur.size {
			continue
		}
		if !pieceLine.MatchString(clean) {
			cur.open = false
			continue
		}
		cur.piece.WriteString(clean)
	}
	if len(blocks) == 0 {
		return true
	}
	refused := false
	for _, b := range blocks {
		piece := b.piece.String()
		if b.size < 1 || b.size > requestPieceChars || len(piece) < b.size {
			refused = true // cut short
			continue
		}
		piece = piece[:b.size]
		if b.h != a.h || b.i < 1 || b.i > b.n || b.n > requestMaxBlocks || (a.n != 0 && b.n != a.n) {
			refused = true
			continue
		}
		a.n = b.n
		a.pieces[b.i] = piece
	}
	return refused
}

// text returns the joined request, or the fixture's error token.
func (a *blockAssembler) text() (string, string) {
	if a.n == 0 || len(a.pieces) < a.n {
		return "", "INCOMPLETE"
	}
	var b strings.Builder
	for i := 1; i <= a.n; i++ {
		b.WriteString(a.pieces[i])
	}
	if requestHash(b.String()) != a.h {
		return "", "MISMATCH"
	}
	return b.String(), ""
}

func readRequestFile(content, h string) (string, string) {
	content = strings.TrimPrefix(content, "\ufeff")
	text := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.White_Space, r) {
			return -1
		}
		return r
	}, content)
	if requestHash(text) != h {
		return "", "MISMATCH"
	}
	return text, ""
}

var requestTextPattern = regexp.MustCompile(`^2\.[A-Za-z0-9_-]+$`)

// TestRequestFileVectors checks each vector's h, hash link, file name and
// blocks follow the contract, and that the vectors cover one block, several,
// exactly the most blocks, and a request over it that goes as a file only.
func TestRequestFileVectors(t *testing.T) {
	t.Parallel()
	v := loadRequestFileVectors(t)
	require.Equal(t, requestPieceChars, v.PieceChars)
	require.Equal(t, requestMaxBlocks, v.MaxBlocks)
	counts := map[int]bool{}
	for _, c := range v.Vectors {
		require.Regexp(t, requestTextPattern, c.Text, c.Name)
		require.Equal(t, requestHash(c.Text), c.H, c.Name)
		require.Len(t, c.H, 22, c.Name)
		path, kind := "approvals", "approval"
		if c.Kind == "REVERT" {
			path, kind = "reverts", "revert"
		}
		require.Equal(t, c.Base+"/"+path+"/"+c.ID+"#h="+c.H, c.Link, c.Name)
		require.Equal(t, "basalt-"+kind+"-"+c.ID+".txt", c.FileName, c.Name)
		require.Equal(t, requestBlocks(c.Text), c.Blocks, c.Name)
		counts[len(c.Blocks)] = true
	}
	for _, n := range []int{0, 1, 3, requestMaxBlocks} {
		require.True(t, counts[n], "no vector with %d blocks", n)
	}
}

// TestRequestFilePastes runs the paste and file cases through the reference
// page rules.
func TestRequestFilePastes(t *testing.T) {
	t.Parallel()
	v := loadRequestFileVectors(t)
	for _, c := range v.Pastes {
		vec := v.Vectors[c.Vector]
		a := &blockAssembler{h: vec.H, pieces: map[int]string{}}
		refused := []int{}
		for i, p := range c.Pastes {
			if a.add(p) {
				refused = append(refused, i)
			}
		}
		want := c.Refused
		if want == nil {
			want = []int{}
		}
		require.Equal(t, want, refused, c.Name)
		text, errToken := a.text()
		require.Equal(t, c.Error, errToken, c.Name)
		require.Equal(t, c.Text, text, c.Name)
	}
	for _, c := range v.Files {
		text, errToken := readRequestFile(c.File, v.Vectors[c.Vector].H)
		require.Equal(t, c.Error, errToken, c.Name)
		require.Equal(t, c.Text, text, c.Name)
	}
}
