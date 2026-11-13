package links

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// The request file and pasted blocks (CONTRACT.md): over the link budget with
// no short link, the engine hands over a hash link, <page>#h=<h>, and the
// request beside it, as a file and as numbered text blocks.
const (
	// RequestPieceChars is the most characters of the request one block
	// carries: with its header it stays under Discord's 2000-character
	// message limit, the smallest common one.
	RequestPieceChars = 1800
	// RequestMaxBlocks is the most blocks a request is cut into; a longer
	// request goes as a file only.
	RequestMaxBlocks = 10
	// requestHashBytes is how much of sha256(request text) h keeps.
	requestHashBytes = 16
	hashFragment     = "#h="
)

// RequestFile is the request beside a hash link (api/mcp/links/request-file.schema.json).
type RequestFile struct {
	FileName string `json:"fileName"`
	Text     string `json:"text"`
	// Blocks is Text cut into numbered pieces; nil above RequestMaxBlocks.
	Blocks []string `json:"blocks,omitempty"`
}

// ApprovalFile and RevertFile name an item's request file.
func ApprovalFile(id uuid.UUID) string { return "basalt-approval-" + id.String() + ".txt" }
func RevertFile(id uuid.UUID) string   { return "basalt-revert-" + id.String() + ".txt" }

// RequestHash is h: base64url, without padding, of the first 16 bytes of
// sha256(text).
func RequestHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(sum[:requestHashBytes])
}

// HashLink turns a long link, <page>#<request text>, into its hash link,
// <page>#h=<h>, and the request file named fileName. A long link always
// carries a fragment (approval.Request.URL, revert links); one without is
// a programming error.
func HashLink(long, fileName string) (string, RequestFile, error) {
	page, text, ok := strings.Cut(long, "#")
	if !ok || text == "" {
		return "", RequestFile{}, fmt.Errorf("long link has no request fragment")
	}
	h := RequestHash(text)
	return page + hashFragment + h, RequestFile{FileName: fileName, Text: text, Blocks: requestBlocks(text, h)}, nil
}

func requestBlocks(text, h string) []string {
	n := (len(text) + RequestPieceChars - 1) / RequestPieceChars
	if n > RequestMaxBlocks {
		return nil
	}
	blocks := make([]string, 0, n)
	for i := range n {
		piece := text[i*RequestPieceChars : min(len(text), (i+1)*RequestPieceChars)]
		blocks = append(blocks, fmt.Sprintf("basalt-request %d/%d %s\n%s", i+1, n, h, piece))
	}
	return blocks
}
