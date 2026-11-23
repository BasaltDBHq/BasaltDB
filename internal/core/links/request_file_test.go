package links_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

const requestVectorsFile = "../../../api/mcp/links/request-file.json"

type requestVector struct {
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

// TestHashLinkRunsTheSharedVectors builds each vector's hash link and request
// file from its long link (CONTRACT.md, The request file and pasted blocks).
func TestHashLinkRunsTheSharedVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(requestVectorsFile)
	require.NoError(t, err)
	var file struct {
		PieceChars int             `json:"pieceChars"`
		MaxBlocks  int             `json:"maxBlocks"`
		Vectors    []requestVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.Equal(t, links.RequestPieceChars, file.PieceChars)
	require.Equal(t, links.RequestMaxBlocks, file.MaxBlocks)
	require.NotEmpty(t, file.Vectors)
	for _, v := range file.Vectors {
		id := uuid.MustParse(v.ID)
		page, name := links.Approval(v.Base, id), links.ApprovalFile(id)
		if v.Kind == "REVERT" {
			page, name = links.Revert(v.Base, id), links.RevertFile(id)
		}
		link, rf, err := links.HashLink(page+"#"+v.Text, name)
		require.NoError(t, err, v.Name)
		require.Equal(t, v.Link, link, v.Name)
		require.Equal(t, v.H, links.RequestHash(v.Text), v.Name)
		require.Equal(t, links.RequestFile{FileName: v.FileName, Text: v.Text, Blocks: v.Blocks}, rf, v.Name)
	}
}

func TestHashLinkRefusesALinkWithoutARequest(t *testing.T) {
	t.Parallel()
	_, _, err := links.HashLink("https://portal.basaltvault.app/approvals/x", "f.txt")
	require.Error(t, err)
	_, _, err = links.HashLink("https://portal.basaltvault.app/approvals/x#", "f.txt")
	require.Error(t, err)
}
