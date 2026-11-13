package shim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	rfName  = "basalt-approval-0193a4c2-7d1e-7c3a-9f00-0000000000d4.txt"
	rfText  = "2.AbCd_-Ef"
	rfName2 = "basalt-revert-0193a4c2-7d1e-7c3a-9f00-0000000000b2.txt"
)

// toolAnswer is a tools/call answer as the engine writes it: the body as
// indented JSON text.
func toolAnswer(t *testing.T, body any) []byte {
	t.Helper()
	text, err := json.MarshalIndent(body, "", "  ")
	require.NoError(t, err)
	line, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7,
		"result": map[string]any{"content": []map[string]any{{"type": "text", "text": string(text)}}, "isError": true},
	})
	require.NoError(t, err)
	return line
}

func answerText(t *testing.T, line []byte) string {
	t.Helper()
	var msg struct {
		ID     json.Number `json:"id"`
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(line, &msg))
	require.Equal(t, json.Number("7"), msg.ID)
	require.True(t, msg.Result.IsError)
	return msg.Result.Content[0].Text
}

func TestAttachWritesTheRequestFileAndAddsItsPath(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "requests")
	f := requestFiles{dir: dir, now: time.Now}
	body := map[string]any{
		"code": "APPROVAL_REQUIRED",
		"approval": map[string]any{
			"approvalUrl": "https://portal.basaltvault.app/approvals/x#h=abc",
			"requestFile": map[string]any{"fileName": rfName, "text": rfText, "blocks": []string{"b"}},
		},
		"items": []any{map[string]any{"requestFile": map[string]any{"fileName": rfName2, "text": "2.Zz"}}},
	}
	text := answerText(t, f.attach(toolAnswer(t, body)))

	want := filepath.Join(dir, rfName)
	content, err := os.ReadFile(want)
	require.NoError(t, err)
	require.Equal(t, rfText, string(content), "exactly the request text")
	info, err := os.Stat(want)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(requestFileMode), info.Mode().Perm())
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(requestDirMode), dirInfo.Mode().Perm())

	var got struct {
		Approval struct {
			RequestFile struct{ FileName, Text, Path string } `json:"requestFile"`
		} `json:"approval"`
		Items []struct {
			RequestFile struct{ Path string } `json:"requestFile"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(text), &got))
	require.Equal(t, want, got.Approval.RequestFile.Path)
	require.Equal(t, rfText, got.Approval.RequestFile.Text, "text stays for clients that cannot attach by path")
	require.Equal(t, filepath.Join(dir, rfName2), got.Items[0].RequestFile.Path)
	require.Contains(t, text, `"fileName": "`+rfName+`",`+"\n"+`      "path": `, "inserted at the same indent")
}

func TestAttachLeavesOtherAnswersAlone(t *testing.T) {
	t.Parallel()
	f := requestFiles{dir: filepath.Join(t.TempDir(), "requests"), now: time.Now}
	plain := toolAnswer(t, map[string]any{"rows": 1})
	require.Equal(t, plain, f.attach(plain))
	notJSON := []byte(`{"requestFile": nope`)
	require.Equal(t, notJSON, f.attach(notJSON))
	off := requestFiles{}
	withFile := toolAnswer(t, map[string]any{"requestFile": map[string]any{"fileName": rfName, "text": rfText}})
	require.Equal(t, withFile, off.attach(withFile), "no cache dir: the agent copies text")
}

func TestAttachRefusesANameOrTextOutsideTheSchema(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "requests")
	f := requestFiles{dir: dir, now: time.Now}
	for _, rf := range []map[string]any{
		{"fileName": "../../.bashrc", "text": rfText},
		{"fileName": "basalt-approval-x.txt", "text": rfText},
		{"fileName": rfName, "text": "2.has space"},
	} {
		line := toolAnswer(t, map[string]any{"requestFile": rf})
		require.Equal(t, line, f.attach(line))
	}
	_, err := os.Stat(dir)
	require.True(t, os.IsNotExist(err), "nothing written")
}

func TestAttachPrunesOldRequestFiles(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "requests")
	require.NoError(t, os.MkdirAll(dir, requestDirMode))
	old, fresh := filepath.Join(dir, "old.txt"), filepath.Join(dir, "fresh.txt")
	require.NoError(t, os.WriteFile(old, []byte("x"), requestFileMode))
	require.NoError(t, os.WriteFile(fresh, []byte("x"), requestFileMode))
	now := time.Now()
	require.NoError(t, os.Chtimes(old, now.Add(-25*time.Hour), now.Add(-25*time.Hour)))
	f := requestFiles{dir: dir, now: func() time.Time { return now }}
	f.attach(toolAnswer(t, map[string]any{"requestFile": map[string]any{"fileName": rfName, "text": rfText}}))
	_, err := os.Stat(old)
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(fresh)
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".request-"), "no temporary file left")
	}
}
