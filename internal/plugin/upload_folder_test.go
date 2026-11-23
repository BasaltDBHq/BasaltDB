package plugin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

type fakeChannel struct {
	src     plugin.UploadSource
	readErr error
	sent    [][]plugin.UploadFile
	id      string
	sendErr error
}

func (c *fakeChannel) ReadSource(string) (plugin.UploadSource, error) { return c.src, c.readErr }

func (c *fakeChannel) Upload(_ context.Context, files []plugin.UploadFile) (string, error) {
	c.sent = append(c.sent, files)
	return c.id, c.sendErr
}

// UploadFolder sends what it read and answers with the upload's id and the
// manifest's name and executables; a folder it cannot read sends nothing.
func TestUploadFolder(t *testing.T) {
	files := []plugin.UploadFile{{Path: "manifest.json", Data: []byte("{}")}, {Path: "bin/p", Data: []byte("x")}}
	ch := &fakeChannel{src: plugin.UploadSource{Files: files, Executables: []string{"bin/p"}, Name: "acme-ner"}, id: "u1"}
	got, err := plugin.UploadFolder(context.Background(), ch, "/src")
	require.NoError(t, err)
	require.Equal(t, plugin.UploadResult{UploadID: "u1", Name: "acme-ner", Executables: []string{"bin/p"}}, got)
	require.Equal(t, [][]plugin.UploadFile{files}, ch.sent)

	bad := &fakeChannel{readErr: errors.New("unreadable")}
	_, err = plugin.UploadFolder(context.Background(), bad, "/src")
	require.EqualError(t, err, "unreadable")
	require.Empty(t, bad.sent)

	refused := &fakeChannel{src: plugin.UploadSource{Name: "acme-ner"}, sendErr: errors.New("refused")}
	got, err = plugin.UploadFolder(context.Background(), refused, "/src")
	require.EqualError(t, err, "refused")
	require.Equal(t, plugin.UploadResult{}, got)
}
