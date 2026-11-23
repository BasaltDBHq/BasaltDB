package plugin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

type fakeChannel struct {
	readDir string
	sentCtx context.Context
	src     plugin.UploadSource
	readErr error
	sent    [][]plugin.UploadFile
	id      string
	sendErr error
}

func (c *fakeChannel) ReadSource(dir string) (plugin.UploadSource, error) {
	c.readDir = dir
	return c.src, c.readErr
}

func (c *fakeChannel) Upload(ctx context.Context, files []plugin.UploadFile) (string, error) {
	c.sentCtx = ctx
	c.sent = append(c.sent, files)
	return c.id, c.sendErr
}

// UploadFolder sends what it read and answers with the upload's id and the
// manifest's name and executables; a folder it cannot read sends nothing.
func TestUploadFolder(t *testing.T) {
	files := []plugin.UploadFile{{Path: "manifest.json", Data: []byte("{}")}, {Path: "bin/p", Data: []byte("x")}}
	ch := &fakeChannel{src: plugin.UploadSource{Files: files, Executables: []string{"bin/p"}, Name: "acme-ner"}, id: "u1"}
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "this call")
	got, err := plugin.UploadFolder(ctx, ch, "/src/acme-ner")
	require.NoError(t, err)
	require.Equal(t, "/src/acme-ner", ch.readDir, "the folder named is the one read")
	require.Equal(t, "this call", ch.sentCtx.Value(key{}), "the upload runs under the caller's context")
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
