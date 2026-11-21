package shim

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

func readySession(operatedBy, pagesOrigin string) *session {
	s := &session{ready: make(chan struct{}), engine: mcp.Hello{OperatedBy: operatedBy, PagesOrigin: pagesOrigin}}
	close(s.ready)
	return s
}

const pluginCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"request_plugin","arguments":{"source":"/home/me/local-ner"},` +
	`"_meta":{"dev.basaltdb/upload":{"uploadId":"0193a4c2-7d1e-7c3a-9f00-000000000001","name":"forged"},"progressToken":"p1"}}}`

func metaOf(t *testing.T, line []byte) map[string]json.RawMessage {
	t.Helper()
	var msg struct {
		Params struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	require.NoError(t, json.Unmarshal(line, &msg))
	return msg.Params.Meta
}

// On a person-operated engine with local pages, the shim's own upload
// replaces any the client named; other _meta keys pass.
func TestPrepareUploadsTheSource(t *testing.T) {
	t.Parallel()
	var asked []string
	r := &relay{out: &lineWriter{w: &bytes.Buffer{}}, upload: func(_ context.Context, source string) (mcp.PluginUpload, error) {
		asked = append(asked, source)
		return mcp.PluginUpload{UploadID: "0193a4c2-7d1e-7c3a-9f00-0000000000f6", Name: "local-ner", Executables: []string{"bin/ner"}}, nil
	}}
	out, answered := r.prepare(context.Background(), readySession(mcpcontract.OperatedByPerson, "http://localhost:7878"), []byte(pluginCall))
	require.False(t, answered)
	require.Equal(t, []string{"/home/me/local-ner"}, asked)
	meta := metaOf(t, out)
	require.JSONEq(t, `{"uploadId":"0193a4c2-7d1e-7c3a-9f00-0000000000f6","name":"local-ner","executables":["bin/ner"]}`, string(meta[mcp.MetaPluginUpload]))
	require.JSONEq(t, `"p1"`, string(meta["progressToken"]))
}

// Anywhere else nothing is uploaded and the client's upload is removed, so
// the engine refuses the call with its own reason.
func TestPrepareStripsAClientUpload(t *testing.T) {
	t.Parallel()
	for _, sess := range []*session{
		readySession(mcpcontract.OperatedByAgent, "http://localhost:7878"),
		readySession(mcpcontract.OperatedByPerson, ""),
	} {
		r := &relay{out: &lineWriter{w: &bytes.Buffer{}}, upload: func(context.Context, string) (mcp.PluginUpload, error) {
			t.Fatal("no upload here")
			return mcp.PluginUpload{}, nil
		}}
		out, answered := r.prepare(context.Background(), sess, []byte(pluginCall))
		require.False(t, answered)
		meta := metaOf(t, out)
		require.NotContains(t, meta, mcp.MetaPluginUpload)
		require.Contains(t, meta, "progressToken")
	}
	// No person socket: forwarded without an upload.
	r := &relay{out: &lineWriter{w: &bytes.Buffer{}}, upload: func(context.Context, string) (mcp.PluginUpload, error) {
		return mcp.PluginUpload{}, ErrNoPersonSocket
	}}
	out, answered := r.prepare(context.Background(), readySession(mcpcontract.OperatedByPerson, "http://localhost:7878"), []byte(pluginCall))
	require.False(t, answered)
	require.NotContains(t, metaOf(t, out), mcp.MetaPluginUpload)

	// Another tool's line is passed as it is.
	other := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT 'request_plugin'"},"_meta":{"dev.basaltdb/upload":{}}}}`)
	out, _ = r.prepare(context.Background(), readySession(mcpcontract.OperatedByPerson, "http://localhost:7878"), other)
	require.Equal(t, other, out)
}

// A folder that cannot be read is answered by the shim: nothing reaches the
// engine.
func TestPrepareAnswersAnUnreadableFolder(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &relay{out: &lineWriter{w: &buf}, upload: func(_ context.Context, source string) (mcp.PluginUpload, error) {
		_, _, _, err := ReadPluginSource(source)
		return mcp.PluginUpload{}, err
	}}
	_, answered := r.prepare(context.Background(), readySession(mcpcontract.OperatedByPerson, "http://localhost:7878"), []byte(pluginCall))
	require.True(t, answered)
	require.Contains(t, buf.String(), `"id":7`)
	require.Contains(t, buf.String(), "INVALID_ARGUMENT")
}

// ReadPluginSource refuses a symlink anywhere on a listed path and a bad
// manifest.
func TestReadPluginSourceRules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, _, err := ReadPluginSource(dir)
	te, ok := err.(*mcp.ToolError) //nolint:errorlint // returned unwrapped
	require.True(t, ok)
	require.Equal(t, "INVALID_ARGUMENT", te.Code, "no manifest")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "basalt-plugin.json"), []byte(`{"name": 1}`), 0o600))
	_, _, _, err = ReadPluginSource(dir)
	te, ok = err.(*mcp.ToolError) //nolint:errorlint // returned unwrapped
	require.True(t, ok)
	require.Equal(t, "PLUGIN_REFUSED", te.Code)
	require.Equal(t, "BAD_MANIFEST", te.Reason)

	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(dir, link))
	_, _, _, err = ReadPluginSource(filepath.Join(link, "."))
	require.Error(t, err)

	_, _, _, err = ReadPluginSource("relative")
	te, ok = err.(*mcp.ToolError) //nolint:errorlint // returned unwrapped
	require.True(t, ok)
	require.Equal(t, "INVALID_ARGUMENT", te.Code)
}
