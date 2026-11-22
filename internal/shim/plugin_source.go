package shim

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// maxSourceBytes bounds what is read of a plugin folder: the upload's own
// cap (CONTRACT.md, Plugin approval in service mode, The upload).
const maxSourceBytes = 256 << 20

// ErrNoUploads: the engine takes no plugin uploads (it keeps no plugins of
// its own, or it is older), so the call goes to it without one and the
// engine says why it cannot take a plugin.
var ErrNoUploads = errors.New("the engine takes no plugin uploads")

// PluginFile is one file of a plugin to upload: its path in the copy and
// its bytes.
type PluginFile struct {
	Path string
	Data []byte
}

// uploadWait bounds one upload: the engine answers each part at once.
const uploadWait = 2 * time.Minute

// NewPluginUploader uploads plugin folders to the engine over a second
// connection to the agent's own socket at socketPath, as this process's OS
// user (the agent's), which the socket admits and the upload belongs to.
func NewPluginUploader(socketPath string) PluginUploader {
	return func(ctx context.Context, source string) (mcp.PluginUpload, error) {
		src, err := ReadPluginSource(source)
		if err != nil {
			return mcp.PluginUpload{}, err
		}
		ctx, cancel := context.WithTimeout(ctx, uploadWait)
		defer cancel()
		id, err := upload(ctx, socketPath, src.Files)
		if err != nil {
			return mcp.PluginUpload{}, err
		}
		return mcp.PluginUpload{UploadID: id, Name: src.Manifest.Name, Executables: src.Executables}, nil
	}
}

// uploadConn is the second connection: one request, one answer.
type uploadConn struct {
	conn net.Conn
	in   *bufio.Reader
	id   int
}

// upload begins an upload and sends files in parts of at most the engine's
// maxPartBytes, in order, and returns the upload's id.
func upload(ctx context.Context, socketPath string, files []PluginFile) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return "", ErrNoUploads
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c := &uploadConn{conn: conn, in: bufio.NewReaderSize(conn, scannerInitSize)}
	if _, err := conn.Write(append(mcp.HelloLine(buildinfo.Version), '\n')); err != nil {
		return "", uploadFailed(err)
	}
	if _, err := c.answer(); err != nil {
		return "", err
	}
	var begun struct {
		UploadID     string `json:"uploadId"`
		MaxPartBytes int    `json:"maxPartBytes"`
	}
	if err := c.call(mcp.MethodPluginUploadBegin, struct{}{}, &begun); err != nil {
		return "", err
	}
	part := begun.MaxPartBytes
	if part <= 0 {
		return "", uploadFailed(fmt.Errorf("the engine offers parts of %d bytes", part))
	}
	send := func(path string, off int, chunk []byte) error {
		return c.call(mcp.MethodPluginUploadPart, map[string]any{
			"uploadId": begun.UploadID, "path": path, "offset": off, "data": base64.RawURLEncoding.EncodeToString(chunk),
		}, nil)
	}
	for _, f := range files {
		if len(f.Data) == 0 {
			// An empty file is one empty part at offset 0.
			if err := send(f.Path, 0, nil); err != nil {
				return "", err
			}
			continue
		}
		for off := 0; off < len(f.Data); off += part {
			if err := send(f.Path, off, f.Data[off:min(off+part, len(f.Data))]); err != nil {
				return "", err
			}
		}
	}
	return begun.UploadID, nil
}

// call sends one request and decodes its answer's result into out.
func (c *uploadConn) call(method string, params, out any) error {
	c.id++
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if err != nil {
		return uploadFailed(err)
	}
	if _, err := c.conn.Write(append(raw, '\n')); err != nil {
		return uploadFailed(err)
	}
	result, err := c.answer()
	if err != nil || out == nil {
		return err
	}
	if err := json.Unmarshal(result, out); err != nil {
		return uploadFailed(err)
	}
	return nil
}

// answer reads the next answer: its result, the engine's ToolError, or
// ErrNoUploads when the engine does not serve the method.
func (c *uploadConn) answer() (json.RawMessage, error) {
	line, err := c.in.ReadBytes('\n')
	if err != nil {
		return nil, uploadFailed(err)
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *mcp.RPCError   `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, uploadFailed(err)
	}
	switch {
	case resp.Error == nil:
		return resp.Result, nil
	case mcp.IsMethodNotFound(resp.Error):
		return nil, ErrNoUploads
	case resp.Error.Data != nil && resp.Error.Data.Code == codePluginRefused:
		return nil, refusal(resp.Error.Data.Reason, resp.Error.Data.Message)
	case resp.Error.Data != nil && resp.Error.Data.Code == "INVALID_ARGUMENT":
		return nil, badFolder("%s", resp.Error.Data.Message)
	}
	return nil, uploadFailed(errors.New(resp.Error.Message))
}

// codePluginRefused is the engine's refusal of a plugin change.
const codePluginRefused = "PLUGIN_REFUSED"

// uploadFailed is the answer to an upload that broke off.
func uploadFailed(err error) *mcp.ToolError {
	return &mcp.ToolError{
		Code: "INTERNAL", Message: "the plugin's files could not be handed to the engine: " + err.Error(),
		PersonMessage: "Basalt could not hand the plugin's files to its engine, so nothing was changed.",
		NextSteps:     []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the upload failed; do not retry in a loop."}},
	}
}

// refusal is PLUGIN_REFUSED as the engine words it, with the catalog's
// steps for these reasons: stop, and ask the person.
func refusal(reason, message string) *mcp.ToolError {
	return &mcp.ToolError{
		Code: codePluginRefused, Reason: reason, Message: message,
		PersonMessage: "Basalt did not add or change the plugin: " + message,
		NextSteps: []mcp.NextStep{
			{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the engine refused this plugin change; do not work around it."},
			{Actor: mcp.ActorAgent, Action: mcp.ActionAskPerson, Text: "Show the person the personMessage; only they can decide about this plugin."},
		},
	}
}

// badFolder is INVALID_ARGUMENT for a folder that cannot be read as a
// plugin.
func badFolder(format string, args ...any) *mcp.ToolError {
	return &mcp.ToolError{
		Code: "INVALID_ARGUMENT", Message: fmt.Sprintf(format, args...),
		NextSteps: []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionReviseCall, Tool: toolRequestPlugin, Text: "Call again with source naming the plugin's folder."}},
	}
}

// PluginSource is a plugin folder as read for an upload.
type PluginSource struct {
	Files []PluginFile
	// Executables are the listed files with an execute bit.
	Executables []string
	Manifest    plugin.Manifest
}

// ReadPluginSource reads a plugin folder for an upload: the manifest, its
// .sig when there is one, and every file the manifest lists, each a regular
// file reached through no symlink, of at most maxSourceBytes in all.
// Executables are the listed files with an execute bit. A manifest that
// does not parse is PLUGIN_REFUSED BAD_MANIFEST; any other problem
// INVALID_ARGUMENT.
func ReadPluginSource(dir string) (PluginSource, error) {
	if !filepath.IsAbs(dir) {
		return PluginSource{}, badFolder("source must be an absolute path, not %q", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return PluginSource{}, badFolder("%s cannot be opened as a folder", dir)
	}
	defer func() { _ = root.Close() }()
	var total int64
	read := func(rel string, limit int64) ([]byte, bool, error) {
		parts := strings.Split(rel, "/")
		for i := 1; i <= len(parts); i++ {
			fi, err := root.Lstat(filepath.FromSlash(path.Join(parts[:i]...)))
			if err != nil {
				return nil, false, badFolder("%s cannot be read", filepath.Join(dir, rel))
			}
			if fi.Mode()&fs.ModeSymlink != 0 {
				return nil, false, badFolder("%s is a symlink, which a plugin may not hold", filepath.Join(dir, rel))
			}
		}
		f, err := root.OpenFile(filepath.FromSlash(rel), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, false, badFolder("%s cannot be opened", filepath.Join(dir, rel))
		}
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			return nil, false, badFolder("%s is not a regular file", filepath.Join(dir, rel))
		}
		b, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil || int64(len(b)) > limit {
			return nil, false, badFolder("%s is too large", filepath.Join(dir, rel))
		}
		total += int64(len(b))
		if total > maxSourceBytes {
			return nil, false, badFolder("the plugin in %s is over %d bytes", dir, maxSourceBytes)
		}
		return b, fi.Mode().Perm()&0o111 != 0, nil
	}
	manifest, _, err := read(plugin.ManifestFile, plugin.MaxManifestBytes)
	if err != nil {
		return PluginSource{}, err
	}
	m, err := plugin.ParseManifest(manifest)
	if err != nil {
		return PluginSource{}, &mcp.ToolError{
			Code: codePluginRefused, Reason: "BAD_MANIFEST", Message: "the plugin is refused: " + err.Error() + ". Nothing was written",
			PersonMessage: "The plugin was refused because its manifest breaks a rule (" + err.Error() + "). Its publisher must fix the manifest.",
			NextSteps:     []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the plugin's publisher must fix its manifest."}},
		}
	}
	files := []PluginFile{{Path: plugin.ManifestFile, Data: manifest}}
	if _, err := root.Lstat(plugin.SignatureFile); err == nil {
		sig, _, err := read(plugin.SignatureFile, plugin.MaxSignatureFileBytes)
		if err != nil {
			return PluginSource{}, err
		}
		files = append(files, PluginFile{Path: plugin.SignatureFile, Data: sig})
	}
	var execs []string
	for _, rel := range slices.Sorted(maps.Keys(m.Files)) {
		b, exec, err := read(rel, maxSourceBytes)
		if err != nil {
			return PluginSource{}, err
		}
		files = append(files, PluginFile{Path: rel, Data: b})
		if exec {
			execs = append(execs, rel)
		}
	}
	return PluginSource{Files: files, Executables: execs, Manifest: m}, nil
}
