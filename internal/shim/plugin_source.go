package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// maxSourceBytes bounds what is read of a plugin folder: the upload's own
// cap (CONTRACT.md, Plugin approval in service mode, The upload).
const maxSourceBytes = 256 << 20

// ErrNoPersonSocket: the engine has no person socket this process can
// reach (it runs as the person's own user, or it is not running), so no
// plugin is uploaded.
var ErrNoPersonSocket = errors.New("the engine has no person socket")

// NewPluginUploader uploads plugin folders to the engine's person socket at
// socketPath, as this process's OS user (the agent's).
func NewPluginUploader(socketPath string) PluginUploader {
	client := person.Client{Path: socketPath}
	return func(ctx context.Context, source string) (mcp.PluginUpload, error) {
		files, execs, m, err := ReadPluginSource(source)
		if err != nil {
			return mcp.PluginUpload{}, err
		}
		id, err := client.PluginUpload(ctx, files)
		if err != nil {
			return mcp.PluginUpload{}, uploadError(err)
		}
		return mcp.PluginUpload{UploadID: id.String(), Name: m.Name, Executables: execs}, nil
	}
}

// uploadError is the answer to an upload the person socket refused.
func uploadError(err error) error {
	var pe *person.Error
	switch {
	case errors.Is(err, person.ErrNotRunning):
		return ErrNoPersonSocket
	case errors.Is(err, person.ErrUIDNotAllowed):
		return refusal("AGENT_NOT_ALLOWED", fmt.Sprintf(
			"the engine does not let OS user %d use its person socket, so this agent cannot hand it a plugin. Nothing was written", os.Getuid()))
	case errors.As(err, &pe) && pe.Code == person.CodePluginRefused:
		return refusal(pe.Reason, pe.Message)
	}
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
		Code: "PLUGIN_REFUSED", Reason: reason, Message: message,
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

// ReadPluginSource reads a plugin folder for an upload: the manifest, its
// .sig when there is one, and every file the manifest lists, each a regular
// file reached through no symlink, of at most maxSourceBytes in all.
// Executables are the listed files with an execute bit. A manifest that
// does not parse is PLUGIN_REFUSED BAD_MANIFEST; any other problem
// INVALID_ARGUMENT.
func ReadPluginSource(dir string) ([]person.PluginFile, []string, plugin.Manifest, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, plugin.Manifest{}, badFolder("source must be an absolute path, not %q", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, plugin.Manifest{}, badFolder("%s cannot be opened as a folder", dir)
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
		return nil, nil, plugin.Manifest{}, err
	}
	m, err := plugin.ParseManifest(manifest)
	if err != nil {
		return nil, nil, plugin.Manifest{}, &mcp.ToolError{
			Code: "PLUGIN_REFUSED", Reason: "BAD_MANIFEST", Message: "the plugin is refused: " + err.Error() + ". Nothing was written",
			PersonMessage: "The plugin was refused because its manifest breaks a rule (" + err.Error() + "). Its publisher must fix the manifest.",
			NextSteps:     []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the plugin's publisher must fix its manifest."}},
		}
	}
	files := []person.PluginFile{{Path: plugin.ManifestFile, Data: manifest}}
	if _, err := root.Lstat(plugin.SignatureFile); err == nil {
		sig, _, err := read(plugin.SignatureFile, plugin.MaxSignatureFileBytes)
		if err != nil {
			return nil, nil, plugin.Manifest{}, err
		}
		files = append(files, person.PluginFile{Path: plugin.SignatureFile, Data: sig})
	}
	var execs []string
	for _, rel := range slices.Sorted(maps.Keys(m.Files)) {
		b, exec, err := read(rel, maxSourceBytes)
		if err != nil {
			return nil, nil, plugin.Manifest{}, err
		}
		files = append(files, person.PluginFile{Path: rel, Data: b})
		if exec {
			execs = append(execs, rel)
		}
	}
	return files, execs, m, nil
}
