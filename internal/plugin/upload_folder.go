package plugin

import "context"

// UploadFile is one file of a plugin to upload: its path in the copy and
// its bytes.
type UploadFile struct {
	Path string
	Data []byte
}

// UploadSource is a plugin folder as read for an upload: the files to send,
// the listed files with an execute bit, and the manifest's name.
type UploadSource struct {
	Files       []UploadFile
	Executables []string
	Name        string
}

// UploadResult is an upload the engine took: its id, and the plugin's name
// and executables as the agent's request_plugin call carries them.
type UploadResult struct {
	UploadID    string
	Name        string
	Executables []string
}

// PluginUploadChannel is the agent's side of a plugin upload: it reads the
// plugin folder as the agent's OS user and sends it to the engine over the
// agent's own socket (the shim implements it).
type PluginUploadChannel interface {
	// ReadSource reads the plugin folder dir for an upload.
	ReadSource(dir string) (UploadSource, error)
	// Upload sends files to the engine as one upload and returns its id.
	Upload(ctx context.Context, files []UploadFile) (uploadID string, err error)
}

// UploadFolder reads the plugin folder dir through ch and uploads it to
// the engine: what basalt mcp does for a request_plugin call that names a
// source folder.
func UploadFolder(ctx context.Context, ch PluginUploadChannel, dir string) (UploadResult, error) {
	src, err := ch.ReadSource(dir)
	if err != nil {
		return UploadResult{}, err
	}
	id, err := ch.Upload(ctx, src.Files)
	if err != nil {
		return UploadResult{}, err
	}
	return UploadResult{UploadID: id, Name: src.Name, Executables: src.Executables}, nil
}
