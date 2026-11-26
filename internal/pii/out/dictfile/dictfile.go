// Package dictfile keeps the PII dictionary's files in the engine's
// stateDir: the key file pii.key, and dictionary.bin and status.json in
// <stateDir>/pii (CONTRACT.md, PII classification, engine files). It is the
// pii.DictionaryFiles a pii.FuseDictionary is opened on.
package dictfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

const (
	// dictionaryDirMode: the engine user writes, the person's basalt log reads status.json.
	dictionaryDirMode os.FileMode = 0o755
	// dirWriteMask: nobody but the engine user may add or swap files in pii/.
	dirWriteMask os.FileMode = 0o022
	// dictionaryFileMode: the dictionary is the engine user's alone.
	dictionaryFileMode os.FileMode = 0o600
	// statusFileMode: counts and times only, readable by basalt log.
	statusFileMode os.FileMode = 0o644
	// maxStatusFileSize bounds what is read back from status.json.
	maxStatusFileSize = 4096
	// goosWindows is runtime.GOOS on Windows, where file modes are not checked.
	goosWindows = "windows"
)

// Files is a dictionary's files in <stateDir>/pii.
type Files struct {
	stateDir string
	dir      string // <stateDir>/pii, once Prepare checked it
}

var _ pii.DictionaryFiles = (*Files)(nil)

// Open opens the dictionary in <stateDir>/pii (pii.OpenDictionary), creating
// the directory (0755) when missing. A file or directory that is a link,
// owned by another user or too open is an error.
func Open(stateDir string, keys *pii.Keys, opts pii.DictionaryOptions) (*pii.FuseDictionary, error) {
	return pii.OpenDictionary(&Files{stateDir: stateDir}, keys, opts)
}

// Prepare creates <stateDir>/pii when missing and checks it.
func (f *Files) Prepare() error {
	dir, err := ensureDictionaryDir(f.stateDir)
	if err != nil {
		return err
	}
	f.dir = dir
	return nil
}

// BasePath is dictionary.bin's path.
func (f *Files) BasePath() string { return filepath.Join(f.dir, pii.DictionaryFileName) }

// MapBase maps dictionary.bin read-only (openBaseFile). found is false when
// the file does not exist.
func (f *Files) MapBase() ([]byte, func() error, bool, error) {
	data, unmap, err := openBaseFile(f.BasePath())
	return data, unmap, !errors.Is(err, fs.ErrNotExist), err
}

// WriteBase replaces dictionary.bin (0600) atomically with what write writes.
func (f *Files) WriteBase(write func(io.WriteSeeker) error) error {
	return atomicfile.WriteFunc(f.BasePath(), atomicfile.Options{Mode: dictionaryFileMode, SyncDir: true}, func(file *os.File) error { return write(file) })
}

// ReadStatus reads status.json back (readStatusFile).
func (f *Files) ReadStatus() pii.DictionaryStatus { return readStatusFile(f.dir) }

// WriteStatus writes status.json (0644) atomically.
func (f *Files) WriteStatus(st pii.DictionaryStatus) error { return writeStatusFile(f.dir, st) }

// ensureDictionaryDir creates <stateDir>/pii (0755) when missing and refuses
// one that is a link, not a directory, owned by another user, or writable by
// group or others.
func ensureDictionaryDir(stateDir string) (string, error) {
	dir := filepath.Join(stateDir, pii.DictionaryDirName)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := createDictionaryDir(stateDir, dir); err != nil {
			return "", err
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("pii directory %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("pii directory %s must be a directory, not a link or file", dir)
	}
	if err := ownerfile.CheckOwner(fi, ownerfile.Rules{}); err != nil {
		return "", fmt.Errorf("pii directory %s: %w", dir, err)
	}
	if runtime.GOOS != goosWindows && fi.Mode().Perm()&dirWriteMask != 0 {
		return "", fmt.Errorf("pii directory %s is mode %o; only the engine's user may write it (0755)", dir, fi.Mode().Perm())
	}
	return dir, nil
}

func createDictionaryDir(stateDir, dir string) error {
	err := os.Mkdir(dir, dictionaryDirMode)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pii directory %s: %w", dir, err)
	}
	// The umask may have narrowed it; the contract mode is 0755.
	if err := os.Chmod(dir, dictionaryDirMode); err != nil {
		return fmt.Errorf("pii directory %s: %w", dir, err)
	}
	if err := atomicfile.SyncDir(stateDir); err != nil {
		return fmt.Errorf("pii directory %s: sync parent: %w", dir, err)
	}
	return nil
}

// openBaseFile maps the dictionary file at path read-only and checks it. It
// opens without following a link and checks the opened file itself
// (ownerfile.Open): a regular file with one link, of this process's user,
// mode 0600 or narrower. Those failures are errors (someone changed the
// engine's files). A missing file wraps os.ErrNotExist; a file of an
// unusable size wraps pii's invalid-dictionary error
// (pii.CheckDictionarySize) and is rebuilt. pii parses the content.
//
// A read never overlaps a rebuild's rename of this file: pii maps the file
// only when the dictionary is opened (before any build can start) and right
// after a build's WriteBase, in that build, and one build runs at a time
// (pii.FuseDictionary.StartBuild); one engine holds a state directory (the
// engine lock). A mapping made before a rename keeps the old file, which
// keeps its one link until it is unmapped, so a hard error here is never a
// race with the rebuild.
func openBaseFile(path string) ([]byte, func() error, error) {
	f, fi, err := ownerfile.Open(path, ownerfile.Rules{})
	if err != nil {
		return nil, nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	defer f.Close()
	if err := pii.CheckDictionarySize(fi.Size()); err != nil {
		return nil, nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	data, unmap, err := mapFile(f, int(fi.Size()))
	if err != nil {
		return nil, nil, fmt.Errorf("pii dictionary %s: map: %w", path, err)
	}
	return data, unmap, nil
}

// writeStatusFile writes status.json (0644) atomically.
func writeStatusFile(dir string, st pii.DictionaryStatus) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, pii.StatusFileName), data, atomicfile.Options{Mode: statusFileMode, SyncDir: true})
}

// readStatusFile reads status.json back (the last scan survives a restart).
// Any problem gives a zero status: it only carries counts.
func readStatusFile(dir string) pii.DictionaryStatus {
	var st pii.DictionaryStatus
	f, err := ownerfile.OpenNoFollow(filepath.Join(dir, pii.StatusFileName))
	if err != nil {
		return st
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusFileSize))
	if err != nil {
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return pii.DictionaryStatus{}
	}
	return st
}
