package pii

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
)

// Files of the dictionary in the engine's stateDir (CONTRACT.md, PII
// classification, engine files).
const (
	DictionaryDirName  = "pii"
	DictionaryFileName = "dictionary.bin"
	StatusFileName     = "status.json"
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
	// maxMapSize is the largest file a slice can address on this platform.
	maxMapSize = math.MaxInt
)

// ensureDictionaryDir creates <stateDir>/pii (0755) when missing and refuses
// one that is a link, not a directory, owned by another user, or writable by
// group or others.
func ensureDictionaryDir(stateDir string) (string, error) {
	dir := filepath.Join(stateDir, DictionaryDirName)
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
	if err := checkOwner(fi); err != nil {
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
	if err := syncDir(stateDir); err != nil {
		return fmt.Errorf("pii directory %s: sync parent: %w", dir, err)
	}
	return nil
}

// openBaseFile maps the dictionary file at path read-only and checks it. It
// opens without following a link and checks the opened file itself: a regular
// file of this process's user, mode 0600 or narrower. Those failures are
// errors (someone changed the engine's files). A missing file wraps
// os.ErrNotExist; a file whose content is unusable wraps errDictionaryInvalid
// and is rebuilt.
func openBaseFile(path string, keyCheck uint64) (*baseFilter, error) {
	link, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	if !link.Mode().IsRegular() {
		return nil, fmt.Errorf("pii dictionary %s must be a regular file, not a link or directory", path)
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	if !os.SameFile(link, fi) || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("pii dictionary %s changed while it was opened", path)
	}
	if err := checkOwner(fi); err != nil {
		return nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	if runtime.GOOS != goosWindows && fi.Mode().Perm()&keyFilePermMask != 0 {
		return nil, fmt.Errorf("pii dictionary %s is mode %o; it must be readable by the engine's user only (0600)", path, fi.Mode().Perm())
	}
	if fi.Size() < dictHeaderSize || fi.Size() > maxMapSize {
		return nil, fmt.Errorf("pii dictionary %s: %w", path, invalidf("size %d", fi.Size()))
	}
	data, unmap, err := mapFile(f, int(fi.Size()))
	if err != nil {
		return nil, fmt.Errorf("pii dictionary %s: map: %w", path, err)
	}
	b, err := parseDictionary(data, keyCheck)
	if err != nil {
		_ = unmap()
		return nil, fmt.Errorf("pii dictionary %s: %w", path, err)
	}
	return newMappedBase(b, unmap), nil
}

// writeAtomic writes a file through a temp file in the same directory, synced,
// then renamed over path, and syncs the directory, so a reader sees the old
// file or the new one, whole.
func writeAtomic(path string, mode os.FileMode, write func(f *os.File) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // gone after the rename; cleans up after a failure
	if err := fillTemp(tmp, mode, write); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func fillTemp(tmp *os.File, mode os.FileMode, write func(f *os.File) error) error {
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}

// writeStatusFile writes status.json (0644) atomically.
func writeStatusFile(dir string, st DictionaryStatus) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, StatusFileName), statusFileMode, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

// ReadStatus reads <stateDir>/pii/status.json, as basalt log does. It
// reports false when the file is missing, cannot be read (permissions, an
// unreadable stateDir) or does not parse. It holds counts and times only.
func ReadStatus(stateDir string) (DictionaryStatus, bool) {
	var st DictionaryStatus
	f, err := openNoFollow(filepath.Join(stateDir, DictionaryDirName, StatusFileName))
	if err != nil {
		return st, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusFileSize))
	if err != nil || json.Unmarshal(data, &st) != nil {
		return DictionaryStatus{}, false
	}
	return st, true
}

// readStatusFile reads status.json back (the last scan survives a restart).
// Any problem gives a zero status: it only carries counts.
func readStatusFile(dir string) DictionaryStatus {
	var st DictionaryStatus
	f, err := openNoFollow(filepath.Join(dir, StatusFileName))
	if err != nil {
		return st
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusFileSize))
	if err != nil {
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return DictionaryStatus{}
	}
	return st
}
