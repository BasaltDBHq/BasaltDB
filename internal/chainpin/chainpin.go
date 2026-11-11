// Package chainpin keeps the last ledger chain head a reader verified, so
// the next check is incremental (basalt_meta.verify_chain_from) and a
// rewrite of history between two checks is caught. The engine keeps one
// file per agent in its state directory; basalt log keeps one per database
// and role in the user's cache directory. A pin lives outside the database
// on purpose: whoever can rewrite basalt_meta could rewrite a pin stored
// there too.
package chainpin

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
	suffix   = ".head.json"
)

// namePattern keeps pin names to one plain file name.
var namePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// ErrInvalidName is a pin name that is not a plain file name.
var ErrInvalidName = errors.New("invalid pin name")

// pinFile is the file format: the head as JSON, the hash in hex.
type pinFile struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// File keeps pins as <Dir>/<name>.head.json, mode 0600.
type File struct {
	Dir string
}

func (f File) path(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return filepath.Join(f.Dir, name+suffix), nil
}

// Load returns the pin named name, and false when there is none yet.
func (f File) Load(name string) (guard.ChainHead, bool, error) {
	path, err := f.path(name)
	if err != nil {
		return guard.ChainHead{}, false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return guard.ChainHead{}, false, nil
	}
	if err != nil {
		return guard.ChainHead{}, false, err
	}
	var p pinFile
	if err := json.Unmarshal(raw, &p); err != nil {
		return guard.ChainHead{}, false, fmt.Errorf("pin %s: %w", path, err)
	}
	hash, err := hex.DecodeString(p.Hash)
	if err != nil || p.Seq < 0 {
		return guard.ChainHead{}, false, fmt.Errorf("pin %s is not a chain head", path)
	}
	return guard.ChainHead{Seq: p.Seq, Hash: hash}, true, nil
}

// Save replaces the pin named name atomically (write, then rename).
func (f File) Save(name string, h guard.ChainHead) error {
	path, err := f.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, dirMode); err != nil {
		return err
	}
	raw, err := json.Marshal(pinFile{Seq: h.Seq, Hash: hex.EncodeToString(h.Hash)})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(f.Dir, name+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Memory keeps pins in memory: the fallback when no state directory can be
// written, and tests.
type Memory struct {
	mu   sync.Mutex
	pins map[string]guard.ChainHead
}

// Load returns the pin named name, and false when there is none yet.
func (m *Memory) Load(name string) (guard.ChainHead, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.pins[name]
	return h, ok, nil
}

// Save replaces the pin named name.
func (m *Memory) Save(name string, h guard.ChainHead) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pins == nil {
		m.pins = map[string]guard.ChainHead{}
	}
	m.pins[name] = h
	return nil
}
