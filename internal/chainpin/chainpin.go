// Package chainpin keeps the last ledger chain head a reader verified, so
// the next check is incremental (basalt_meta.verify_chain_from) and a
// rewrite of history between two checks is caught. The engine keeps one
// file per agent in its state directory; basalt log keeps one per database
// and role in the user's cache directory. A pin lives outside the database
// on purpose: whoever can rewrite basalt_meta could rewrite a pin stored
// there too.
package chainpin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

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

// Pin is a verified chain head and the install of the guard it belongs to
// (guard.InstallID; 0 for a pin saved before installs were told apart).
type Pin struct {
	Head    guard.ChainHead
	Install uint32
	// SetAside are the pins this witness set aside after a reinstall and
	// reported in the ledger, kept so the notice stays whatever happens to
	// the ledger rows (CONTRACT.md, Version 36, step 4).
	SetAside []guard.SetAside
}

// Kept returns p with s in its SetAside, once: the same pin set aside on
// the same install is kept once.
func (p Pin) Kept(s guard.SetAside) Pin {
	for _, k := range p.SetAside {
		if k.PinnedSeq == s.PinnedSeq && k.PinnedInstall == s.PinnedInstall && k.Install == s.Install &&
			bytes.Equal(k.PinnedHash, s.PinnedHash) {
			return p
		}
	}
	p.SetAside = append(slices.Clone(p.SetAside), s)
	return p
}

// Of reports whether p belongs to install: a pin of another install is of a
// ledger that no longer exists, and is set aside, not checked. A pin with
// no install is taken as this one's.
func (p Pin) Of(install uint32) bool { return p.Install == 0 || p.Install == install }

// pinFile is the file format: the head as JSON, hashes in hex.
type pinFile struct {
	Seq      int64          `json:"seq"`
	Hash     string         `json:"hash"`
	Install  uint32         `json:"install,omitempty"`
	SetAside []setAsideFile `json:"setAside,omitempty"`
}

// setAsideFile is one guard.SetAside in the pin file.
type setAsideFile struct {
	PinnedSeq     int64     `json:"pinnedSeq"`
	PinnedHash    string    `json:"pinnedHash"`
	PinnedInstall uint32    `json:"pinnedInstall"`
	Install       uint32    `json:"install"`
	At            time.Time `json:"at"`
}

func setAsideToFile(s guard.SetAside) setAsideFile {
	return setAsideFile{
		PinnedSeq: s.PinnedSeq, PinnedHash: hex.EncodeToString(s.PinnedHash),
		PinnedInstall: s.PinnedInstall, Install: s.Install, At: s.At.UTC(),
	}
}

func (s setAsideFile) toDomain() (guard.SetAside, error) {
	hash, err := hex.DecodeString(s.PinnedHash)
	if err != nil || s.PinnedSeq < 0 {
		return guard.SetAside{}, errors.New("a set-aside pin is not a chain head")
	}
	return guard.SetAside{PinnedSeq: s.PinnedSeq, PinnedHash: hash, PinnedInstall: s.PinnedInstall, Install: s.Install, At: s.At}, nil
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
func (f File) Load(name string) (Pin, bool, error) {
	path, err := f.path(name)
	if err != nil {
		return Pin{}, false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Pin{}, false, nil
	}
	if err != nil {
		return Pin{}, false, err
	}
	var p pinFile
	if err := json.Unmarshal(raw, &p); err != nil {
		return Pin{}, false, fmt.Errorf("pin %s: %w", path, err)
	}
	hash, err := hex.DecodeString(p.Hash)
	if err != nil || p.Seq < 0 {
		return Pin{}, false, fmt.Errorf("pin %s is not a chain head", path)
	}
	pin := Pin{Head: guard.ChainHead{Seq: p.Seq, Hash: hash}, Install: p.Install}
	for _, s := range p.SetAside {
		kept, err := s.toDomain()
		if err != nil {
			return Pin{}, false, fmt.Errorf("pin %s: %w", path, err)
		}
		pin.SetAside = append(pin.SetAside, kept)
	}
	return pin, true, nil
}

// Save replaces the pin named name atomically (write, then rename).
func (f File) Save(name string, pin Pin) error {
	h := pin.Head
	path, err := f.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, dirMode); err != nil {
		return err
	}
	file := pinFile{Seq: h.Seq, Hash: hex.EncodeToString(h.Hash), Install: pin.Install}
	for _, s := range pin.SetAside {
		file.SetAside = append(file.SetAside, setAsideToFile(s))
	}
	raw, err := json.Marshal(file)
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
	pins map[string]Pin
}

// Load returns the pin named name, and false when there is none yet.
func (m *Memory) Load(name string) (Pin, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.pins[name]
	return h, ok, nil
}

// Save replaces the pin named name.
func (m *Memory) Save(name string, p Pin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pins == nil {
		m.pins = map[string]Pin{}
	}
	m.pins[name] = p
	return nil
}
