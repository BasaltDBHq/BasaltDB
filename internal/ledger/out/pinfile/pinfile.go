// Package pinfile keeps chain pins (chainpin.Pin) as files: one
// <Dir>/<name>.head.json per pin, mode 0600, in a directory of mode 0700.
package pinfile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
	suffix   = ".head.json"
)

// pinFile is the file format: the head as JSON, hashes in hex.
type pinFile struct {
	Seq      int64          `json:"seq"`
	Hash     string         `json:"hash"`
	Install  uuid.UUID      `json:"installId"`
	SetAside []setAsideFile `json:"setAside,omitempty"`
}

// setAsideFile is one action.SetAside in the pin file.
type setAsideFile struct {
	PinnedSeq     int64     `json:"pinnedSeq"`
	PinnedHash    string    `json:"pinnedHash"`
	PinnedInstall uuid.UUID `json:"pinnedInstallId"`
	Install       uuid.UUID `json:"installId"`
	At            time.Time `json:"at"`
}

func setAsideToFile(s action.SetAside) setAsideFile {
	return setAsideFile{
		PinnedSeq: s.PinnedSeq, PinnedHash: hex.EncodeToString(s.PinnedHash),
		PinnedInstall: s.PinnedInstall, Install: s.Install, At: s.At.UTC(),
	}
}

func (s setAsideFile) toDomain() (action.SetAside, error) {
	hash, err := hex.DecodeString(s.PinnedHash)
	if err != nil || s.PinnedSeq < 0 {
		return action.SetAside{}, errors.New("a set-aside pin is not a chain head")
	}
	return action.SetAside{PinnedSeq: s.PinnedSeq, PinnedHash: hash, PinnedInstall: s.PinnedInstall, Install: s.Install, At: s.At}, nil
}

// File keeps pins as <Dir>/<name>.head.json, mode 0600.
type File struct {
	Dir string
}

func (f File) path(name string) (string, error) {
	if err := chainpin.CheckName(name); err != nil {
		return "", err
	}
	return filepath.Join(f.Dir, name+suffix), nil
}

// Load returns the pin named name, and false when there is none yet.
func (f File) Load(name string) (chainpin.Pin, bool, error) {
	path, err := f.path(name)
	if err != nil {
		return chainpin.Pin{}, false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return chainpin.Pin{}, false, nil
	}
	if err != nil {
		return chainpin.Pin{}, false, err
	}
	var p pinFile
	if err := json.Unmarshal(raw, &p); err != nil {
		return chainpin.Pin{}, false, fmt.Errorf("pin %s: %w", path, err)
	}
	hash, err := hex.DecodeString(p.Hash)
	if err != nil || p.Seq < 0 {
		return chainpin.Pin{}, false, fmt.Errorf("pin %s is not a chain head", path)
	}
	pin := chainpin.Pin{Head: action.ChainHead{Seq: p.Seq, Hash: hash}, Install: p.Install}
	for _, s := range p.SetAside {
		kept, err := s.toDomain()
		if err != nil {
			return chainpin.Pin{}, false, fmt.Errorf("pin %s: %w", path, err)
		}
		pin.SetAside = append(pin.SetAside, kept)
	}
	return pin, true, nil
}

// Save replaces the pin named name atomically (write, then rename).
func (f File) Save(name string, pin chainpin.Pin) error {
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
	return atomicfile.Write(path, raw, atomicfile.Options{Mode: fileMode})
}
