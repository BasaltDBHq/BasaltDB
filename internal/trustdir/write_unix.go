//go:build unix

package trustdir

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// fileMode is the mode of the files Add and Disable write: readable, and
// writable by their owner only.
const fileMode = 0o644

// pemExt is the extension of the roots file Add writes.
const pemExt = ".pem"

// Add writes an operator profile called name to configPath's trust.d, its
// roots the CA certificates in ca, for the hosts match names: the PEM file
// <name>.pem first, then <name>.json pinning its SHA-256. Both are checked
// as the engine loads them before anything is written (a CA certificate
// only, a valid match that is no public suffix on its own), under the
// config lock, owned by the config directory's owner. A name trust.d
// already holds is ErrExists; a built-in's name replaces that built-in.
func Add(configPath, name string, match []string, ca []byte) (*trustprofile.Profile, error) {
	pemName := name + pemExt
	raw, err := json.MarshalIndent(trustprofile.Spec{
		Name: name, Match: match,
		Roots: []trustprofile.RootSpec{{File: pemName, SHA256: trustprofile.FileSHA256(ca)}},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	p, err := trustprofile.Parse(raw, trustprofile.Operator, func(string) ([]byte, error) { return ca, nil })
	if err != nil {
		return nil, err
	}
	err = write(configPath, func(d *service.TrustedDir, trusted int) error {
		if exists(d, trustprofile.FileName(name)) {
			return fmt.Errorf("%w (%s)", ErrExists, name)
		}
		if err := d.WriteFile(pemName, ca, fileMode, fileOwner(trusted)); err != nil {
			return err
		}
		return d.WriteFile(trustprofile.FileName(name), raw, fileMode, fileOwner(trusted))
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Disable writes the operator profile that turns off the built-in profile
// called name. trust.d holding a profile of that name already is
// ErrExists: remove it first.
func Disable(configPath, name string) error {
	raw, err := json.MarshalIndent(trustprofile.Spec{Name: name, Disabled: true}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return write(configPath, func(d *service.TrustedDir, trusted int) error {
		if exists(d, trustprofile.FileName(name)) {
			return fmt.Errorf("%w (%s)", ErrExists, name)
		}
		return d.WriteFile(trustprofile.FileName(name), raw, fileMode, fileOwner(trusted))
	})
}

// Remove deletes the operator profile called name from configPath's
// trust.d: its JSON file first, so it stops applying, then the roots files
// it names. A profile that does not load (refused) is removed too. No such
// profile is ErrNotFound.
func Remove(configPath, name string) error {
	return writeExisting(configPath, func(d *service.TrustedDir, trusted int) error {
		file := trustprofile.FileName(name)
		if !exists(d, file) {
			return fmt.Errorf("%w (%s)", ErrNotFound, name)
		}
		raw, err := Read(d, file, trusted, trustprofile.MaxProfileBytes)
		var s trustprofile.Spec
		if err == nil {
			_ = json.Unmarshal(raw, &s) // a profile that does not parse names no roots files
		}
		keep := otherRoots(d, name, trusted)
		if err := d.Remove(file); err != nil {
			return err
		}
		for _, r := range s.Roots {
			if !trustprofile.ValidFileName(r.File) || slices.Contains(keep, r.File) {
				continue
			}
			if err := d.Remove(r.File); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	})
}

// otherRoots are the roots files the other profiles in d name, which
// Remove keeps.
func otherRoots(d *service.TrustedDir, name string, trusted int) []string {
	names, err := d.Names()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		if !profileFile(n) || n == trustprofile.FileName(name) {
			continue
		}
		raw, err := Read(d, n, trusted, trustprofile.MaxProfileBytes)
		var s trustprofile.Spec
		if err != nil || json.Unmarshal(raw, &s) != nil {
			continue
		}
		for _, r := range s.Roots {
			out = append(out, r.File)
		}
	}
	return out
}

func exists(d *service.TrustedDir, name string) bool {
	f, err := d.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = f.Close()
	}
	return !errors.Is(err, fs.ErrNotExist)
}

// write runs change on configPath's trust.d, made when missing, under the
// config lock, with the owner its files must have (or root).
func write(configPath string, change func(d *service.TrustedDir, trusted int) error) error {
	return locked(configPath, true, change)
}

// writeExisting is write on a trust.d that must exist already.
func writeExisting(configPath string, change func(d *service.TrustedDir, trusted int) error) error {
	return locked(configPath, false, change)
}

func locked(configPath string, create bool, change func(d *service.TrustedDir, trusted int) error) error {
	held, err := config.LockConfigAs(configPath, -1)
	if err != nil {
		return err
	}
	defer held.Release()
	d, trusted, err := Open(configPath, create)
	if errors.Is(err, fs.ErrNotExist) && !create {
		return fmt.Errorf("%w: %s does not exist", ErrNotFound, Path(configPath))
	}
	if err != nil {
		return err
	}
	defer d.Close()
	return change(d, trusted)
}

// fileOwner is who a file written in trust.d belongs to: the config
// directory's owner when root writes it (so the engine's user reads it as
// its own), else this process (-1).
func fileOwner(trusted int) int {
	if os.Geteuid() != 0 || trusted <= 0 {
		return -1
	}
	return trusted
}
