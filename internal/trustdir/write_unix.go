//go:build unix

package trustdir

import (
	"crypto/x509"
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
	// Only a pin (Pin) holds a certificate that is not a CA.
	if _, err := trustprofile.ParseCAs(ca); err != nil {
		return nil, err
	}
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
		if exists(d, pemName) {
			return fmt.Errorf("%w: %s is in trust.d already (another profile may name it); remove it first", ErrExists, pemName)
		}
		if err := d.WriteFile(pemName, ca, fileMode, fileOwner(trusted)); err != nil {
			return err
		}
		if err := d.WriteFile(trustprofile.FileName(name), raw, fileMode, fileOwner(trusted)); err != nil {
			_ = d.Remove(pemName)
			return err
		}
		return nil
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
		keep, err := otherRoots(d, name, trusted)
		if errors.Is(err, errKeepRoots) {
			return d.Remove(file)
		}
		if err != nil {
			return err
		}
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
// Remove keeps. A profile file that cannot be read keeps every file: Remove
// then deletes only the profile's JSON.
func otherRoots(d *service.TrustedDir, name string, trusted int) ([]string, error) {
	names, err := d.Names()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if !profileFile(n) || n == trustprofile.FileName(name) {
			continue
		}
		raw, err := Read(d, n, trusted, trustprofile.MaxProfileBytes)
		var s trustprofile.Spec
		if err != nil || json.Unmarshal(raw, &s) != nil {
			return nil, errKeepRoots
		}
		for _, r := range s.Roots {
			out = append(out, r.File)
		}
	}
	return out, nil
}

// errKeepRoots: another profile file cannot be read, so Remove cannot tell
// which roots files it names and keeps them all.
var errKeepRoots = errors.New("another profile cannot be read")

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

// Pin writes the exact-host operator profile for host (pin-<host>, match
// =host) holding cert, the chain's top the person accepted, with verify:
// ca when caOnly (a certificate that does not name the host). A pin for
// host that trust.d holds already is replaced: the new PEM file first,
// then the profile, then the old PEM file removed, under the config lock.
// A profile of that name for another host, or one that is not a pin, is
// ErrExists. It returns the pin and the fingerprints it replaced.
func Pin(configPath, host string, cert *x509.Certificate, caOnly bool) (*trustprofile.Profile, []string, error) {
	pf, err := trustprofile.NewPin(host, cert, caOnly)
	if err != nil {
		return nil, nil, err
	}
	var replaced []string
	err = write(configPath, func(d *service.TrustedDir, trusted int) error {
		var err error
		replaced, err = writePin(d, trusted, pf)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return pf.Profile, replaced, nil
}

// ErrCovered: PinNew found a trust profile that covers the host already.
var ErrCovered = errors.New("a trust profile covers this host already")

// PinNew is Pin for a pin that may add trust and never replace it: under
// the config lock, when a profile covers host (built-in or operator, a pin
// included), it writes nothing and returns false when that profile is this
// very pin, else ErrCovered naming it. True when it wrote the pin.
func PinNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error) {
	pf, err := trustprofile.NewPin(host, cert, caOnly)
	if err != nil {
		return false, err
	}
	wrote := false
	err = write(configPath, func(d *service.TrustedDir, trusted int) error {
		if cur := Set(configPath).For(host); cur != nil {
			if cur.Name == pf.Profile.Name && slices.ContainsFunc(cur.Certificates(), cert.Equal) {
				return nil
			}
			return fmt.Errorf("%w: %s covers %s", ErrCovered, cur.Name, host)
		}
		_, err := writePin(d, trusted, pf)
		wrote = err == nil
		return err
	})
	return wrote, err
}

// writePin writes pf in d, replacing the pin of the same name, and returns
// the fingerprints it replaced. The config lock is held.
func writePin(d *service.TrustedDir, trusted int, pf trustprofile.PinFiles) ([]string, error) {
	name, match, pemName, pemBytes, raw := pf.Profile.Name, pf.Profile.Match[0], pf.PEMName, pf.PEM, pf.JSON
	var replaced []string
	err := func() error {
		old, err := existingPin(d, name, match, trusted)
		if err != nil {
			return err
		}
		if err := d.WriteFile(pemName, pemBytes, fileMode, fileOwner(trusted)); err != nil {
			return err
		}
		if err := d.WriteFile(trustprofile.FileName(name), raw, fileMode, fileOwner(trusted)); err != nil {
			return err
		}
		for _, r := range old.Roots {
			if r.File != pemName && trustprofile.ValidFileName(r.File) {
				_ = d.Remove(r.File)
			}
		}
		replaced = old.fingerprints
		return nil
	}()
	return replaced, err
}

// oldPin is the pin a Pin replaces: its roots files and the fingerprints of
// their certificates.
type oldPin struct {
	Roots        []trustprofile.RootSpec
	fingerprints []string
}

// existingPin is the pin for match that trust.d holds as name, or none. A
// file of that name that is not that host's pin is ErrExists.
func existingPin(d *service.TrustedDir, name, match string, trusted int) (oldPin, error) {
	file := trustprofile.FileName(name)
	if !exists(d, file) {
		return oldPin{}, nil
	}
	raw, err := Read(d, file, trusted, trustprofile.MaxProfileBytes)
	if err != nil {
		return oldPin{}, fmt.Errorf("%w: %s cannot be read (%w); remove it first", ErrExists, file, err)
	}
	p, err := trustprofile.Parse(raw, trustprofile.Operator, func(n string) ([]byte, error) { return Read(d, n, trusted, trustprofile.MaxRootFileBytes) })
	if err != nil || len(p.Match) != 1 || p.Match[0] != match {
		return oldPin{}, fmt.Errorf("%w: the name %s is taken by a profile that is not the pin for %s (another host's pin, whose name "+
			"is the same); name the CA with sslrootcert for this host instead", ErrExists, name, match)
	}
	out := oldPin{Roots: p.Roots}
	for _, c := range p.Certificates() {
		out.fingerprints = append(out.fingerprints, trustprofile.DERSHA256(c))
	}
	return out, nil
}
