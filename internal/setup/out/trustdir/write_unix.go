//go:build unix

package trustdir

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// fileMode is the mode of the files a pin writes: readable, and writable
// by their owner only.
const fileMode = 0o644

func exists(d *osservice.TrustedDir, name string) bool {
	f, err := d.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = f.Close()
	}
	return !errors.Is(err, fs.ErrNotExist)
}

// write runs change on configPath's trust.d, made when missing, under the
// config lock, with the owner its files must have (or root).
func write(configPath string, change func(d *osservice.TrustedDir, trusted int) error) error {
	return locked(configPath, true, change)
}

// writeExisting is write on a trust.d that must exist already.
func writeExisting(configPath string, change func(d *osservice.TrustedDir, trusted int) error) error {
	return locked(configPath, false, change)
}

func locked(configPath string, create bool, change func(d *osservice.TrustedDir, trusted int) error) error {
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
// its own, credfiles.CredentialOwner), else this process (-1).
func fileOwner(trusted int) int {
	if os.Geteuid() != 0 {
		return -1
	}
	return credfiles.CredentialOwner(trusted)
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
	err = write(configPath, func(d *osservice.TrustedDir, trusted int) error {
		var err error
		replaced, err = writePin(d, trusted, pf)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return pf.Profile, replaced, nil
}

// PinNew is Pin for a pin that may add trust and never replace it: under
// the config lock, when a profile covers host (built-in or operator, a pin
// included), it writes nothing and returns false when that profile is this
// very pin, else setupcode.ErrCovered naming it. True when it wrote the pin.
func PinNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error) {
	pf, err := trustprofile.NewPin(host, cert, caOnly)
	if err != nil {
		return false, err
	}
	wrote := false
	err = write(configPath, func(d *osservice.TrustedDir, trusted int) error {
		if cur := Set(configPath).For(host); cur != nil {
			if cur.Name == pf.Profile.Name && slices.ContainsFunc(cur.Certificates(), cert.Equal) {
				return nil
			}
			return fmt.Errorf("%w: %s covers %s", setupcode.ErrCovered, cur.Name, host)
		}
		_, err := writePin(d, trusted, pf)
		wrote = err == nil
		return err
	})
	return wrote, err
}

// Repin replaces the engine's own pin for host (pin-<host>) with cert, as
// the setup page's TRUST fix does (the new PEM file, then the profile,
// then the old PEM file removed, under the config lock), for a certificate
// the person trusted on the connect page that the engine's own reading
// matched. Under the lock, the profile that covers host must be that pin:
// another one (built-in or operator) is setupcode.ErrCovered and nothing is
// written, so a replacement never reaches past the engine's own pin. It
// returns the fingerprints it replaced.
func Repin(configPath, host string, cert *x509.Certificate, caOnly bool) ([]string, error) {
	pf, err := trustprofile.NewPin(host, cert, caOnly)
	if err != nil {
		return nil, err
	}
	var replaced []string
	err = writeExisting(configPath, func(d *osservice.TrustedDir, trusted int) error {
		if cur := Set(configPath).For(host); cur == nil || cur.Name != pf.Profile.Name || !cur.Exact() {
			return fmt.Errorf("%w: the engine's pin %s is not what covers %s now", setupcode.ErrCovered, pf.Profile.Name, host)
		}
		var err error
		replaced, err = writePin(d, trusted, pf)
		return err
	})
	return replaced, err
}

// writePin writes pf in d, replacing the pin of the same name, and returns
// the fingerprints it replaced. The config lock is held.
func writePin(d *osservice.TrustedDir, trusted int, pf trustprofile.PinFiles) ([]string, error) {
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
func existingPin(d *osservice.TrustedDir, name, match string, trusted int) (oldPin, error) {
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
			"is the same); remove that profile from trust.d, then trust this host again", ErrExists, name, match)
	}
	out := oldPin{Roots: p.Roots}
	for _, c := range p.Certificates() {
		out.fingerprints = append(out.fingerprints, trustprofile.DERSHA256(c))
	}
	return out, nil
}
