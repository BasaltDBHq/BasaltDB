//go:build !unix

package trustdir

import (
	"crypto/x509"
	"errors"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// errUnsupported: trust.d is read and written on linux and darwin only.
var errUnsupported = errors.New("trust.d is supported on linux and darwin only")

// Load: operator profiles are read on linux and darwin only.
func Load(string) ([]*trustprofile.Profile, []trustprofile.Refused) { return nil, nil }

// Add: see errUnsupported.
func Add(string, string, []string, []byte) (*trustprofile.Profile, error) { return nil, errUnsupported }

// Disable: see errUnsupported.
func Disable(string, string) error { return errUnsupported }

// Remove: see errUnsupported.
func Remove(string, string) error { return errUnsupported }

// Pin: see errUnsupported.
func Pin(string, string, *x509.Certificate, bool) (*trustprofile.Profile, []string, error) {
	return nil, nil, errUnsupported
}

// PinNew: see errUnsupported.
func PinNew(string, string, *x509.Certificate, bool) (bool, error) { return false, errUnsupported }

// ErrCovered: PinNew found a trust profile that covers the host already.
var ErrCovered = errors.New("a trust profile covers this host already")

// PinProfile: see errUnsupported.
func PinProfile(string, *x509.Certificate, bool) (*trustprofile.Profile, error) {
	return nil, errUnsupported
}
