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

// Pin: see errUnsupported.
func Pin(string, string, *x509.Certificate, bool) (*trustprofile.Profile, []string, error) {
	return nil, nil, errUnsupported
}

// PinNew: see errUnsupported.
func PinNew(string, string, *x509.Certificate, bool) (bool, error) { return false, errUnsupported }

// Repin: see errUnsupported.
func Repin(string, string, *x509.Certificate, bool) ([]string, error) { return nil, errUnsupported }
