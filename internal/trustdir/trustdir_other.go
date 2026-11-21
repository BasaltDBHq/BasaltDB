//go:build !unix

package trustdir

import (
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
