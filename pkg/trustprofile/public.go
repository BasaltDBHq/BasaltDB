package trustprofile

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
)

// A pin trusts one certificate for one host. A certificate of a publicly
// trusted authority, or one that chains to it, can never be pinned: with
// verify: ca it would accept every certificate that authority issues, for
// any name, as the host (CONTRACT.md, Pinning on first use, Public
// authorities). A host whose certificate a public authority signed needs
// no pin; when it fails, it failed on the name, and the fix is the host
// name its certificate names.

// systemRoots is the system's trust store as IsPublic reads it; tests
// replace it (SetSystemRootsForTest).
var systemRoots atomic.Pointer[func() (*x509.CertPool, error)]

func init() {
	f := x509.SystemCertPool
	systemRoots.Store(&f)
}

// SetSystemRootsForTest makes pool the system's trust store for IsPublic
// with a nil pool, Parse and package trustpin, until restore is called.
// Only tests call it.
func SetSystemRootsForTest(pool *x509.CertPool) (restore func()) {
	old := systemRoots.Load()
	f := func() (*x509.CertPool, error) { return pool, nil } //nolint:unparam // the same type as x509.SystemCertPool
	systemRoots.Store(&f)
	return func() { systemRoots.Store(old) }
}

// SystemRoots is the system's trust store.
func SystemRoots() (*x509.CertPool, error) { return (*systemRoots.Load())() }

// ErrPublic is a pin, or a verify: ca root, of a publicly trusted
// certificate authority.
var ErrPublic = errors.New("the certificate is, or chains to, an authority in the system's trust store")

// IsPublic reports whether c is, or chains to, a root of system (the
// system's trust store when nil). A store that cannot be read counts as
// public: fail closed.
func IsPublic(c *x509.Certificate, system *x509.CertPool) bool {
	if system == nil {
		var err error
		if system, err = SystemRoots(); err != nil || system == nil {
			return true
		}
	}
	_, err := c.Verify(x509.VerifyOptions{Roots: system, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// checkNotPublic refuses an operator verify: ca profile with a public root.
func checkNotPublic(s Spec, origin Origin, files []RootFile) error {
	if origin != Operator || s.Verify != VerifyCA {
		return nil
	}
	for _, f := range files {
		for _, c := range f.Certs {
			if IsPublic(c, nil) {
				return fmt.Errorf("%s: %w; with verify %q it would accept any certificate that authority issues as this host, so it is refused (use the host name the certificate names instead)", f.Name, ErrPublic, VerifyCA)
			}
		}
	}
	return nil
}
