package trustprofile

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/x509roots/fallback/bundle"
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

// PublicRoots are the publicly trusted roots this binary carries: the
// Mozilla (NSS) root store, whatever the system's store holds. They are
// verified with Go's own verifier, so the answer is the same on every
// system (on macOS a system pool hands verification to the platform,
// which judges any certificate as a TLS server leaf and can miss a public
// CA). A root NSS constrains (a distrust date) counts as public all the
// same: refusing more is safe.
var PublicRoots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	for r := range bundle.Roots() {
		if c, err := x509.ParseCertificate(r.Certificate); err == nil {
			pool.AddCert(c)
		}
	}
	return pool
})

// IsPublic reports whether c is, or chains to, a publicly trusted root:
// one of PublicRoots, or a root of system (the system's trust store when
// nil, which also holds the roots an administrator added).
func IsPublic(c *x509.Certificate, system *x509.CertPool) bool {
	opts := x509.VerifyOptions{Roots: PublicRoots(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, err := c.Verify(opts); err == nil {
		return true
	}
	if system == nil {
		var err error
		if system, err = SystemRoots(); err != nil || system == nil {
			return false // PublicRoots answered for the public authorities
		}
	}
	opts.Roots = system
	_, err := c.Verify(opts)
	return err == nil
}

// checkNotPublic refuses an operator verify: ca profile with a public root.
// Built-in profiles are vetted in the source tree and never use verify: ca.
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
