// Package certroots is the root certificates a TLS client checks against:
// the system's trust store, which tests can replace, and the publicly
// trusted roots the binary carries.
package certroots

import (
	"crypto/x509"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// systemRoots is the system's trust store as SystemRoots reads it; tests
// replace it (SetSystemRootsForTest).
var systemRoots atomic.Pointer[func() (*x509.CertPool, error)]

func init() {
	f := x509.SystemCertPool
	systemRoots.Store(&f)
}

// SetSystemRootsForTest makes pool the system's trust store for SystemRoots
// and IsPublic with a nil pool, until restore is called. Only tests call it.
func SetSystemRootsForTest(pool *x509.CertPool) (restore func()) {
	old := systemRoots.Load()
	f := func() (*x509.CertPool, error) { return pool, nil } //nolint:unparam // the same type as x509.SystemCertPool
	systemRoots.Store(&f)
	return func() { systemRoots.Store(old) }
}

// SystemRoots is the system's trust store.
func SystemRoots() (*x509.CertPool, error) { return (*systemRoots.Load())() }

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

// WithSystem is the system's authorities and cas. Without a system pool (an
// error loading it) it is cas alone. It reads x509.SystemCertPool itself,
// not SystemRoots. The pool is never changed after.
func WithSystem(cas []*x509.Certificate) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, ca := range cas {
		pool.AddCert(ca)
	}
	return pool
}
