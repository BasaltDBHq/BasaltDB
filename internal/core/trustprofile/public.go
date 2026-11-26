package trustprofile

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// A pin trusts one certificate for one host. A certificate of a publicly
// trusted authority, or one that chains to it, can never be pinned: with
// verify: ca it would accept every certificate that authority issues, for
// any name, as the host (CONTRACT.md, Pinning on first use, Public
// authorities). A host whose certificate a public authority signed needs
// no pin; when it fails, it failed on the name, and the fix is the host
// name its certificate names.

// Roots are the root stores a check reads: the caller passes them, so this
// package reads no system state itself. The engine passes
// certroots.Store{}; a test can pass its own.
type Roots interface {
	// System is the system's trust store: an empty pool when it does not
	// load, never nil.
	System() *x509.CertPool
	// Public are the publicly trusted roots the binary carries.
	Public() *x509.CertPool
	// WithSystem is a new pool of the system's authorities and cas: cas
	// alone when the system's do not load.
	WithSystem(cas []*x509.Certificate) *x509.CertPool
}

// ErrPublic is a pin, or a verify: ca root, of a publicly trusted
// certificate authority.
var ErrPublic = errors.New("the certificate is, or chains to, an authority in the system's trust store")

// IsPublic reports whether c is, or chains to, a publicly trusted root:
// one of roots.Public, or a root of system (roots.System when nil, which
// also holds the roots an administrator added).
func IsPublic(c *x509.Certificate, system *x509.CertPool, roots Roots) bool {
	opts := x509.VerifyOptions{Roots: roots.Public(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, err := c.Verify(opts); err == nil {
		return true
	}
	if system == nil {
		system = roots.System()
	}
	opts.Roots = system
	_, err := c.Verify(opts)
	return err == nil
}

// checkNotPublic refuses an operator verify: ca profile with a public root.
// Built-in profiles are vetted in the source tree and never use verify: ca.
func checkNotPublic(s Spec, origin Origin, files []RootFile, roots Roots) error {
	if origin != Operator || s.Verify != VerifyCA {
		return nil
	}
	for _, f := range files {
		for _, c := range f.Certs {
			if IsPublic(c, nil, roots) {
				return fmt.Errorf("%s: %w; with verify %q it would accept any certificate that authority issues as this host, so it is refused (use the host name the certificate names instead)", f.Name, ErrPublic, VerifyCA)
			}
		}
	}
	return nil
}
