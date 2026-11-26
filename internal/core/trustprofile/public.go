package trustprofile

import (
	"errors"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/lib/certroots"
)

// A pin trusts one certificate for one host. A certificate of a publicly
// trusted authority, or one that chains to it, can never be pinned: with
// verify: ca it would accept every certificate that authority issues, for
// any name, as the host (CONTRACT.md, Pinning on first use, Public
// authorities). A host whose certificate a public authority signed needs
// no pin; when it fails, it failed on the name, and the fix is the host
// name its certificate names. Which authorities are public is
// certroots.IsPublic.

// ErrPublic is a pin, or a verify: ca root, of a publicly trusted
// certificate authority.
var ErrPublic = errors.New("the certificate is, or chains to, an authority in the system's trust store")

// checkNotPublic refuses an operator verify: ca profile with a public root.
// Built-in profiles are vetted in the source tree and never use verify: ca.
func checkNotPublic(s Spec, origin Origin, files []RootFile) error {
	if origin != Operator || s.Verify != VerifyCA {
		return nil
	}
	for _, f := range files {
		for _, c := range f.Certs {
			if certroots.IsPublic(c, nil) {
				return fmt.Errorf("%s: %w; with verify %q it would accept any certificate that authority issues as this host, so it is refused (use the host name the certificate names instead)", f.Name, ErrPublic, VerifyCA)
			}
		}
	}
	return nil
}
