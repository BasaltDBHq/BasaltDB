package setup

import (
	"crypto/tls"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The kinds of certificate the confirm step shows (pkg/setup's
// CertificateKind).
const (
	certificateProvider    = "PROVIDER"
	certificateNotVerified = "NOT_VERIFIED"
	certificateNone        = "NONE"
)

// CertificateOf is a connection's certificate for the confirm step, from its
// TLS state (nil without TLS): the kind shown and the issuer's short name
// (trustpin.Name), the provider's name for PROVIDER, "" for NOT_VERIFIED and
// NONE. kind is what the caller's dial verified it with; provider is the
// built-in profile's name with PROVIDER. A connection without TLS is NONE
// whatever kind says.
func CertificateOf(state *tls.ConnectionState, kind, provider string) (shown, issuer string) {
	switch {
	case state == nil:
		return certificateNone, ""
	case kind == certificateNotVerified:
		return kind, ""
	case kind == certificateProvider:
		return kind, trustprofile.ProviderName(provider)
	}
	return kind, trustpin.IssuerOf(*state)
}
