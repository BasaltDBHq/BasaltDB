package trustpin

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
)

// maxName is the most of a certificate authority's name Name returns: the
// server chooses it.
const maxName = 128

// Name is a certificate authority's short name, as the confirm step shows
// it (CONTRACT.md, The install of a real database, Is this your
// database?): the subject's common name, else its first organization, else
// the whole subject (RFC 2253), cleaned as Subject is and cut to 128
// characters. The server chooses it: it names, it proves nothing.
func Name(n pkix.Name) string {
	switch {
	case n.CommonName != "":
		return clean(n.CommonName, maxName)
	case len(n.Organization) > 0 && n.Organization[0] != "":
		return clean(n.Organization[0], maxName)
	}
	return clean(n.String(), maxName)
}

// IssuerOf is the name of the authority at the top of a TLS connection's
// chain: the root of the chain it verified against, else the highest
// certificate the server sent (a pin checked in a VerifyConnection leaves
// no verified chain): that certificate itself when it is self-signed, else
// its issuer. "" when the server sent no certificate.
func IssuerOf(cs tls.ConnectionState) string {
	chain := cs.PeerCertificates
	if len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		chain = cs.VerifiedChains[0]
	}
	if len(chain) == 0 {
		return ""
	}
	return topName(chain[len(chain)-1])
}

// topName is the authority c stands for at a chain's top: c's own name when
// it is self-signed (a root), else the name of the root that signed it.
func topName(c *x509.Certificate) string {
	if bytes.Equal(c.RawIssuer, c.RawSubject) {
		return Name(c.Subject)
	}
	return Name(c.Issuer)
}
