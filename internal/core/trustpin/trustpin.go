// Package trustpin checks the certificate chain a Postgres server presents
// (read with pgtls.Fetch), so a person can pin the chain's top for that one
// host (CONTRACT.md, Trust profiles, Pinning on first use). The engine and
// the connect service share it through package pkg/trustpin, so a
// certificate authority the person trusted on the connect page is checked
// the same way on both sides (Approved; CONTRACT.md, Pinning from the
// connect page).
package trustpin

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
)

// Seen is what Check found in a chain for a host.
type Seen struct {
	// Top is the chain's top certificate: the root when the server sends
	// it, else the highest one it sends.
	Top *x509.Certificate
	// SHA256 is Top's DER fingerprint, lowercase hex (trustprofile.DERSHA256).
	SHA256 string
	// System: the chain verifies for the host against the system's
	// authorities, so no pin is needed.
	System bool
	// Full: the chain verifies for the host name against Top.
	Full bool
	// NameOnly: the chain verifies against Top but not for the host name
	// (a certificate that does not name it): only verify: ca can pin it.
	NameOnly bool
	// Public: Top is, or the chain chains to, an authority in the system's
	// trust store (System implies it). Such a chain is never pinned: a
	// failure there is the name's, and a pin with verify: ca would accept
	// anything that authority issues as the host.
	Public bool
}

// Pinnable reports whether the chain can be pinned: it verifies against
// its own top (with the name, or without it) and nothing of it is public.
func (s Seen) Pinnable() bool { return !s.Public && (s.Full || s.NameOnly) }

// Check is what chain, leaf first, proves for host, against the system's
// trust store (roots.System) and, for Public, the public roots the binary
// carries as well (roots.Public).
func Check(chain []*x509.Certificate, host string, now time.Time, roots trustprofile.Roots) Seen {
	top := chain[len(chain)-1]
	s := Seen{Top: top, SHA256: trustprofile.DERSHA256(top)}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	system := roots.System() // empty when it does not load: the public roots still answer
	opts := x509.VerifyOptions{DNSName: host, Roots: system, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, err := chain[0].Verify(opts)
	s.System = err == nil
	s.Public = s.System || publicChain(chain, inter, now, system, roots)
	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(top)
	_, err = chain[0].Verify(opts)
	s.Full = err == nil
	if !s.Full {
		opts.DNSName = ""
		_, err = chain[0].Verify(opts)
		var hostErr x509.HostnameError
		s.NameOnly = err == nil && hostnameFailed(chain[0], host, &hostErr)
	}
	return s
}

// publicChain reports whether the leaf chains, without the name, to a
// public root or a root of system, or any certificate of chain is, or
// chains to, one (trustprofile.IsPublic).
func publicChain(chain []*x509.Certificate, inter *x509.CertPool, now time.Time, system *x509.CertPool, roots trustprofile.Roots) bool {
	for _, pool := range []*x509.CertPool{roots.Public(), system} {
		opts := x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
		if _, err := chain[0].Verify(opts); err == nil {
			return true
		}
	}
	for _, c := range chain {
		if trustprofile.IsPublic(c, system, roots) {
			return true
		}
	}
	return false
}

// hostnameFailed reports whether leaf fails for host on the name alone.
func hostnameFailed(leaf *x509.Certificate, host string, target *x509.HostnameError) bool {
	return errors.As(leaf.VerifyHostname(host), target)
}

// maxSubject is the most of a chain top's subject Subject returns: the
// server chooses it.
const maxSubject = 512

// Subject is the subject of s's top, RFC 2253, with the control characters
// (C0, C1) and the bidirectional controls removed, cut to 512 characters:
// the server chooses it, and a person reads it.
func (s Seen) Subject() string { return SubjectOf(s.Top) }

// SubjectOf is c's subject as Subject gives a chain top's: RFC 2253,
// cleaned and cut to 512 characters.
func SubjectOf(c *x509.Certificate) string { return clean(c.Subject.String(), maxSubject) }

// clean is text a server chose with the control characters (C0, C1) and
// the bidirectional controls removed, cut to max characters.
func clean(text string, maxChars int) string {
	r := []rune(strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || bidiControl(c) {
			return -1
		}
		return c
	}, text))
	if len(r) > maxChars {
		r = r[:maxChars]
	}
	return string(r)
}

// bidiControl is a Unicode bidirectional control, which can reorder what a
// person reads.
func bidiControl(c rune) bool {
	const (
		arabicLetterMark      = 0x061c
		leftToRightMark       = 0x200e
		rightToLeftMark       = 0x200f
		leftToRightEmbedding  = 0x202a
		rightToLeftOverride   = 0x202e
		leftToRightIsolate    = 0x2066
		popDirectionalIsolate = 0x2069
	)
	switch c {
	case arabicLetterMark, leftToRightMark, rightToLeftMark:
		return true
	}
	return (c >= leftToRightEmbedding && c <= rightToLeftOverride) || (c >= leftToRightIsolate && c <= popDirectionalIsolate)
}

// ErrMismatch: the chain's top is not the certificate the person approved.
var ErrMismatch = errors.New("the server presents another certificate authority than the one approved")

// ErrPublic: the chain is, or chains to, an authority in the system's
// trust store, so it is never pinned (Seen.Public).
var ErrPublic = trustprofile.ErrPublic

// ErrNotPinnable: the chain does not verify against its own top, with or
// without the host name, so no pin can hold it.
var ErrNotPinnable = errors.New("the server's certificate does not verify against the top of its own chain")

// ValidSHA256 reports whether fp is a SHA-256 as an approval carries it:
// 64 lowercase hex digits.
func ValidSHA256(fp string) bool {
	if len(fp) != sha256HexLen {
		return false
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sha256HexLen is a SHA-256 in hex.
const sha256HexLen = 64

// Approved is what chain proves for host against approved, the SHA-256 the
// person approved: the pin for its top (verify: ca when the leaf does not
// name the host), only when that top's SHA-256 is approved (ErrMismatch,
// also for a malformed approved) and the chain verifies against it
// (ErrNotPinnable). A public chain is never pinned (ErrPublic), whatever
// the approval. The approval is never trusted on its own: the chain is the
// caller's own reading. Check and the pin read roots.
func Approved(chain []*x509.Certificate, host string, now time.Time, approved string, roots trustprofile.Roots) (Seen, *trustprofile.Profile, error) {
	s := Check(chain, host, now, roots)
	if s.Public {
		return s, nil, ErrPublic
	}
	if !ValidSHA256(approved) || s.SHA256 != approved {
		return s, nil, ErrMismatch
	}
	if !s.Full && !s.NameOnly {
		return s, nil, ErrNotPinnable
	}
	pin, err := trustprofile.NewPin(host, s.Top, !s.Full, roots)
	if err != nil {
		return s, nil, err
	}
	return s, pin.Profile, nil
}
