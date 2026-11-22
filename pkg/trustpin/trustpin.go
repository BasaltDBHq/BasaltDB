// Package trustpin reads the certificate chain a Postgres server presents,
// with nothing but the TLS handshake, and checks it, so a person can pin
// the chain's top for that one host (CONTRACT.md, Trust profiles, Pinning
// on first use). It sends Postgres's SSLRequest and completes a TLS
// handshake that does not verify the certificate, only to read it, then
// closes the connection: no startup message, no user name, no password.
// The engine and the connect service share it, so a certificate authority
// the person trusted on the connect page is checked the same way on both
// sides (Approved; CONTRACT.md, Pinning from the connect page).
package trustpin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Dial opens the TCP connection; nil is a plain net.Dialer.
type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

const (
	// timeout bounds the TCP connection and the handshake.
	timeout = 10 * time.Second
	// sslRequestCode is Postgres's SSLRequest code (protocol 1234.5679).
	sslRequestCode = 80877103
	// sslRequestLen is the SSLRequest's length, the length field included.
	sslRequestLen = 8
	// lenBytes is the size of a length field.
	lenBytes = 4
	// acceptsTLS is the server's one-byte answer that it accepts TLS.
	acceptsTLS = 'S'
)

// ErrNoTLS: the server answered the SSLRequest with no.
var ErrNoTLS = errors.New("the server does not offer TLS")

// Fetch is the chain host:port presents, leaf first, read with the TLS
// handshake alone. The certificate is not verified here: Check does that.
func Fetch(ctx context.Context, dial Dial, host string, port int) ([]*x509.Certificate, error) {
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	var req [sslRequestLen]byte
	binary.BigEndian.PutUint32(req[:lenBytes], sslRequestLen)
	binary.BigEndian.PutUint32(req[lenBytes:], sslRequestCode)
	if _, err := conn.Write(req[:]); err != nil {
		return nil, err
	}
	var answer [1]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil {
		return nil, err
	}
	if answer[0] != acceptsTLS {
		return nil, ErrNoTLS
	}
	cfg := &tls.Config{
		// Only to read the chain: Check verifies it, and nothing but the
		// handshake is sent on this connection.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if _, err := netip.ParseAddr(host); err != nil {
		cfg.ServerName = host // SNI for a name; none for an address
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("the TLS handshake with %s failed: %w", host, err)
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("the server sent no certificate")
	}
	return chain, nil
}

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
// trust store (trustprofile.SystemRoots) and, for Public, the public roots
// the binary carries as well (trustprofile.PublicRoots).
func Check(chain []*x509.Certificate, host string, now time.Time) Seen {
	top := chain[len(chain)-1]
	s := Seen{Top: top, SHA256: trustprofile.DERSHA256(top)}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	system, serr := trustprofile.SystemRoots()
	if serr != nil || system == nil {
		system = x509.NewCertPool() // PublicRoots still answer for the public authorities
	}
	opts := x509.VerifyOptions{DNSName: host, Roots: system, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, err := chain[0].Verify(opts)
	s.System = err == nil
	s.Public = s.System || publicChain(chain, inter, now, system)
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
func publicChain(chain []*x509.Certificate, inter *x509.CertPool, now time.Time, system *x509.CertPool) bool {
	for _, roots := range []*x509.CertPool{trustprofile.PublicRoots(), system} {
		opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
		if _, err := chain[0].Verify(opts); err == nil {
			return true
		}
	}
	for _, c := range chain {
		if trustprofile.IsPublic(c, system) {
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
func (s Seen) Subject() string {
	r := []rune(strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || bidiControl(c) {
			return -1
		}
		return c
	}, s.Top.Subject.String()))
	if len(r) > maxSubject {
		r = r[:maxSubject]
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
// caller's own reading.
func Approved(chain []*x509.Certificate, host string, now time.Time, approved string) (Seen, *trustprofile.Profile, error) {
	s := Check(chain, host, now)
	if s.Public {
		return s, nil, ErrPublic
	}
	if !ValidSHA256(approved) || s.SHA256 != approved {
		return s, nil, ErrMismatch
	}
	if !s.Full && !s.NameOnly {
		return s, nil, ErrNotPinnable
	}
	pin, err := trustprofile.NewPin(host, s.Top, !s.Full)
	if err != nil {
		return s, nil, err
	}
	return s, pin.Profile, nil
}
