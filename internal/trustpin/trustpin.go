// Package trustpin reads the certificate chain a Postgres server presents,
// with nothing but the TLS handshake, and checks it, so a person can pin
// the chain's top for that one host (CONTRACT.md, Trust profiles, Pinning
// on first use). It sends Postgres's SSLRequest and completes a TLS
// handshake that does not verify the certificate, only to read it, then
// closes the connection: no startup message, no user name, no password.
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
	"time"

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
		InsecureSkipVerify: true, //nolint:gosec // the chain is read, not trusted; Check verifies it before anything is sent
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
}

// Check is what chain, leaf first, proves for host.
func Check(chain []*x509.Certificate, host string, now time.Time) Seen {
	top := chain[len(chain)-1]
	s := Seen{Top: top, SHA256: trustprofile.DERSHA256(top)}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{DNSName: host, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, err := chain[0].Verify(opts)
	s.System = err == nil
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

// hostnameFailed reports whether leaf fails for host on the name alone.
func hostnameFailed(leaf *x509.Certificate, host string, target *x509.HostnameError) bool {
	return errors.As(leaf.VerifyHostname(host), target)
}
