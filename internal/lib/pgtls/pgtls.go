// Package pgtls reads the certificate chain a Postgres server presents,
// with nothing but the TLS handshake. It sends Postgres's SSLRequest and
// completes a TLS handshake that does not verify the certificate, only to
// read it, then closes the connection: no startup message, no user name,
// no password.
package pgtls

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
// handshake alone. The certificate is not verified here: the caller checks
// it.
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
