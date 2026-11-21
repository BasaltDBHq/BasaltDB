// Package trustprofiletest is a stand-in for a database whose certificate
// chains to a trust profile's root, in tests: a test CA playing the root, and a
// Postgres server that completes TLS
// with a certificate that CA signed and then refuses the password. A client
// that gets the refusal (28P01) verified the certificate.
package trustprofiletest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// certLife is how long the test certificates are valid.
const certLife = 24 * time.Hour

// sslRequestCode is the request code of Postgres's SSLRequest message.
const sslRequestCode = 80877103

// sslRequestLen is the length of an SSLRequest, its length field included.
const sslRequestLen = 8

// maxStartup bounds the startup message the server reads.
const maxStartup = 1 << 16

// lenBytes is the size of a message's length field.
const lenBytes = 4

// Chain is a test CA and a server certificate for host it signed.
func Chain(t *testing.T, host string) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "trustprofiletest root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certLife),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certLife),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return ca, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Serve runs the server with cert until the test ends and returns a dialer
// that reaches it whatever address is asked for (pgx's DialFunc).
func Serve(t *testing.T, cert tls.Certificate) func(ctx context.Context, network, addr string) (net.Conn, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c, cfg)
		}
	}()
	addr := ln.Addr().String()
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// serve answers one connection: SSLRequest, TLS, the startup message, then
// an ErrorResponse 28P01.
func serve(c net.Conn, cfg *tls.Config) {
	defer func() { _ = c.Close() }()
	var req [sslRequestLen]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	if binary.BigEndian.Uint32(req[lenBytes:]) != sslRequestCode {
		return
	}
	if _, err := c.Write([]byte{'S'}); err != nil {
		return
	}
	tc := tls.Server(c, cfg)
	if err := tc.Handshake(); err != nil {
		return
	}
	if err := readStartup(tc); err != nil {
		return
	}
	_, _ = tc.Write(errorResponse("28P01", "password authentication failed"))
}

func readStartup(r io.Reader) error {
	var n [lenBytes]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size < lenBytes || size > maxStartup {
		return errors.New("bad startup length")
	}
	_, err := io.CopyN(io.Discard, r, int64(size-lenBytes))
	return err
}

// errorResponse is a FATAL ErrorResponse with code and message.
func errorResponse(code, msg string) []byte {
	var body []byte
	for _, f := range []struct {
		k byte
		v string
	}{{'S', "FATAL"}, {'V', "FATAL"}, {'C', code}, {'M', msg}} {
		body = append(body, f.k)
		body = append(body, f.v...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 1+lenBytes, 1+lenBytes+len(body))
	out[0] = 'E'
	binary.BigEndian.PutUint32(out[1:], uint32(len(body)+lenBytes))
	return append(out, body...)
}

// pemSize is about the size of one test certificate in PEM.
const pemSize = 1024

// PEM is cas as one PEM file.
func PEM(cas ...*x509.Certificate) []byte {
	out := make([]byte, 0, len(cas)*pemSize)
	for _, ca := range cas {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	return out
}

// Profile is a profile called name of origin, matching match, whose one
// roots file holds cas, loaded through trustprofile.Parse.
func Profile(t testing.TB, origin trustprofile.Origin, name string, match []string, cas ...*x509.Certificate) *trustprofile.Profile {
	t.Helper()
	b := PEM(cas...)
	raw, err := json.Marshal(trustprofile.Spec{Name: name, Match: match, Roots: []trustprofile.RootSpec{{File: name + ".pem", SHA256: trustprofile.FileSHA256(b)}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := trustprofile.Parse(raw, origin, func(string) ([]byte, error) { return b, nil })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Set is the built-in profiles with each named one's roots replaced by
// cas (a test CA standing in for the provider's roots), and operator.
func Set(t testing.TB, replace map[string][]*x509.Certificate, operator ...*trustprofile.Profile) *trustprofile.Set {
	t.Helper()
	builtin := make([]*trustprofile.Profile, 0, len(trustprofile.BuiltIns()))
	for _, p := range trustprofile.BuiltIns() {
		if cas, ok := replace[p.Name]; ok {
			p = Profile(t, trustprofile.BuiltIn, p.Name, p.Match, cas...)
		}
		builtin = append(builtin, p)
	}
	return trustprofile.NewSet(builtin, operator, nil)
}
