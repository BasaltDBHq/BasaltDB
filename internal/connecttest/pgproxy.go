package connecttest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // Postgres's md5 password method, checked, never used to protect anything
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Proxy is a TLS-terminating Postgres proxy for tests: it presents a
// certificate for Host from its own CA (Roots), forwards the session in
// plain to the upstream Postgres, and records every authentication message
// the client sends, so a test can check which logins carried the agent's
// real password. It is how the tests see the wire: the engine's verified
// TLS reaches it as it would reach the person's database.
type Proxy struct {
	// Host is the name the certificate is for.
	Host string
	// Addr is where it listens (127.0.0.1:port).
	Addr  string
	Roots *x509.CertPool

	upstream string
	tls      *tls.Config

	mu     sync.Mutex
	logins []Login
}

// Login is one login attempt the proxy saw.
type Login struct {
	User string
	// TLS: the client came over TLS.
	TLS bool
	// SCRAM is the exchange, when the server asked for SCRAM.
	SCRAM *SCRAMExchange
	// Cleartext is a cleartext password message; MD5 an md5 one with its
	// salt.
	Cleartext *string
	MD5       *md5Password
}

// SCRAMExchange is what a SCRAM login carried: the messages its proof is
// computed over, and the proof.
type SCRAMExchange struct {
	ClientFirstBare, ServerFirst, ClientFinalWithoutProof string
	Proof                                                 []byte
}

type md5Password struct {
	Value string
	Salt  []byte
}

// Carried reports whether the login carried a valid credential for user
// with password: a SCRAM proof that verifies against it, the cleartext
// password, or its md5 hash.
func (l Login) Carried(user, password string) bool {
	switch {
	case l.User != user:
		return false
	case l.SCRAM != nil:
		return l.SCRAM.valid(password)
	case l.Cleartext != nil:
		return *l.Cleartext == password
	case l.MD5 != nil:
		inner := md5.Sum([]byte(password + user))                                     //nolint:gosec // see the import
		outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), l.MD5.Salt...)) //nolint:gosec // see the import
		return l.MD5.Value == "md5"+hex.EncodeToString(outer[:])
	}
	return false
}

// valid recomputes the proof the client would send with password.
func (x *SCRAMExchange) valid(password string) bool {
	attrs := map[string]string{}
	for _, kv := range strings.Split(x.ServerFirst, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			attrs[k] = v
		}
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		return false
	}
	iter, err := strconv.Atoi(attrs["i"])
	if err != nil {
		return false
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		return false
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	sig := mac(stored[:], x.ClientFirstBare+","+x.ServerFirst+","+x.ClientFinalWithoutProof)
	want := make([]byte, len(clientKey))
	for i := range clientKey {
		want[i] = clientKey[i] ^ sig[i]
	}
	return hmac.Equal(want, x.Proof)
}

func mac(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// Logins are the logins seen so far.
func (p *Proxy) Logins() []Login {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Login(nil), p.logins...)
}

// CarriedFor are the logins that carried user's password.
func (p *Proxy) CarriedFor(user, password string) int {
	n := 0
	for _, l := range p.Logins() {
		if l.Carried(user, password) {
			n++
		}
	}
	return n
}

// StartProxy serves a Proxy for host in front of upstream (host:port of a
// Postgres that accepts plain connections) until the test ends.
func StartProxy(t *testing.T, host, upstream string) *Proxy {
	t.Helper()
	cert, roots := testCertificate(t, host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Host: host, Addr: ln.Addr().String(), Roots: roots, upstream: upstream, tls: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { p.serve(c) })
		}
	})
	return p
}

// Dial is a dialer that sends every connection to the proxy, whatever
// address was asked for (the engine's checked address, in a test).
func (p *Proxy) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", p.Addr)
}

// certLife is how long the test certificates are valid.
const certLife = 24 * time.Hour

const (
	sslRequestCode = 80877103
	gssEncCode     = 80877104
	// authentication request codes of the 'R' message.
	authCleartext    = 3
	authMD5          = 5
	authSASL         = 10
	authSASLContinue = 11
	maxMessage       = 1 << 20
	lengthBytes      = 4
)

// conn is one proxied session and its login.
type conn struct {
	p     *Proxy
	mu    sync.Mutex
	login *Login
	// asked is the last authentication request the server sent.
	asked uint32
}

func (p *Proxy) serve(c net.Conn) {
	defer c.Close()
	client := c
	first, err := readStartup(client)
	if err != nil {
		return
	}
	login := &Login{}
	for code := binary.BigEndian.Uint32(first[lengthBytes:]); code == sslRequestCode || code == gssEncCode; code = binary.BigEndian.Uint32(first[lengthBytes:]) {
		if code == gssEncCode {
			_, _ = client.Write([]byte{'N'})
		} else {
			if _, err := client.Write([]byte{'S'}); err != nil {
				return
			}
			tc := tls.Server(client, p.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			client, login.TLS = tc, true
		}
		if first, err = readStartup(client); err != nil {
			return
		}
	}
	login.User = startupUser(first)
	up, err := net.Dial("tcp", p.upstream)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(first); err != nil {
		return
	}
	s := &conn{p: p, login: login}
	done := make(chan struct{}, 2)
	go func() { s.fromServer(up, client); done <- struct{}{} }()
	go func() { s.fromClient(client, up); done <- struct{}{} }()
	<-done
	client.Close()
	up.Close()
	<-done
}

// record keeps the login once its credential message is complete, before
// it is forwarded: a test that saw the login answered sees it recorded.
// s.mu is held.
func (s *conn) record() {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	s.p.logins = append(s.p.logins, *s.login)
}

// fromServer forwards the server's messages, noting each authentication
// request before the client sees it.
func (s *conn) fromServer(up io.Reader, client io.Writer) {
	for {
		typ, body, err := readMessage(up)
		if err != nil {
			return
		}
		if typ == 'R' && len(body) >= lengthBytes {
			code := binary.BigEndian.Uint32(body)
			s.mu.Lock()
			s.asked = code
			switch {
			case code == authSASLContinue && s.login.SCRAM != nil:
				s.login.SCRAM.ServerFirst = string(body[lengthBytes:])
			case code == authMD5 && len(body) >= 2*lengthBytes:
				s.login.MD5 = &md5Password{Salt: bytes.Clone(body[lengthBytes : 2*lengthBytes])}
			}
			s.mu.Unlock()
		}
		if err := writeMessage(client, typ, body); err != nil {
			return
		}
	}
}

// fromClient forwards the client's messages, recording each password
// message by the request it answers.
func (s *conn) fromClient(client io.Reader, up io.Writer) {
	for {
		typ, body, err := readMessage(client)
		if err != nil {
			return
		}
		if typ == 'p' {
			s.password(body)
		}
		if err := writeMessage(up, typ, body); err != nil {
			return
		}
	}
}

func (s *conn) password(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.asked {
	case authSASL:
		// SASLInitialResponse: mechanism, int32 length, client-first.
		_, rest, ok := bytes.Cut(body, []byte{0})
		if !ok || len(rest) < lengthBytes {
			return
		}
		first := string(rest[lengthBytes:])
		bare := first
		if i := strings.Index(first, "n="); i >= 0 {
			bare = first[i:]
		}
		s.login.SCRAM = &SCRAMExchange{ClientFirstBare: bare}
	case authSASLContinue:
		if s.login.SCRAM == nil {
			return
		}
		final := string(body)
		without, proof, ok := strings.Cut(final, ",p=")
		if !ok {
			return
		}
		s.login.SCRAM.ClientFinalWithoutProof = without
		s.login.SCRAM.Proof, _ = base64.StdEncoding.DecodeString(proof)
		s.record()
	case authCleartext:
		pw := strings.TrimRight(string(body), "\x00")
		s.login.Cleartext = &pw
		s.record()
	case authMD5:
		if s.login.MD5 != nil {
			s.login.MD5.Value = strings.TrimRight(string(body), "\x00")
			s.record()
		}
	}
}

// readStartup reads an untyped startup-phase message, length included.
func readStartup(r io.Reader) ([]byte, error) {
	head := make([]byte, lengthBytes)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(head))
	if n < 2*lengthBytes || n > maxMessage {
		return nil, errors.New("bad startup length")
	}
	msg := make([]byte, n)
	copy(msg, head)
	if _, err := io.ReadFull(r, msg[lengthBytes:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// startupUser is the user parameter of a startup message.
func startupUser(msg []byte) string {
	params := bytes.Split(msg[2*lengthBytes:], []byte{0})
	for i := 0; i+1 < len(params); i += 2 {
		if string(params[i]) == "user" {
			return string(params[i+1])
		}
	}
	return ""
}

func readMessage(r io.Reader) (byte, []byte, error) {
	head := make([]byte, 1+lengthBytes)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(head[1:]))
	if n < lengthBytes || n > maxMessage {
		return 0, nil, errors.New("bad message length")
	}
	body := make([]byte, n-lengthBytes)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func writeMessage(w io.Writer, typ byte, body []byte) error {
	out := make([]byte, 1+lengthBytes, 1+lengthBytes+len(body))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:], uint32(len(body)+lengthBytes))
	_, err := w.Write(append(out, body...))
	return err
}

// testCertificate is a CA and a server certificate for host signed by it.
func testCertificate(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "connecttest CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certLife),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
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
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

// Connect opens a connection with url through the proxy: the host name is
// kept for TLS and verified against the proxy's roots, and every address is
// the proxy's. connecttest's Options.Dial for a pasted string naming Host.
func (p *Proxy) Connect(ctx context.Context, url string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = p.Dial
	for _, t := range append([]*tls.Config{cfg.TLSConfig}, fallbackTLS(cfg)...) {
		if t != nil {
			t.RootCAs = p.Roots
		}
	}
	return pgx.ConnectConfig(ctx, cfg)
}

func fallbackTLS(cfg *pgx.ConnConfig) []*tls.Config {
	out := make([]*tls.Config, 0, len(cfg.Fallbacks))
	for _, f := range cfg.Fallbacks {
		out = append(out, f.TLSConfig)
	}
	return out
}
