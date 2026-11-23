package setup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"
)

// fakeProbe answers a probe by its sslmode and channel binding: answers maps
// "<sslmode>/<channel_binding>" to the error the server gives; any other
// probe fails in the client, as without channel binding or TLS.
func fakeProbe(t *testing.T, answers map[string]error, seen *[]string) func(context.Context, string) error {
	t.Helper()
	return func(_ context.Context, dsn string) error {
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		q := u.Query()
		key := q.Get(ParamSSLMode) + "/" + q.Get(ParamChannelBinding)
		*seen = append(*seen, key)
		if err := answers[key]; err != nil {
			return err
		}
		return errors.New("channel binding required but server does not support SCRAM-SHA-256-PLUS")
	}
}

var (
	errRefusedPassword = &pgconn.PgError{Code: sqlstateInvalidPassword, Message: "password authentication failed"}
	errNoTenant        = &pgconn.PgError{Code: SQLStateInternal, Message: SupavisorNoTenant}
	errTooMany         = &pgconn.PgError{Code: "53300", Message: "too many connections"}
)

func TestHardenedCredential(t *testing.T) {
	t.Parallel()
	const base = "postgres://basalt_agent_bot:pw@db.example.com:5432/postgres"
	const pooler = "postgres://basalt_agent_bot.abcdefghijklmnopqrst:pw@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
	for _, tc := range []struct {
		name, dsn string
		answers   map[string]error
		want      string
		probes    []string
		line      string
	}{
		{
			name: "verify-full with channel binding where both work", dsn: base,
			answers: map[string]error{"verify-full/require": errRefusedPassword},
			want:    base + "?channel_binding=require&sslmode=verify-full",
			probes:  []string{"verify-full/require"},
			line:    "database identity verified, channel binding on",
		},
		{
			name: "verify-full without channel binding when the certificate verifies (PgBouncer)", dsn: base + "?sslmode=prefer",
			answers: map[string]error{"verify-full/": errRefusedPassword, "require/require": errRefusedPassword},
			want:    base + "?sslmode=verify-full",
			probes:  []string{"verify-full/require", "verify-full/"},
			line:    "database identity verified (the server offers no channel binding)",
		},
		{
			name: "Supabase pooler: verify-full on the pooler, which answers before SASL", dsn: pooler,
			answers: map[string]error{"verify-full/require": errNoTenant, "verify-full/": errNoTenant},
			want:    pooler + "?sslmode=verify-full",
			probes:  []string{"verify-full/require", "verify-full/"},
			line:    "database identity verified (channel binding not available through the Supabase pooler)",
		},
		{
			name: "Supabase pooler whose certificate does not verify: unchanged", dsn: pooler + "?sslmode=require",
			want:   pooler + "?sslmode=require",
			probes: []string{"verify-full/require", "verify-full/", "require/require"},
			line:   "not protected further",
		},
		{
			name: "a server error that is no login refusal proves nothing", dsn: base,
			answers: map[string]error{"verify-full/": errTooMany},
			want:    base,
			probes:  []string{"verify-full/require", "verify-full/", "require/require"},
			line:    "not protected further",
		},
		{
			name: "else require with channel binding", dsn: base + "?sslmode=prefer", answers: map[string]error{"require/require": errRefusedPassword},
			want:   base + "?channel_binding=require&sslmode=require",
			probes: []string{"verify-full/require", "verify-full/", "require/require"},
			line:   "encrypted with channel binding, but the database's certificate did not verify",
		},
		{
			name: "require with channel binding needs a refused password, not a refused role", dsn: base,
			answers: map[string]error{"require/require": errNoTenant},
			want:    base,
			probes:  []string{"verify-full/require", "verify-full/", "require/require"},
			line:    "not protected further",
		},
		{
			name: "verify-ca is kept, never weakened to require", dsn: base + "?sslmode=verify-ca&sslrootcert=%2Fca.pem",
			answers: map[string]error{"verify-ca/require": errRefusedPassword},
			want:    base + "?channel_binding=require&sslmode=verify-ca&sslrootcert=%2Fca.pem",
			probes:  []string{"verify-full/require", "verify-full/", "verify-ca/require"},
			line:    "checked against its CA (host name not checked), channel binding on",
		},
		{
			name: "verify-ca moves to verify-full when the host name verifies", dsn: base + "?sslmode=verify-ca&sslrootcert=%2Fca.pem",
			answers: map[string]error{"verify-full/": errRefusedPassword},
			want:    base + "?sslmode=verify-full&sslrootcert=%2Fca.pem",
			probes:  []string{"verify-full/require", "verify-full/"},
			line:    "database identity verified (the server offers no channel binding)",
		},
		{
			name: "no channel binding and no verified certificate: unchanged", dsn: base + "?sslmode=require",
			want:   base + "?sslmode=require",
			probes: []string{"verify-full/require", "verify-full/", "require/require"},
			line:   "not protected further: TLS with a verified certificate or channel binding could not be confirmed",
		},
		{
			name: "verify-full is never weakened", dsn: base + "?sslmode=verify-full", answers: map[string]error{"require/require": errRefusedPassword},
			want:   base + "?sslmode=verify-full",
			probes: []string{"verify-full/require"},
			line:   "database identity verified (sslmode=verify-full as given; channel binding could not be confirmed)",
		},
		{
			name: "verify-full kept, channel binding added", dsn: base + "?sslmode=verify-full", answers: map[string]error{"verify-full/require": errRefusedPassword},
			want:   base + "?channel_binding=require&sslmode=verify-full",
			probes: []string{"verify-full/require"},
			line:   "database identity verified, channel binding on",
		},
		{name: "sslmode=disable: unchanged, no probe", dsn: base + "?sslmode=disable", want: base + "?sslmode=disable", line: "not protected further: sslmode=disable"},
		{
			name: "a Unix socket: unchanged, no probe", dsn: "postgres://basalt_agent_bot:pw@/postgres?host=%2Fvar%2Frun%2Fpostgresql",
			want: "postgres://basalt_agent_bot:pw@/postgres?host=%2Fvar%2Frun%2Fpostgresql", line: "not protected further: a Unix socket",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var seen []string
			got, p := HardenedCredential(context.Background(), fakeProbe(t, tc.answers, &seen), pgErrors{}, tc.dsn)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.probes, seen)
			line := p.Line()
			require.Regexp(t, `^basalt: connection [^\n]+\n$`, line, "one line")
			require.Contains(t, line, tc.line)
			require.NotContains(t, line, "pw@", "the line never carries the credential")
		})
	}
}

func TestHardenedCredentialStopsAtAnUnreachableDatabase(t *testing.T) {
	t.Parallel()
	dsn := "postgres://basalt_agent_bot:pw@db.example.com/postgres"
	for _, err := range []error{context.DeadlineExceeded, &net.OpError{Op: "dial", Err: errors.New("connection refused")}} {
		probes := 0
		got, p := HardenedCredential(context.Background(), func(context.Context, string) error { probes++; return err }, pgErrors{}, dsn)
		require.Equal(t, dsn, got)
		require.Equal(t, 1, probes, "one probe that cannot reach the server is enough")
		require.Contains(t, p.Line(), "could not be reached")
	}
}

// One address that cannot be dialed does not end the probing when another
// address of the host was reached: pgx joins one error per address.
func TestHardenedCredentialProbesOnWhenOneAddressIsReached(t *testing.T) {
	t.Parallel()
	refused := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	require.True(t, unreachable(fmt.Errorf("connect: %w", errors.Join(refused, context.DeadlineExceeded))))
	require.False(t, unreachable(fmt.Errorf("connect: %w", errors.Join(errors.New("tls: failed to verify certificate"), refused))))

	ca := newTestCA(t, "db.example.test")
	port := startFakePostgres(t, ca, postgresPlus)
	closed, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.2:0")
	if err != nil {
		closed, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	}
	require.NoError(t, err)
	deadPort := closed.Addr().(*net.TCPAddr).Port
	require.NoError(t, closed.Close())
	// A multi-host URL: the live server (untrusted certificate, channel
	// binding) and a closed port.
	dsn := "postgres://basalt_agent_bot:pw@db.example.test:" + strconv.Itoa(port) + ",db.example.test:" + strconv.Itoa(deadPort) + "/postgres?sslmode=prefer"
	got, p := HardenedCredential(context.Background(), loopbackProbe, pgErrors{}, dsn)
	u, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, sslRequire, u.Query().Get(ParamSSLMode), got)
	require.Equal(t, bindingRequire, u.Query().Get(ParamChannelBinding), got)
	require.Contains(t, p.Line(), "encrypted with channel binding")
}

// fakeServer is what a TLS Postgres front answers after the startup message.
type fakeServer int

const (
	// postgresPlus offers SCRAM-SHA-256-PLUS and refuses the password.
	postgresPlus fakeServer = iota
	// pgbouncer offers SCRAM-SHA-256 only and refuses the password.
	pgbouncer
	// supavisor does not know the role and answers before any SASL message.
	supavisor
)

// testCA is a CA's certificate file and a server certificate it signed.
type testCA struct {
	file string
	cert tls.Certificate
}

func newTestCA(t *testing.T, hosts ...string) testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "basalt test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))
	return testCA{file: file, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

// startFakePostgres serves kind on a loopback port with ca's server
// certificate and returns the port.
func startFakePostgres(t *testing.T, ca testCA, kind fakeServer) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFake(conn, ca, kind)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveFake(conn net.Conn, ca testCA, kind fakeServer) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	b := pgproto3.NewBackend(conn, conn)
	msg, err := b.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := msg.(*pgproto3.SSLRequest); !ok {
		return
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}
	tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{ca.cert}, MinVersion: tls.VersionTLS12})
	defer tc.Close()
	b = pgproto3.NewBackend(tc, tc)
	if _, err := b.ReceiveStartupMessage(); err != nil {
		return
	}
	switch kind {
	case supavisor:
		b.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: SQLStateInternal, Message: SupavisorNoTenant})
		_ = b.Flush()
		return
	case postgresPlus:
		b.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}})
	case pgbouncer:
		b.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	}
	if b.Flush() != nil {
		return
	}
	b.SetAuthType(pgproto3.AuthTypeSASL)
	if _, err := b.Receive(); err != nil {
		return // the client gave up: it requires channel binding
	}
	b.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: sqlstateInvalidPassword, Message: "password authentication failed"})
	_ = b.Flush()
}

// loopbackProbe is probeLogin's login through pgx, with every host name
// resolved to 127.0.0.1: the TLS checks still use the name in the URL.
func loopbackProbe(ctx context.Context, dsn string) error {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return err
	}
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	return conn.Close(ctx)
}

// TestHardenedCredentialOverTLS runs the probes with pgx against TLS
// servers on loopback: a certificate from a test CA (trusted through
// sslrootcert, or not), with or without channel binding.
func TestHardenedCredentialOverTLS(t *testing.T) {
	t.Parallel()
	const poolerHost = "aws-0-eu-central-1.pooler.supabase.com"
	ca := newTestCA(t, "db.example.test", poolerHost)
	rootcert := "sslrootcert=" + url.QueryEscape(ca.file)
	for _, tc := range []struct {
		name, host, user, params string
		kind                     fakeServer
		mode, binding, line      string
	}{
		{
			name: "Postgres with channel binding and a verified certificate", host: "db.example.test", params: rootcert,
			kind: postgresPlus, mode: SSLVerifyFull, binding: bindingRequire, line: "database identity verified, channel binding on",
		},
		{
			name: "PgBouncer: verified certificate, no channel binding", host: "db.example.test", params: rootcert,
			kind: pgbouncer, mode: SSLVerifyFull, line: "(the server offers no channel binding)",
		},
		{
			name: "Supabase pooler: verified certificate, answers before SASL", host: poolerHost, user: ".abcdefghijklmnopqrst", params: rootcert,
			kind: supavisor, mode: SSLVerifyFull, line: "(channel binding not available through the Supabase pooler)",
		},
		{
			name: "channel binding, certificate not trusted", host: "db.example.test", params: "sslmode=prefer",
			kind: postgresPlus, mode: sslRequire, binding: bindingRequire, line: "certificate did not verify",
		},
		{
			name: "certificate for another host name", host: "other.example.test", params: rootcert,
			kind: pgbouncer, line: "not protected further",
		},
		{
			name: "Supabase pooler, certificate not trusted", host: poolerHost, user: ".abcdefghijklmnopqrst", params: "sslmode=require",
			kind: supavisor, line: "not protected further",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			port := startFakePostgres(t, ca, tc.kind)
			dsn := "postgres://basalt_agent_bot" + tc.user + ":pw@" + tc.host + ":" + strconv.Itoa(port) + "/postgres?" + tc.params
			got, p := HardenedCredential(context.Background(), loopbackProbe, pgErrors{}, dsn)
			require.Contains(t, p.Line(), tc.line)
			if tc.mode == "" {
				require.Equal(t, dsn, got, "unchanged")
				return
			}
			u, err := url.Parse(got)
			require.NoError(t, err)
			require.Equal(t, tc.mode, u.Query().Get(ParamSSLMode), got)
			require.Equal(t, tc.binding, u.Query().Get(ParamChannelBinding), got)
			// The credential written gets as far as the probe did.
			var pg *pgconn.PgError
			require.ErrorAs(t, loopbackProbe(context.Background(), got), &pg)
		})
	}
}

// pgErrors is DBErrors on pgx's server errors, as the command table's glue
// fills it.
type pgErrors struct{}

func (pgErrors) ServerMessage(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", false
	}
	return pg.Message, true
}
