//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// pinServer is a database for host whose chain (leaf and CA) comes from a
// test CA no system trusts, and a dialer that reaches it.
type pinServer struct {
	ca   *x509.Certificate
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newPinServer(t *testing.T, certHost string) pinServer {
	t.Helper()
	ca, leaf := trustprofiletest.Chain(t, certHost)
	full := tls.Certificate{Certificate: append(leaf.Certificate, ca.Raw), PrivateKey: leaf.PrivateKey}
	return pinServer{ca: ca, dial: trustprofiletest.Serve(t, full)}
}

// login logs in to host through s with sslmode=verify-full and the
// profiles of cfg: the server's refusal of the password proves the
// certificate verified.
func login(t *testing.T, s pinServer, cfg, host string) error {
	t.Helper()
	cc, err := pgdial.ConnConfigTrusting("postgres://u:pw@"+host+":5432/postgres?sslmode=verify-full", trustdir.Set(cfg))
	require.NoError(t, err)
	cc.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cc.DialFunc = s.dial
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

// init --remote reads the chain of the credential's database before any
// probe. The agent runs it, so it never pins: it says the person's command
// and goes on, with or without an agent marker.
func TestInitRemotePins(t *testing.T) {
	t.Parallel()
	const host = "db.internal.example.com"
	s := newPinServer(t, host)
	dsn := agentDSN(t, "postgres://postgres@"+host+":5432/postgres?sslmode=require", guard.DefaultPrefix, "bot", "0123abcd")
	for name, env := range map[string]map[string]string{"no marker": nil, "agent marker": {"CLAUDECODE": "1"}} {
		cfg := tempConfig(t)
		installedAgent(t, noDB(t), cfg, dsn)
		e := noDB(t)
		e.env = env
		e.noNetwork = false
		var stdout, stderr bytes.Buffer
		c := e.io(&stdout, &stderr)
		c.fetchChain = func(ctx context.Context, h string, p int) ([]*x509.Certificate, error) {
			return trustpin.Fetch(ctx, s.dial, h, p)
		}
		code := runInit(c, takePathFlags(c, runInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
		require.Equal(t, exitOK, code, "%s: %s", name, stderr.String())
		require.Contains(t, stderr.String(), "an agent never pins one", name)
		require.Contains(t, stderr.String(), "basalt trust pin --host "+host+" --port 5432", name)
		require.NotContains(t, stderr.String(), "--trust-root", "the agent is not handed the flag")
		require.NoFileExists(t, filepath.Join(trustdir.Path(cfg), trustprofile.FileName(trustprofile.PinName(host))), name)
	}
}

// init --remote reads the chain before it logs in with a credential it
// already holds: nothing but the handshake reaches the server first.
func TestInitRemotePinsBeforeLogin(t *testing.T) {
	t.Parallel()
	const host = "db.internal.example.com"
	s := newPinServer(t, host)
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, agentDSN(t, "postgres://postgres@"+host+":5432/postgres?sslmode=require", guard.DefaultPrefix, "bot", "0123abcd"))
	var events []string
	var out, errb bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &out, err: &errb}, func(string) string { return "" })
	c.probe, c.host = noNetworkProbe, systemSocketHost(t)
	c.agentLogin = func(ctx context.Context, dsn string) (agentConn, error) {
		events = append(events, "login")
		return nil, errLoginRefused
	}
	c.fetchChain = func(ctx context.Context, h string, p int) ([]*x509.Certificate, error) {
		events = append(events, "handshake")
		return trustpin.Fetch(ctx, s.dial, h, p)
	}
	code := runInit(c, takePathFlags(c, runInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
	require.Equal(t, exitOK, code, errb.String())
	require.NotEmpty(t, events)
	require.Equal(t, "handshake", events[0], "the handshake comes before any login: %v", events)
}

// A connection string that names its own roots gets no pin offer: the
// pin would not apply to it.
func TestInitPinSkipsOwnRoots(t *testing.T) {
	t.Parallel()
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
	fetched := false
	c.fetchChain = func(context.Context, string, int) ([]*x509.Certificate, error) {
		fetched = true
		return nil, errors.New("not reached")
	}
	file := filepath.Join(t.TempDir(), "ca.pem")
	ca, _ := trustprofiletest.Chain(t, "x")
	require.NoError(t, os.WriteFile(file, trustprofiletest.PEM(ca), 0o600))
	_, ok, err := c.initPin("postgres://u@db.internal.example.com/postgres?sslmode=verify-full&sslrootcert="+file, "", trustConfig(t), false)
	require.NoError(t, err)
	require.False(t, ok)
	_, _, err = c.initPin("postgres://u@db.internal.example.com/postgres?sslmode=disable", "abc", trustConfig(t), false)
	require.ErrorIs(t, err, errUsage, "--trust-root with no TLS is a usage error")
	require.False(t, fetched)
}

func TestTargetOf(t *testing.T) {
	t.Parallel()
	for dsn, want := range map[string]pinTarget{
		"postgres://u@DB.Example.com/postgres":       {"db.example.com", 5432},
		"postgres://u@db.example.com:6543/postgres":  {"db.example.com", 6543},
		"postgres://u@[2001:db8::1]:5433/postgres":   {"2001:db8::1", 5433},
		"postgres://u@a.example.com,b.example.com/x": {"a.example.com", 5432},
	} {
		got, ok := targetOf(dsn)
		require.True(t, ok, dsn)
		require.Equal(t, want, got, dsn)
	}
	for _, dsn := range []string{"postgres:///postgres?host=/var/run/postgresql", "postgres:///postgres"} {
		_, ok := targetOf(dsn)
		require.False(t, ok, dsn)
	}
}

// A connection to a pinned host that presents another root says
// TRUST_ROOT_CHANGED with both fingerprints; the pinned root says nothing.
// Not parallel: it sets this process's trust profiles.
func TestRootChanged(t *testing.T) {
	const host = "db.internal.example.com"
	first, second := newPinServer(t, host), newPinServer(t, host)
	cfg := trustConfig(t)
	_, _, err := trustdir.Pin(cfg, host, first.ca, false)
	require.NoError(t, err)
	pgdial.SetTrust(trustdir.Source(cfg))
	t.Cleanup(func() { pgdial.SetTrust(nil) })
	err = login(t, second, cfg, host)
	require.True(t, trustprofile.CertificateNotVerified(err))
	// rootChanged dials the host itself: stand the second server in for it.
	got := rootChangedVia(context.Background(), "postgres://u:pw@"+host+":5432/postgres?sslmode=verify-full", err, second.dial)
	require.Error(t, got)
	require.Contains(t, got.Error(), "TRUST_ROOT_CHANGED")
	require.Contains(t, got.Error(), trustprofile.Fingerprint(second.ca))
	require.Contains(t, got.Error(), trustprofile.Fingerprint(first.ca))
	require.Contains(t, got.Error(), "run basalt init")
	require.NotContains(t, got.Error(), "basalt trust")
	require.NoError(t, rootChangedVia(context.Background(), "postgres://u:pw@"+host+":5432/postgres?sslmode=verify-full", err, first.dial))
}

// A certificate from an authority this machine trusts that fails on the
// name is never pinned, with or without --trust-root: the fix is the host
// name. Not parallel: it swaps the system's store.
func TestInitPinRefusesPublicAuthorities(t *testing.T) {
	const ip = "203.0.113.7"
	s := newPinServer(t, "other.example.com")
	store := x509.NewCertPool()
	store.AddCert(s.ca)
	defer trustprofile.SetSystemRootsForTest(store)()
	cfg := trustConfig(t)
	var errb bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &errb}, func(string) string { return "" })
	c.fetchChain = func(ctx context.Context, host string, port int) ([]*x509.Certificate, error) {
		return trustpin.Fetch(ctx, s.dial, host, port)
	}
	dsn := "postgres://u@" + ip + ":5432/postgres?sslmode=verify-full"
	_, ok, err := c.initPin(dsn, trustprofile.DERSHA256(s.ca), cfg, false)
	require.ErrorIs(t, err, errUsage)
	require.Contains(t, err.Error(), "failed on the name")
	require.False(t, ok)
	_, ok, err = c.initPin(dsn, "", cfg, false)
	require.NoError(t, err)
	require.False(t, ok)
	require.Contains(t, errb.String(), "failed on the name")
	require.Nil(t, trustdir.Set(cfg).For(ip))
}

func trustConfig(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))
	return filepath.Join(dir, "engine.json")
}
