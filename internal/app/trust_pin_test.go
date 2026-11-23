//go:build unix

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
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

// verifyFullDSN is a connection string for host that verifies the
// certificate and the host name.
func verifyFullDSN(host string) string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword("u", "pw"), Host: host + ":5432", Path: "/postgres", RawQuery: "sslmode=verify-full"}
	return u.String()
}

// login logs in to host through s with sslmode=verify-full and the
// profiles of cfg: the server's refusal of the password proves the
// certificate verified.
func login(t *testing.T, s pinServer, cfg, host string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgdial.Login(ctx, verifyFullDSN(host), trustdir.Set(cfg), "127.0.0.1", s.dial, nil)
}

// init --remote reads the chain before it logs in with a credential it
// already holds: nothing but the handshake reaches the server first.
func TestInitRemotePinsBeforeLogin(t *testing.T) {
	t.Parallel()
	const host = "db.internal.example.com"
	s := newPinServer(t, host)
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, agentDSN(t, "postgres://postgres@"+host+":5432/postgres?sslmode=require", guardmodel.DefaultPrefix, "bot", "0123abcd"))
	var events []string
	var out, errb bytes.Buffer
	c := newIO(context.Background(), cli.Stdio{In: strings.NewReader(""), Out: &out, Err: &errb}, func(string) string { return "" })
	c.Probe, c.Host = noNetworkProbe, systemSocketHost(t)
	c.AgentLogin = func(ctx context.Context, dsn string) (cli.AgentConn, error) {
		events = append(events, "login")
		return nil, handoff.ErrLoginRefused
	}
	c.FetchChain = func(ctx context.Context, h string, p int) ([]*x509.Certificate, error) {
		events = append(events, "handshake")
		return trustpin.Fetch(ctx, s.dial, h, p)
	}
	code := runInit(c, SetupHost{}, takePathFlags(c, runInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
	require.Equal(t, cli.ExitOK, code, errb.String())
	require.NotEmpty(t, events)
	require.Equal(t, "handshake", events[0], "the handshake comes before any login: %v", events)
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

func trustConfig(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))
	return filepath.Join(dir, "engine.json")
}

// rootChangedVia is rootChangedOn with the real shell host.
func rootChangedVia(ctx context.Context, dsn string, err error, dial trustpin.Dial) error {
	return cli.RootChangedOn(ctx, Shell{}, dsn, err, dial)
}
