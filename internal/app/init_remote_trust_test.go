//go:build unix

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// caServer is a database for pinnedHost whose chain comes from a test CA no system
// trusts, and a dialer that reaches it.
type caServer struct {
	ca   *x509.Certificate
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newCAServer(t *testing.T) caServer {
	t.Helper()
	ca, leaf := trustprofiletest.Chain(t, pinnedHost)
	full := tls.Certificate{Certificate: append(leaf.Certificate, ca.Raw), PrivateKey: leaf.PrivateKey}
	return caServer{ca: ca, dial: trustprofiletest.Serve(t, full)}
}

// fetch reads s's chain as init does, with the handshake alone.
func (s caServer) fetch(ctx context.Context, h string, p int) ([]*x509.Certificate, error) {
	return trustpin.Fetch(ctx, s.dial, h, p)
}

const pinnedHost = "db.internal.example.com"

// pinnedAgent is an installed bot whose credential names pinnedHost with
// verify-full, and the engine's pin for that host to first's CA in the
// config's trust.d.
func pinnedAgent(t *testing.T, first caServer) string {
	t.Helper()
	cfg := tempConfig(t)
	dsn := agentDSN(t, "postgres://postgres@"+pinnedHost+":5432/postgres?sslmode=verify-full", guardmodel.DefaultPrefix, "bot", "0123abcd")
	seedCredential(t, noDB(t), cfg, "bot", dsn)
	clearSetup(t, cfg)
	_, _, err := trustdir.Pin(cfg, pinnedHost, first.ca, false)
	require.NoError(t, err)
	return cfg
}

// certRun runs basalt init --remote for the bot at cfg, its login failing
// on the certificate as a verify-full login to the pinned host does when
// the server presents another chain, and the chain read from server.
func certRun(t *testing.T, cfg string, server caServer) (setup.RemoteInitResult, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := noDB(t).io(&stdout, &stderr)
	c.AgentLogin = func(context.Context, string) (cli.AgentConn, error) {
		return nil, fmt.Errorf("cannot reach the database to check the agent's role (nothing changed): connect: %w", x509.UnknownAuthorityError{})
	}
	c.FetchChain = server.fetch
	res, err := setupcli.InitRemote(c, setupHost{}, takePathFlags(c, runInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
	return res, stderr.String(), err
}

// A pinned host that presents another chain top is not a refused
// credential: init makes an UPGRADE code from guard version 0, which names
// no agent (no password, no table: the role keeps its grants), carrying
// engine and the engine's pin as trustPin, marks the pending setup
// certificateChanged, and writes no new password. It pins nothing.
func TestInitRemoteChangedCertificate(t *testing.T) {
	t.Parallel()
	first, second := newCAServer(t), newCAServer(t)
	cfg := pinnedAgent(t, first)
	pinFile := filepath.Join(trustdir.Path(cfg), trustprofile.FileName(trustprofile.PinName(pinnedHost)))
	before, err := os.ReadFile(pinFile)
	require.NoError(t, err)

	res, stderr, err := certRun(t, cfg, second)
	require.NoError(t, err, stderr)
	p, err := setupcode.Decode(res.Code)
	require.NoError(t, err)
	require.Equal(t, setupcode.KindUpgrade, p.Kind)
	require.Nil(t, p.Agent, "never a new password, never a table")
	require.NotNil(t, p.Engine, "the engine collects the certificate with its key")
	require.Equal(t, trustprofile.DERSHA256(first.ca), p.TrustPin, "the engine's pin, for the page's Was:")
	require.Equal(t, 0, p.Guard.From)

	c, err := config.Load(cfg)
	require.NoError(t, err)
	s := c.Agents[0].Setup
	require.NotNil(t, s)
	require.True(t, s.CertificateChanged)
	require.False(t, s.ConnectOnly())
	cred := c.Agents[0].Store.CredentialFile
	require.NoFileExists(t, cred+setup.PendingSuffix, "no new password is written")
	after, err := os.ReadFile(pinFile)
	require.NoError(t, err)
	require.Equal(t, before, after, "init pins nothing")

	// The same change again prints the same code; a changed certificate's
	// code is never reused for another case.
	again, stderr, err := certRun(t, cfg, second)
	require.NoError(t, err, stderr)
	require.True(t, again.Reused)
	require.Equal(t, res.Code, again.Code)
}

// A certificate failure on a pinned host that still presents the pinned
// top is not a changed certificate: init fails as for an unreachable
// database, and never falls into the new-password branch.
func TestInitRemoteSameCertificateFails(t *testing.T) {
	t.Parallel()
	first := newCAServer(t)
	cfg := pinnedAgent(t, first)
	_, _, err := certRun(t, cfg, first)
	require.Error(t, err)
	c, lerr := config.Load(cfg)
	require.NoError(t, lerr)
	require.Nil(t, c.Agents[0].Setup)
	require.NoFileExists(t, c.Agents[0].Store.CredentialFile+setup.PendingSuffix)
}

// Every code with a target of the AGENT or UPGRADE kind carries the
// engine's pin for the target's host as trustPin.
func TestInitRemoteTrustPin(t *testing.T) {
	t.Parallel()
	first := newCAServer(t)
	cfg := pinnedAgent(t, first)
	r := remote(t, cfg, "--agent", "bot")
	require.Equal(t, setupcode.KindAgent, r.payload.Kind, "the login is refused: a new password")
	require.NotEmpty(t, r.payload.Agent.Verifier)
	require.Equal(t, trustprofile.DERSHA256(first.ca), r.payload.TrustPin)
	require.False(t, r.cfg.Agents[0].Setup.CertificateChanged)
}

// init --remote reads the chain of the credential's database before any
// probe. The agent runs it, so it never pins: it says that the person
// trusts the certificate on the connect page, and goes on, with or without
// an agent marker. It names no basalt trust command.
func TestInitRemotePins(t *testing.T) {
	t.Parallel()
	s := newCAServer(t)
	dsn := agentDSN(t, "postgres://postgres@"+pinnedHost+":5432/postgres?sslmode=require", guardmodel.DefaultPrefix, "bot", "0123abcd")
	for name, env := range map[string]map[string]string{"no marker": nil, "agent marker": {"CLAUDECODE": "1"}} {
		cfg := tempConfig(t)
		installedAgent(t, noDB(t), cfg, dsn)
		e := noDB(t)
		e.env = env
		e.noNetwork = false
		var stdout, stderr bytes.Buffer
		c := e.io(&stdout, &stderr)
		c.FetchChain = s.fetch
		code := runInit(c, setupHost{}, takePathFlags(c, runInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
		require.Equal(t, cli.ExitOK, code, "%s: %s", name, stderr.String())
		require.Contains(t, stderr.String(), "trusts it on the connect page", name)
		require.NotContains(t, stderr.String(), "basalt trust", name)
		require.NotContains(t, stderr.String(), "--trust-root", "the agent is not handed the flag")
		require.NoFileExists(t, filepath.Join(trustdir.Path(cfg), trustprofile.FileName(trustprofile.PinName(pinnedHost))), name)
		require.True(t, strings.Contains(stderr.String(), pinnedHost), name)
	}
}
