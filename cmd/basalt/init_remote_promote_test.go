//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

// loggedInConn is an agent connection the tests' recordedHost answers for:
// nothing is queried through it.
type loggedInConn struct{ pgquerier.Querier }

func (loggedInConn) Close(context.Context) error { return nil }

// recordedHost is app.SetupHost with the guard's answers given: the
// database has the latest guard, and the pending setup is recorded or not.
type recordedHost struct {
	app.SetupHost
	recorded bool
}

func (h recordedHost) GuardAgentVersion(context.Context, pgquerier.Querier) (int, error) {
	return h.GuardLatestVersion(), nil
}

func (h recordedHost) GuardSetupRecorded(context.Context, pgquerier.Querier, uuid.UUID) (bool, error) {
	return h.recorded, nil
}

// pendingAgent is an installed bot whose login was refused on the last
// run: its credential file, the .pending one init wrote, and the pending
// setup in the config.
func pendingAgent(t *testing.T) (cfg, credFile string) {
	t.Helper()
	cfg = withState(t, tempConfig(t))
	installedAgent(t, noDB(t), cfg, agentDSN(t, "postgres://postgres@db.example.com:5432/app", guardmodel.DefaultPrefix, "bot", botPassword))
	r := remote(t, cfg, "--agent", "bot")
	require.NotNil(t, r.cfg.Agents[0].Setup)
	require.FileExists(t, r.credFile+setup.PendingSuffix)
	return cfg, r.credFile
}

// runRemote runs basalt init --remote for the bot at cfg on host h, every
// agent login answered by login.
func runRemote(t *testing.T, h setupcli.Host, cfg string, login func(context.Context, string) (cli.AgentConn, error)) (setup.RemoteInitResult, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	e := noDB(t)
	e.login = login
	c := e.io(&stdout, &stderr)
	return setupcli.InitRemote(c, h, takePathFlags(c, app.RunInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
}

// A .pending credential that logs in is moved over the credential file
// only once the pending setup is recorded, as the engine moves it: before
// that, init leaves both files as they are and prints the pending code
// again.
func TestInitRemotePromotesPendingOnlyOnceTheSetupIsRecorded(t *testing.T) {
	t.Parallel()
	loggedIn := func(context.Context, string) (cli.AgentConn, error) { return loggedInConn{}, nil }

	cfg, credFile := pendingAgent(t)
	cred, err := os.ReadFile(credFile)
	require.NoError(t, err)
	pending, err := os.ReadFile(credFile + setup.PendingSuffix)
	require.NoError(t, err)
	res, err := runRemote(t, recordedHost{recorded: false}, cfg, loggedIn)
	require.NoError(t, err)
	require.True(t, res.Reused, "the pending code is printed again")
	got, err := os.ReadFile(credFile)
	require.NoError(t, err)
	require.Equal(t, string(cred), string(got), "the credential file is unchanged")
	got, err = os.ReadFile(credFile + setup.PendingSuffix)
	require.NoError(t, err)
	require.Equal(t, string(pending), string(got), ".pending stays")

	_, err = runRemote(t, recordedHost{recorded: true}, cfg, loggedIn)
	require.NoError(t, err)
	require.NoFileExists(t, credFile+setup.PendingSuffix)
	got, err = os.ReadFile(credFile)
	require.NoError(t, err)
	require.Equal(t, string(pending), string(got), "the recorded setup's .pending is the credential")
}

// The kept credential is used only for the database and the role of the
// newest one (.pending): one naming another role is not tried.
func TestInitRemoteIgnoresACredentialForAnotherRole(t *testing.T) {
	t.Parallel()
	cfg, credFile := pendingAgent(t)
	require.NoError(t, config.WriteFile(credFile,
		[]byte(agentDSN(t, "postgres://postgres@db.example.com:5432/app", "other", "bot", botPassword)+"\n")))
	var dialed []string
	_, err := runRemote(t, app.SetupHost{}, cfg, func(_ context.Context, dsn string) (cli.AgentConn, error) {
		dialed = append(dialed, dsn)
		return nil, handoff.ErrLoginRefused
	})
	require.NoError(t, err)
	pending, err := os.ReadFile(credFile + setup.PendingSuffix)
	require.NoError(t, err)
	require.Equal(t, []string{string(bytes.TrimSpace(pending))}, dialed, "only .pending logs in")
}

// A lock another run holds keeps init --remote's message, and is still
// config.ErrLocked, by path and through the directory root opens.
func TestInitRemoteLockedKeepsItsMessageAndErrLocked(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	path := filepath.Join(dir, "bot.url"+setup.LockSuffix)
	unlock, err := config.LockFile(path)
	require.NoError(t, err)
	defer unlock()
	root, err := app.SetupHost{}.OpenRootCredFiles(dir, os.Geteuid())
	require.NoError(t, err)
	defer root.Close()
	want := fmt.Sprintf("another basalt init --remote is running for this agent, or the engine is finishing its setup (%s is locked); run it again in a moment", path)
	for name, files := range map[string]setup.CredFiles{"path": app.PathCredFiles{}, "root": root} {
		_, err := files.Lock(path)
		require.ErrorIs(t, err, config.ErrLocked, name)
		require.EqualError(t, err, want, name)
	}
}

// A .pending login that fails on a pinned host presenting another chain top
// is a changed certificate, not an error: init makes the certificateChanged
// code and leaves .pending as it is.
func TestInitRemoteChangedCertificateOnThePendingLogin(t *testing.T) {
	t.Parallel()
	first, second := newCAServer(t), newCAServer(t)
	cfg := pinnedAgent(t, first)
	c, err := config.Load(cfg)
	require.NoError(t, err)
	credFile := c.Agents[0].Store.CredentialFile
	pending := agentDSN(t, "postgres://postgres@"+pinnedHost+":5432/postgres?sslmode=verify-full", guardmodel.DefaultPrefix, "bot", "4567cdef")
	require.NoError(t, config.WriteFile(credFile+setup.PendingSuffix, []byte(pending+"\n")))

	var stdout, stderr bytes.Buffer
	io := noDB(t).io(&stdout, &stderr)
	var dialed []string
	io.AgentLogin = func(_ context.Context, dsn string) (cli.AgentConn, error) {
		dialed = append(dialed, dsn)
		return nil, fmt.Errorf("cannot reach the database to check the agent's role (nothing changed): connect: %w", x509.UnknownAuthorityError{})
	}
	io.FetchChain = second.fetch
	res, err := setupcli.InitRemote(io, app.SetupHost{}, takePathFlags(io, app.RunInit, []string{"--remote", "--config", cfg, "--agent", "bot"}))
	require.NoError(t, err, stderr.String())
	require.Equal(t, []string{pending}, dialed, "the .pending login decides")
	p, err := setupcode.Decode(res.Code)
	require.NoError(t, err)
	require.Equal(t, setupcode.KindUpgrade, p.Kind)
	c, err = config.Load(cfg)
	require.NoError(t, err)
	require.True(t, c.Agents[0].Setup.CertificateChanged)
	got, err := os.ReadFile(credFile + setup.PendingSuffix)
	require.NoError(t, err)
	require.Equal(t, pending+"\n", string(got), ".pending is left as it is")
}
