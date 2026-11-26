//go:build unix

package handoff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// recordingPassword records the passwords the pool is switched to.
type recordingPassword struct{ set []string }

func (p *recordingPassword) Set(pw string) { p.set = append(p.set, pw) }

// pathFinishFiles are the finisher's files by path, as the engine's
// non-root adapter reaches them.
type pathFinishFiles struct{ configPath, credFile string }

func (p pathFinishFiles) ReadPending(limit int) (string, os.FileInfo, error) {
	path := p.credFile + config.PendingSuffix
	if _, err := os.Lstat(path); err != nil {
		return "", nil, err
	}
	return config.ReadOwnCredentialLimit(path, limit)
}

func (p pathFinishFiles) Promote(pending os.FileInfo) error {
	path := p.credFile + config.PendingSuffix
	if err := config.SameCredentialFile(path, pending); err != nil {
		return err
	}
	return os.Rename(path, p.credFile)
}

func (p pathFinishFiles) Lock() (func(), error) {
	return config.LockFile(p.credFile + config.LockSuffix)
}

func (p pathFinishFiles) ClearSetup(agent, id string) (bool, error) {
	return config.ClearSetup(p.configPath, agent, id)
}

// parseURL reads a postgres:// credential's target and password.
func parseURL(dsn string) (LoginTarget, string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return LoginTarget{}, "", err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return LoginTarget{}, "", err
	}
	pw, _ := u.User.Password()
	return LoginTarget{Host: u.Hostname(), Port: uint16(port), Database: strings.TrimPrefix(u.Path, "/"), User: u.User.Username()}, pw, nil
}

// fakeLogin is an agent login that finds the setup recorded or not.
type fakeLogin struct{ recorded bool }

func (l fakeLogin) SetupRecorded(context.Context, uuid.UUID) (bool, error) { return l.recorded, nil }
func (fakeLogin) Close(context.Context) error                              { return nil }

// fileFinisher is a Finisher over files in a temporary directory, with a
// pending setup for agent bot in engine.json.
func fileFinisher(t *testing.T, id uuid.UUID) (*Finisher, *recordingPassword, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfgPath, credFile := filepath.Join(dir, "engine.json"), filepath.Join(dir, "bot.url")
	require.NoError(t, config.WriteFile(credFile, []byte("postgres://bt_agent_bot:old@db:5432/app\n")))
	_, err := config.UpsertAgentVault(cfgPath, config.Settings{SocketDir: "/run/basalt"}, config.Agent{
		Name: "bot", OSUser: "bot", Store: config.PostgresStore(credFile), Setup: &config.Setup{
			SetupID: id.String(), Kind: guardmodel.SetupAgent,
			GuardVersion: 1, ExpiresAt: "2026-11-13T10:00:00Z", Code: "basalt-setup.1.abc.def", Fingerprint: "a1b2",
		},
	})
	require.NoError(t, err)
	pw, logs := &recordingPassword{}, &bytes.Buffer{}
	f := &Finisher{
		ConfigPath: cfgPath, Agent: "bot", CredFile: credFile,
		Files: pathFinishFiles{configPath: cfgPath, credFile: credFile},
		Login: LoginTarget{Host: "db", Port: 5432, Database: "app", User: "bt_agent_bot"}, Parse: parseURL,
		Password: pw, Reset: func() {},
		Connect: func(context.Context, string) (AgentLogin, error) {
			t.Fatal("no login expected")
			return nil, errors.New("no login expected")
		},
		Errors: pgErrors{},
		Log:    slog.New(slog.NewTextHandler(logs, nil)),
	}
	return f, pw, logs
}

// pgErrors is setup.DBErrors on pgx's server errors, as internal/app gives.
type pgErrors struct{}

func (pgErrors) ServerMessage(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", false
	}
	return pg.Message, true
}

// A .pending credential for another database is logged once per setup, not
// on every call.
func TestAPendingCredentialForAnotherDatabaseIsLoggedOncePerSetup(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, _, logs := fileFinisher(t, id)
	require.NoError(t, config.WriteFile(f.CredFile+config.PendingSuffix, []byte("postgres://bt_agent_bot:new@other:5432/app\n")))
	for range 3 {
		recorded, has, err := f.PendingRecorded(context.Background(), id)
		require.NoError(t, err)
		require.False(t, recorded)
		require.False(t, has)
	}
	require.Equal(t, 1, strings.Count(logs.String(), "another database"))
	_, _, err := f.PendingRecorded(context.Background(), uuid.Must(uuid.NewV7()))
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(logs.String(), "another database"), "a new setup is logged again")
}

// Two calls finishing the same setup at once: the first promotes, the
// second finds it already done instead of failing.
func TestASecondFinishOfAPromotedSetupIsDone(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, pw, _ := fileFinisher(t, id)
	pending := f.CredFile + config.PendingSuffix
	require.NoError(t, config.WriteFile(pending, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	fi, err := os.Lstat(pending)
	require.NoError(t, err)
	f.pending = &pendingCredential{setupID: id.String(), file: fi, password: "new"}

	require.NoError(t, f.Finish(context.Background(), id.String(), true))
	require.NoError(t, f.Finish(context.Background(), id.String(), true), "already promoted: done")
	require.Equal(t, []string{"new"}, pw.set, "promoted once")
	got, err := os.ReadFile(f.CredFile)
	require.NoError(t, err)
	require.Contains(t, string(got), ":new@")

	// Another setup with nothing promoted for it is still an error.
	require.Error(t, f.Finish(context.Background(), uuid.Must(uuid.NewV7()).String(), true))
}

// The .pending file replaced after it logged in is never moved.
func TestAReplacedPendingCredentialIsNotPromoted(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, pw, _ := fileFinisher(t, id)
	pending := f.CredFile + config.PendingSuffix
	require.NoError(t, config.WriteFile(pending, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	fi, err := os.Lstat(pending)
	require.NoError(t, err)
	f.pending = &pendingCredential{setupID: id.String(), file: fi, password: "new"}
	require.NoError(t, config.WriteFile(pending, []byte("postgres://bt_agent_bot:planted@db:5432/app\n")))

	require.Error(t, f.Finish(context.Background(), id.String(), true))
	require.Empty(t, pw.set)
	got, err := os.ReadFile(f.CredFile)
	require.NoError(t, err)
	require.Contains(t, string(got), ":old@")
	cfg, err := config.Load(f.ConfigPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Agents[0].Setup, "nothing cleared")
}

// A pending credential Postgres refuses (28P01) means the person has not
// run the code yet: not recorded, and no error.
func TestARefusedPendingLoginIsNotAnError(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, _, _ := fileFinisher(t, id)
	require.NoError(t, config.WriteFile(f.CredFile+config.PendingSuffix, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	f.Connect = func(context.Context, string) (AgentLogin, error) {
		return nil, fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: "28P01", Message: "password authentication failed"})
	}
	recorded, has, err := f.PendingRecorded(context.Background(), id)
	require.NoError(t, err)
	require.False(t, recorded)
	require.False(t, has)
}

// Supabase's pooler not knowing the role (XX000 "Tenant or user not
// found") is a refused login, as basalt init --remote reads it, not an
// error on every status call.
func TestThePoolerNotKnowingTheRoleIsARefusedLogin(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, _, _ := fileFinisher(t, id)
	require.NoError(t, config.WriteFile(f.CredFile+config.PendingSuffix, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	f.Connect = func(context.Context, string) (AgentLogin, error) {
		return nil, fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: "XX000", Message: "Tenant or user not found"})
	}
	recorded, has, err := f.PendingRecorded(context.Background(), id)
	require.NoError(t, err)
	require.False(t, recorded)
	require.False(t, has)

	// Another internal error is still one.
	f.Connect = func(context.Context, string) (AgentLogin, error) {
		return nil, fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: "XX000", Message: "something else"})
	}
	_, _, err = f.PendingRecorded(context.Background(), id)
	require.Error(t, err)
}

// A .pending file over 4096 bytes as stored, its newline included, is
// refused before anything logs in with it, as basalt init --remote refuses
// it.
func TestAPendingCredentialOver4096BytesIsRefused(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, _, _ := fileFinisher(t, id)
	f.Connect = func(context.Context, string) (AgentLogin, error) { return fakeLogin{recorded: true}, nil }
	pw := func(n int) string { return strings.Repeat("p", n-len("postgres://bt_agent_bot:@db:5432/app")) }

	// 4096 bytes of URL and a newline: 4097 bytes stored.
	over := "postgres://bt_agent_bot:" + pw(4096) + "@db:5432/app\n"
	require.Len(t, over, 4097)
	require.NoError(t, config.WriteFile(f.CredFile+config.PendingSuffix, []byte(over)))
	_, _, err := f.PendingRecorded(context.Background(), id)
	require.ErrorContains(t, err, "too large")
	require.NotContains(t, err.Error(), "ppp", "the credential is not echoed")

	// 4096 bytes stored, its newline included: read, and logs in.
	exact := "postgres://bt_agent_bot:" + pw(4095) + "@db:5432/app\n"
	require.Len(t, exact, 4096)
	require.NoError(t, config.WriteFile(f.CredFile+config.PendingSuffix, []byte(exact)))
	recorded, has, err := f.PendingRecorded(context.Background(), id)
	require.NoError(t, err)
	require.True(t, recorded)
	require.True(t, has)
}
