//go:build unix

package engine

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// recordingPassword records the passwords the pool is switched to.
type recordingPassword struct{ set []string }

func (p *recordingPassword) Set(pw string) { p.set = append(p.set, pw) }

// fileFinisher is a setupFinisher over files in a temporary directory, with
// a pending setup for agent bot in engine.json.
func fileFinisher(t *testing.T, id uuid.UUID) (*setupFinisher, *recordingPassword, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfgPath, credFile := filepath.Join(dir, "engine.json"), filepath.Join(dir, "bot.url")
	require.NoError(t, config.WriteFile(credFile, []byte("postgres://bt_agent_bot:old@db:5432/app\n")))
	require.NoError(t, config.UpsertAgent(cfgPath, config.Settings{SocketDir: "/run/basalt"}, config.Agent{
		Name: "bot", OSUser: "bot", CredentialFile: credFile, Setup: &config.Setup{SetupID: id.String(), Kind: guard.SetupAgent,
			GuardVersion: guard.LatestVersion(), ExpiresAt: "2026-11-13T10:00:00Z", Code: "basalt-setup.1.abc.def", Fingerprint: "a1b2"},
	}))
	pw, logs := &recordingPassword{}, &bytes.Buffer{}
	f := &setupFinisher{
		configPath: cfgPath, agent: "bot", credFile: credFile,
		login:    loginTarget{host: "db", port: 5432, database: "app", user: "bt_agent_bot"},
		password: pw, reset: func() {},
		connect: func(context.Context, string) (agentLogin, error) {
			t.Fatal("no login expected")
			return nil, errors.New("no login expected")
		},
		log: slog.New(slog.NewTextHandler(logs, nil)),
	}
	return f, pw, logs
}

// A .pending credential for another database is logged once per setup, not
// on every call.
func TestAPendingCredentialForAnotherDatabaseIsLoggedOncePerSetup(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	f, _, logs := fileFinisher(t, id)
	require.NoError(t, config.WriteFile(f.credFile+pendingSuffix, []byte("postgres://bt_agent_bot:new@other:5432/app\n")))
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
	pending := f.credFile + pendingSuffix
	require.NoError(t, config.WriteFile(pending, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	fi, err := os.Lstat(pending)
	require.NoError(t, err)
	f.pending = &pendingCredential{setupID: id.String(), file: fi, password: "new"}

	require.NoError(t, f.Finish(context.Background(), id.String(), true))
	require.NoError(t, f.Finish(context.Background(), id.String(), true), "already promoted: done")
	require.Equal(t, []string{"new"}, pw.set, "promoted once")
	got, err := os.ReadFile(f.credFile)
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
	pending := f.credFile + pendingSuffix
	require.NoError(t, config.WriteFile(pending, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	fi, err := os.Lstat(pending)
	require.NoError(t, err)
	f.pending = &pendingCredential{setupID: id.String(), file: fi, password: "new"}
	require.NoError(t, config.WriteFile(pending, []byte("postgres://bt_agent_bot:planted@db:5432/app\n")))

	require.Error(t, f.Finish(context.Background(), id.String(), true))
	require.Empty(t, pw.set)
	got, err := os.ReadFile(f.credFile)
	require.NoError(t, err)
	require.Contains(t, string(got), ":old@")
	cfg, err := config.Load(f.configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Agents[0].Setup, "nothing cleared")
}
