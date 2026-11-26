package localsetup_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// The engine's answer to "Is this your database?" comes from its own files
// and connects nowhere; the person's "No" changes no file and is only a
// mark basalt init's probe reads once, within five minutes. Nothing here
// resets anything: the administrator dialog does.
func TestNotMineIsOnlyAMarkForBasaltInit(t *testing.T) {
	t.Parallel()
	f, _ := installed(t)
	ctx := context.Background()
	_, err := f.svc.Engine(ctx)
	refusal(t, err, localsetup.CodeJobUnavailable)

	svc, err := localsetup.New(localsetup.Options{
		Backend:    setupbackend.Backend{},
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true,
		Now: func() time.Time { return f.now },
		Dial: setupbackend.Dialer(func(context.Context, string) (*pgx.Conn, error) {
			t.Error("the engine check connected to a database")
			return nil, errors.New("no connection")
		}),
	})
	require.NoError(t, err)
	got, err := svc.Engine(ctx)
	require.NoError(t, err)
	var database string
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT pg_catalog.current_database()::text`).Scan(&database))
	require.Equal(t, []string{"demo_bot"}, got.Agents)
	require.Len(t, got.Databases, 1)
	require.Equal(t, database, got.Databases[0].Database, "named from the credential file")
	require.NotEmpty(t, got.Databases[0].Host)

	before, err := os.ReadFile(f.config)
	require.NoError(t, err)
	_, err = svc.Check(ctx, localsetup.Request{})
	refusal(t, err, localsetup.CodeJobUnavailable)
	require.NoError(t, svc.NotMine(ctx))
	after, err := os.ReadFile(f.config)
	require.NoError(t, err)
	require.Equal(t, before, after, "a No changes no file")
	require.FileExists(t, filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url"))
	_, err = svc.Check(ctx, localsetup.Request{})
	refusal(t, err, localsetup.CodeResetAsked)
	_, err = svc.Check(ctx, localsetup.Request{})
	refusal(t, err, localsetup.CodeJobUnavailable)

	require.NoError(t, svc.NotMine(ctx))
	f.now = f.now.Add(6 * time.Minute)
	_, err = svc.Check(ctx, localsetup.Request{})
	refusal(t, err, localsetup.CodeJobUnavailable)
}

// After the reset script deleted the engine's files, the person's install
// of the same database under the same agent name finds the agent role with
// no password this engine holds: it sets a new one, as REPAIR does, rather
// than stop at ROLE_EXISTS. A role outside BasaltDB's agents stays
// ROLE_EXISTS.
func TestAnInstallAfterAResetSetsANewPasswordForTheRoleLeft(t *testing.T) {
	t.Parallel()
	f, _ := installed(t)
	ctx := context.Background()
	credential := filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url")
	// What the reset script does as root.
	require.NoError(t, os.Remove(f.config))
	require.NoError(t, os.Remove(credential))

	other, err := f.db.Names.Agent("plain_bot")
	require.NoError(t, err)
	f.db.Exec(t, `CREATE ROLE `+other+` LOGIN`)
	t.Cleanup(func() { _, _ = f.db.Admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+other) })
	plain := f.request()
	plain.Agent = "plain_bot"
	_, err = f.svc.Check(ctx, plain)
	refusal(t, err, localsetup.CodeRoleExists)

	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.Contains(t, checked.Lines[len(checked.Lines)-1], "from an earlier setup")
	req := f.request()
	if checked.PasskeyNeeded {
		req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	} else {
		req.Challenge = checked.Challenge
	}
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	require.Equal(t, "demo_bot", cfg.Agents[0].Name)
	dsn, err := config.ReadCredential(credential)
	require.NoError(t, err)
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err, "the new credential logs in")
	defer func() { _ = conn.Close(ctx) }()
	role, err := f.db.Names.Agent("demo_bot")
	require.NoError(t, err)
	var user string
	require.NoError(t, conn.QueryRow(ctx, `SELECT current_user::text`).Scan(&user))
	require.Equal(t, role, user)
}
