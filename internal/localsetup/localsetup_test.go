package localsetup_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

const origin = "http://localhost:8787"

// unusedAdminURL is an admin string nothing connects to.
const unusedAdminURL = "postgres://admin" + ":" + "pw@db.example/app"

// fakeUsers has the agent's OS user alice (uid 4242) and this engine
// (uid 4000, group 4000).
type fakeUsers struct{ aliceGroups []string }

func (f fakeUsers) Lookup(name string) (*user.User, error) {
	switch name {
	case "alice":
		return &user.User{Username: "alice", Uid: "4242", Gid: "4242"}, nil
	case "root":
		return &user.User{Username: "root", Uid: "0", Gid: "0"}, nil
	case "engine":
		return &user.User{Username: "engine", Uid: "4000", Gid: "4000"}, nil
	case "carol": // the engine's group is her primary group
		return &user.User{Username: "carol", Uid: "4343", Gid: "4000"}, nil
	case "basalt-plugin-acme":
		return &user.User{Username: "basalt-plugin-acme", Uid: "4444", Gid: "4444"}, nil
	}
	return nil, user.UnknownUserError(name)
}

func (fakeUsers) LookupID(uid string) (*user.User, error) {
	return &user.User{Username: "engine", Uid: uid, Gid: "4000"}, nil
}

func (f fakeUsers) GroupIDs(*user.User) ([]string, error) { return f.aliceGroups, nil }

func (fakeUsers) Self() int { return 4000 }

type fixture struct {
	db     *guardtest.DB
	svc    *localsetup.Service
	config string
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := guardtest.New(t)
	if u, err := url.Parse(d.URL); err != nil || u.User == nil {
		t.Skip("the test server's admin string has no password")
	} else if _, ok := u.User.Password(); !ok {
		t.Skip("the test server's admin string has no password")
	}
	f := &fixture{db: d, config: filepath.Join(t.TempDir(), "engine.json"), now: time.Now()}
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: d.Names.Prefix,
		Now: func() time.Time { return f.now },
	})
	require.NoError(t, err)
	f.svc = svc
	return f
}

func (f *fixture) request() localsetup.Request {
	return localsetup.Request{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: "alice", Demo: true, DatabaseURL: f.db.URL}
}

func refusal(t *testing.T, err error, code string) {
	t.Helper()
	var r *localsetup.RefusalError
	require.True(t, errors.As(err, &r), "%v", err)
	require.Equal(t, code, r.Code, r.Message)
}

func exists(t *testing.T, d *guardtest.DB, schema string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)`, schema).Scan(&ok))
	return ok
}

// register is the browser's part: a passkey made with check's challenge.
func register(t *testing.T, c localsetup.Challenge) *localsetup.Passkey {
	t.Helper()
	rp, err := passkey.Local(origin)
	require.NoError(t, err)
	auth, err := passkeytest.New(rp)
	require.NoError(t, err)
	rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	require.NoError(t, err)
	resp, err := auth.Register(rr, nil)
	require.NoError(t, err)
	return &localsetup.Passkey{RegistrationResponse: resp, Label: "laptop"}
}

func TestInstallChecksThenRunsOnceAndWritesTheEnginesFiles(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.True(t, checked.PasskeyNeeded, "a fresh database has no passkey")
	var name string
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT current_database()`).Scan(&name))
	require.Equal(t, name, checked.Database, "the name the server gives")
	require.NotEmpty(t, checked.Lines)
	require.Contains(t, checked.SQL, "basalt_demo")
	require.Empty(t, checked.Questions)
	require.False(t, exists(t, f.db, "basalt_meta"), "check changes nothing")
	require.False(t, exists(t, f.db, "basalt_demo"), "check changes nothing")
	_, err = os.Stat(f.config)
	require.ErrorIs(t, err, os.ErrNotExist)

	_, err = f.svc.Run(ctx, f.request())
	refusal(t, err, localsetup.CodePasskeyRequired)
	require.False(t, exists(t, f.db, "basalt_meta"), "refused: nothing changed")

	req := f.request()
	req.Challenge, req.Passkey = &checked.Challenge, register(t, checked.Challenge)
	done, err := f.svc.Run(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "demo_bot", done.Agent)
	require.Equal(t, "basalt mcp --agent demo_bot", done.MCPCommand)
	require.Equal(t, []string{"demo ready: leads 30, lead_notes 20"}, done.Lines)
	require.Len(t, done.Passkeys, 1)
	require.Regexp(t, `^[0-9a-f]{4}( [0-9a-f]{4}){4}$`, done.Passkeys[0].CheckCode)
	require.True(t, exists(t, f.db, "basalt_meta"))
	require.True(t, exists(t, f.db, "basalt_demo"))

	// The engine wrote its own files: a config its loader takes, and the
	// agent's credential, which logs in.
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	require.Equal(t, "alice", cfg.Agents[0].OSUser)
	require.True(t, cfg.Service())
	cred := filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url")
	info, err := os.Stat(cred)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), info.Mode().Perm())
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	require.NotContains(t, dsn, ":"+mustPassword(t, f.db.URL)+"@", "the agent's string never holds the admin's password")
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err, "the agent logs in with the credential the engine wrote")
	var n int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(id)::int FROM basalt_demo.leads`).Scan(&n))
	require.Equal(t, 30, n)
	require.NoError(t, conn.Close(ctx))

	// Once: the engine has a config now.
	_, err = f.svc.Run(ctx, req)
	refusal(t, err, localsetup.CodeJobUnavailable)
	_, err = f.svc.Check(ctx, f.request())
	refusal(t, err, localsetup.CodeJobUnavailable)
}

func mustPassword(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	return pw
}

func TestRunRefusesAChallengeOfAnotherJobOrTooOld(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)

	other := f.request()
	other.Agent = "other_bot"
	other.Challenge, other.Passkey = &checked.Challenge, register(t, checked.Challenge)
	_, err = f.svc.Run(ctx, other)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	// The same job on another database: the challenge is bound to the one
	// the server named at check.
	other2 := guardtest.New(t)
	elsewhere := f.request()
	elsewhere.DatabaseURL = other2.URL
	elsewhere.Challenge, elsewhere.Passkey = &checked.Challenge, register(t, checked.Challenge)
	_, err = f.svc.Run(ctx, elsewhere)
	refusal(t, err, localsetup.CodeChallengeInvalid)
	require.False(t, exists(t, other2, "basalt_meta"), "nothing changed there")

	f.now = f.now.Add(16 * time.Minute)
	late := f.request()
	late.Challenge, late.Passkey = &checked.Challenge, register(t, checked.Challenge)
	_, err = f.svc.Run(ctx, late)
	refusal(t, err, localsetup.CodeChallengeExpired)
	require.False(t, exists(t, f.db, "basalt_meta"), "nothing changed")
}

// Every refusal is a fixed message that holds no part of the admin string.
func TestRefusalsNeverHoldTheAdminString(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	secret := mustPassword(t, f.db.URL)
	u, err := url.Parse(f.db.URL)
	require.NoError(t, err)
	wrong := *u
	wrong.User = url.UserPassword(u.User.Username(), secret+"-wrong")
	unreachable := *u
	unreachable.Host = "127.0.0.1:1"
	noPassword := *u
	noPassword.User = url.User(u.User.Username())
	for _, v := range []struct {
		dsn, code string
	}{
		{wrong.String(), localsetup.CodeLoginFailed},
		{unreachable.String(), localsetup.CodeDatabaseUnreachable},
		{noPassword.String(), localsetup.CodeConnectionStringRefused},
		{"host=localhost password=" + secret, localsetup.CodeConnectionStringRefused},
	} {
		req := f.request()
		req.DatabaseURL = v.dsn
		_, err := f.svc.Check(ctx, req)
		refusal(t, err, v.code)
		require.NotContains(t, err.Error(), ":"+secret+"@")
		require.NotContains(t, err.Error(), secret+"-wrong")
		require.NotContains(t, err.Error(), u.Host)
	}
}

func TestRequestsTheEngineRefusesBeforeConnecting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dialed := false
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: filepath.Join(dir, "engine.json"), Origin: origin, Users: fakeUsers{aliceGroups: []string{"4000"}},
		Dial: func(context.Context, string) (*pgx.Conn, error) {
			dialed = true
			return nil, errors.New("not here")
		},
	})
	require.NoError(t, err)
	good := localsetup.Request{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: "bob", Demo: true, DatabaseURL: unusedAdminURL}
	for _, v := range []struct {
		edit func(*localsetup.Request)
		code string
	}{
		{func(r *localsetup.Request) { r.Job = "REMOVE" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.Agent = "Bad-Name" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "nobody-here" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "root" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "engine" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "carol" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "basalt-plugin-acme" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.OSUser = "alice" }, localsetup.CodeInvalidArgument}, // in the engine's group
		{func(r *localsetup.Request) { r.OSUser = "alice"; r.Demo = false }, localsetup.CodeInvalidArgument},
	} {
		req := good
		v.edit(&req)
		_, err := svc.Check(context.Background(), req)
		refusal(t, err, v.code)
	}
	require.False(t, dialed, "nothing connects before the request passes")

	// With a config the engine runs no install.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "engine.json"), []byte("{}"), 0o600))
	_, err = svc.Run(context.Background(), good)
	refusal(t, err, localsetup.CodeJobUnavailable)
	require.NotContains(t, err.Error(), unusedAdminURL)
	require.NotContains(t, err.Error(), "db.example")
}

func TestInstallWithoutTheSampleDatabaseIsNotOfferedYet(t *testing.T) {
	t.Parallel()
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: origin,
		Users: okUsers{}, Dial: func(context.Context, string) (*pgx.Conn, error) { return nil, errors.New("not here") },
	})
	require.NoError(t, err)
	_, err = svc.Check(context.Background(), localsetup.Request{Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: unusedAdminURL})
	refusal(t, err, localsetup.CodeNoTables)
}

// okUsers admits alice.
type okUsers struct{ fakeUsers }

// A run whose engine.json write failed after the commit leaves the role and
// the credential: the next run finishes with that role, its password kept,
// and writes the config.
func TestRunFinishesAnInstallWhoseConfigWriteFailed(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a folder without write permission")
	}
	f := newFixture(t)
	ctx := context.Background()
	dir := filepath.Dir(f.config)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "agents"), 0o700))
	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	req := f.request()
	req.Challenge, req.Passkey = &checked.Challenge, register(t, checked.Challenge)

	// The engine's folder takes the credential (agents/) but not engine.json.
	require.NoError(t, os.Chmod(dir, 0o500))
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, os.Chmod(dir, 0o700))
	refusal(t, err, localsetup.CodeSetupFailed)
	var r *localsetup.RefusalError
	require.ErrorAs(t, err, &r)
	require.Equal(t, 500, r.Status)
	require.True(t, exists(t, f.db, "basalt_meta"), "the database part committed")
	cred := filepath.Join(dir, "agents", "demo_bot.url")
	before, err := os.ReadFile(cred)
	require.NoError(t, err, "the credential is kept")

	checked, err = f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.False(t, checked.PasskeyNeeded, "the passkey committed with the role")
	require.Contains(t, strings.Join(checked.Lines, "\n"), "this finishes its setup")
	done, err := f.svc.Run(ctx, f.request())
	require.NoError(t, err)
	require.Equal(t, "demo_bot", done.Agent)
	after, err := os.ReadFile(cred)
	require.NoError(t, err)
	require.Equal(t, before, after, "the password stays")
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err, "the kept password still logs in")
	require.NoError(t, conn.Close(ctx))
}

// A role of the same name this engine holds no password for is never taken
// over, even with a credential file next to it.
func TestRunNeverTakesOverAForeignRole(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	role := f.db.Names.Prefix + "_agent_demo_bot"
	f.db.Exec(t, `CREATE ROLE `+role+` LOGIN PASSWORD 'someone-elses'`)
	_, err := f.svc.Check(ctx, f.request())
	refusal(t, err, localsetup.CodeRoleExists)

	// A credential that does not log in as that role changes nothing.
	u, err := url.Parse(f.db.URL)
	require.NoError(t, err)
	u.User = url.UserPassword(role, "guessed")
	require.NoError(t, config.WriteFile(filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url"), []byte(u.String()+"\n")))
	_, err = f.svc.Run(ctx, f.request())
	refusal(t, err, localsetup.CodeRoleExists)
	require.False(t, exists(t, f.db, "basalt_meta"), "nothing changed")
}
