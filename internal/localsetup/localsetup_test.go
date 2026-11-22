package localsetup_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
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
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/pii/classify"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
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
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
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

// withParam adds a query parameter to a URL.
func withParam(raw, kv string) string {
	if strings.Contains(raw, "?") {
		return raw + "&" + kv
	}
	return raw + "?" + kv
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
	other.Challenge, other.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, other)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	// The same job on another database: the challenge is bound to the one
	// the server named at check.
	other2 := guardtest.New(t)
	elsewhere := f.request()
	elsewhere.DatabaseURL = other2.URL
	elsewhere.Challenge, elsewhere.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, elsewhere)
	refusal(t, err, localsetup.CodeChallengeInvalid)
	require.False(t, exists(t, other2, "basalt_meta"), "nothing changed there")

	f.now = f.now.Add(16 * time.Minute)
	late := f.request()
	late.Challenge, late.Passkey = checked.Challenge, register(t, *checked.Challenge)
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
		{withParam(f.db.URL, "host=other.example"), localsetup.CodeConnectionStringRefused},
		{withParam(f.db.URL, "dbname=other"), localsetup.CodeConnectionStringRefused},
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
		{func(r *localsetup.Request) { r.Job = "MIGRATE" }, localsetup.CodeInvalidArgument},
		{func(r *localsetup.Request) { r.Job = localsetup.JobRemove }, localsetup.CodeJobUnavailable},
		{func(r *localsetup.Request) { r.Job = localsetup.JobRepair }, localsetup.CodeJobUnavailable},
		{func(r *localsetup.Request) { r.Job = localsetup.JobPasskeyRemove }, localsetup.CodeJobUnavailable},
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

// The admin string takes only pgdial's connection keys: one that names a
// file (or anything else) is refused before anything connects or reads it,
// and the refusal names neither the key's value nor the host.
func TestAdminStringRefusesKeysOutsideTheAllowlist(t *testing.T) {
	t.Parallel()
	dialed := false
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: origin, Users: okUsers{},
		Dial: func(context.Context, string) (*pgx.Conn, error) {
			dialed = true
			return nil, errors.New("not here")
		},
	})
	require.NoError(t, err)
	const path = "/etc/secretfile-for-the-test"
	for _, query := range []string{
		"passfile=" + path,
		"sslkey=" + path,
		"sslcert=" + path,
		"sslrootcert=" + path,
		"sslcrl=" + path,
		"sslcrldir=" + path,
		"sslpassword=" + path,
		"service=" + path,
		"servicefile=" + path,
		"hostaddr=10.0.0.1",
		"host=" + path,
		"krbsrvname=" + path,
		"options=-c%20x%3D" + path,
		"PASSFILE=" + path,
		"ssl%6Bey=" + path,
		"sslmode=require&sslkey=" + path,
		"sslmode=require;passfile=" + path,
	} {
		dialed = false
		req := localsetup.Request{Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: unusedAdminURL + "?" + query}
		_, err := svc.Check(context.Background(), req)
		refusal(t, err, localsetup.CodeConnectionStringRefused)
		require.NotContains(t, err.Error(), path, query)
		require.NotContains(t, err.Error(), "db.example", query)
		_, err = svc.Run(context.Background(), req)
		refusal(t, err, localsetup.CodeConnectionStringRefused)
		require.False(t, dialed, "nothing connects with %s", query)
	}
	for _, query := range []string{"sslmode=verify-full", "application_name=app&connect_timeout=5", "channel_binding=require&target_session_attrs=any"} {
		dialed = false
		req := localsetup.Request{Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: unusedAdminURL + "?" + query}
		_, err := svc.Check(context.Background(), req)
		var r *localsetup.RefusalError
		require.True(t, errors.As(err, &r), query)
		require.NotEqual(t, localsetup.CodeConnectionStringRefused, r.Code, query)
		require.True(t, dialed, "an allowed key reaches the connection: %s", query)
	}
}

func TestRealInstallRefusesBadSchemasAndPicksBeforeConnecting(t *testing.T) {
	t.Parallel()
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: origin,
		Users: okUsers{}, Dial: func(context.Context, string) (*pgx.Conn, error) { return nil, errors.New("not here") },
	})
	require.NoError(t, err)
	base := localsetup.Request{Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: unusedAdminURL}
	pick := func(table, access string) []localsetup.TablePick {
		return []localsetup.TablePick{{Table: table, Access: access}}
	}
	cases := map[string]struct {
		mutate func(*localsetup.Request)
		code   string
	}{
		"demo with tables":     {func(r *localsetup.Request) { r.Demo = true; r.Tables = pick("public.a", "READ") }, localsetup.CodeAnswersInvalid},
		"demo with schemas":    {func(r *localsetup.Request) { r.Demo = true; r.Schemas = []string{"public"} }, localsetup.CodeAnswersInvalid},
		"no schema":            {func(r *localsetup.Request) { r.Schemas = []string{} }, localsetup.CodeAnswersInvalid},
		"six schemas":          {func(r *localsetup.Request) { r.Schemas = []string{"a", "b", "c", "d", "e", "f"} }, localsetup.CodeAnswersInvalid},
		"a system schema":      {func(r *localsetup.Request) { r.Schemas = []string{"basalt_meta"} }, localsetup.CodeAnswersInvalid},
		"a pg_ schema":         {func(r *localsetup.Request) { r.Schemas = []string{"pg_toast"} }, localsetup.CodeAnswersInvalid},
		"a schema twice":       {func(r *localsetup.Request) { r.Schemas = []string{"a", "a"} }, localsetup.CodeAnswersInvalid},
		"a capital schema":     {func(r *localsetup.Request) { r.Schemas = []string{"Public"} }, localsetup.CodeAnswersInvalid},
		"an empty pick list":   {func(r *localsetup.Request) { r.Tables = []localsetup.TablePick{} }, localsetup.CodeNoTables},
		"a capital table":      {func(r *localsetup.Request) { r.Tables = pick("public.Users", "READ") }, localsetup.CodeAnswersInvalid},
		"no schema in a pick":  {func(r *localsetup.Request) { r.Tables = pick("users", "READ") }, localsetup.CodeAnswersInvalid},
		"a pick outside":       {func(r *localsetup.Request) { r.Tables = pick("other.users", "READ") }, localsetup.CodeAnswersInvalid},
		"a bad access":         {func(r *localsetup.Request) { r.Tables = pick("public.users", "ALL") }, localsetup.CodeAnswersInvalid},
		"a table picked twice": {func(r *localsetup.Request) { r.Tables = append(pick("public.a", "READ"), pick("public.a", "WRITE")...) }, localsetup.CodeAnswersInvalid},
	}
	for name, c := range cases {
		req := base
		c.mutate(&req)
		_, err := svc.Check(context.Background(), req)
		require.Error(t, err, name)
		var r *localsetup.RefusalError
		require.True(t, errors.As(err, &r), name)
		require.Equal(t, c.code, r.Code, name+": "+r.Message)
	}
	many := make([]localsetup.TablePick, 501)
	for i := range many {
		many[i] = localsetup.TablePick{Table: "public.t" + strings.Repeat("a", i%5), Access: "READ"}
	}
	req := base
	req.Tables = many
	_, err = svc.Check(context.Background(), req)
	refusal(t, err, localsetup.CodeAnswersInvalid)
	// Run without a pick is NO_TABLES, before it connects.
	_, err = svc.Run(context.Background(), base)
	refusal(t, err, localsetup.CodeNoTables)
}

func (f *fixture) real() localsetup.Request {
	r := f.request()
	r.Demo = false
	r.Agent = "bot"
	return r
}

func TestRealInstallListsThenGrantsOnlyThePickedTables(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY, note text);
CREATE TABLE public.logs (line text);
CREATE TABLE public.secrets (id bigint PRIMARY KEY, v text);
CREATE TABLE public."Mixed" (id bigint PRIMARY KEY)`)

	listing, err := f.svc.Check(ctx, f.real())
	require.NoError(t, err)
	require.Nil(t, listing.Challenge, "nothing depends on a pick yet")
	require.Empty(t, listing.SQL)
	require.Contains(t, listing.Tables, localsetup.ListedTable{Table: "public.orders", CanWrite: true})
	require.Contains(t, listing.Tables, localsetup.ListedTable{Table: "public.logs", CanWrite: false})
	require.Contains(t, listing.Excluded, localsetup.ExcludedTable{Table: "public.Mixed", Owner: "unsupported name"})
	require.False(t, exists(t, f.db, "basalt_demo"), "a real install never makes the sample schema")
	// The confirm step's facts: where the string logged in, as whom, and
	// what verified the certificate; never the string itself.
	adminCfg := f.db.Admin.Config()
	require.Equal(t, adminCfg.User, listing.SessionUser)
	require.Equal(t, strings.ToLower(adminCfg.Host), listing.Host)
	require.Equal(t, int(adminCfg.Port), listing.Port)
	require.NotNil(t, listing.Certificate)
	if _, tlsConn := f.db.Admin.PgConn().Conn().(*tls.Conn); !tlsConn {
		require.Equal(t, &localsetup.ConfirmCertificate{Kind: "NONE"}, listing.Certificate, "no TLS: no certificate to name")
	}
	raw, err := json.Marshal(listing)
	require.NoError(t, err)
	u, err := url.Parse(f.db.URL)
	require.NoError(t, err)
	require.NotContains(t, string(raw), u.User.String()+"@", "the answer never echoes the user and password")
	require.NotContains(t, string(raw), "databaseUrl")

	// Write on a table with no primary key: the listing says it cannot.
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.logs", Access: localsetup.AccessWrite}}
	_, err = f.svc.Check(ctx, req)
	refusal(t, err, localsetup.CodeTablesChanged)
	// A table that is not there.
	req.Tables = []localsetup.TablePick{{Table: "public.nothing", Access: localsetup.AccessRead}}
	_, err = f.svc.Check(ctx, req)
	refusal(t, err, localsetup.CodeTablesChanged)

	req.Tables = []localsetup.TablePick{
		{Table: "public.orders", Access: localsetup.AccessWrite},
		{Table: "public.logs", Access: localsetup.AccessRead},
	}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, checked.Challenge)
	require.Contains(t, checked.SQL, "orders")
	require.NotContains(t, checked.SQL, "public.secrets")
	require.Empty(t, checked.Questions)

	// A passkey made for these picks does not fit others.
	other := req
	other.Tables = []localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessRead}}
	other.Challenge, other.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, other)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	done, err := f.svc.Run(ctx, req)
	require.NoError(t, err)
	require.Equal(t, []string{"agent bot ready: 1 tables it can change, 1 it can read"}, done.Lines)

	cred := filepath.Join(filepath.Dir(f.config), "agents", "bot.url")
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	var n int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(id)::int FROM public.orders`).Scan(&n))
	_, err = conn.Exec(ctx, `SELECT 1 FROM public.logs`)
	require.NoError(t, err, "a READ table can be read")
	_, err = conn.Exec(ctx, `SELECT 1 FROM public.secrets`)
	require.Error(t, err, "an unpicked table is never granted")
}

func TestRealInstallAsksTheRowLevelSecurityQuestionAndRunNeedsItsAnswer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.vault (id bigint PRIMARY KEY, v text);
INSERT INTO public.vault VALUES (1, 'a');
ALTER TABLE public.vault ENABLE ROW LEVEL SECURITY`)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.vault", Access: localsetup.AccessRead}}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.Len(t, checked.Questions, 1)
	q := checked.Questions[0]
	require.Equal(t, "ROW_LEVEL_SECURITY", q.Kind)
	require.Equal(t, "public.vault", q.Table)
	require.Equal(t, []string{"ALL_ROWS", "NONE"}, q.Choices)
	require.Contains(t, checked.SQL, "POLICY", "the check shows the page's answer, ALL_ROWS")

	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	// The challenge binds the answers the check showed (ALL_ROWS): a run
	// with none, another choice or another table is refused, nothing changed.
	for _, answers := range [][]localsetup.Answer{
		nil,
		{{Table: "public.vault", Choice: "NONE"}},
		{{Table: "public.vault", Choice: "MAYBE"}},
		{{Table: "public.vault", Choice: "ALL_ROWS"}, {Table: "public.other", Choice: "NONE"}},
	} {
		req.Answers = answers
		_, err = f.svc.Run(ctx, req)
		refusal(t, err, localsetup.CodeChallengeInvalid)
	}
	require.False(t, exists(t, f.db, "basalt_demo"))
	_, statErr := os.Stat(f.config)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	noChallenge := req
	noChallenge.Challenge = nil
	noChallenge.Answers = []localsetup.Answer{{Table: "public.vault", Choice: "ALL_ROWS"}}
	_, err = f.svc.Run(ctx, noChallenge)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	req.Answers = []localsetup.Answer{{Table: "public.vault", Choice: "ALL_ROWS"}}
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
}

func TestRealInstallNoneAnswerCreatesNoPolicyAndOtherOwnersAreExcluded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	other := f.db.Names.Prefix + "_other"
	f.db.Exec(t, `CREATE ROLE `+other+` NOLOGIN`)
	f.db.Exec(t, `CREATE TABLE public.vault (id bigint PRIMARY KEY, v text);
ALTER TABLE public.vault ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.theirs (id bigint PRIMARY KEY);
ALTER TABLE public.theirs OWNER TO `+other)
	listing, err := f.svc.Check(ctx, f.real())
	require.NoError(t, err)
	require.Contains(t, listing.Excluded, localsetup.ExcludedTable{Table: "public.theirs", Owner: other})
	for _, tbl := range listing.Tables {
		require.NotEqual(t, "public.theirs", tbl.Table)
	}

	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.vault", Access: localsetup.AccessWrite}}
	req.Answers = []localsetup.Answer{{Table: "public.vault", Choice: "NONE"}}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.NotRegexp(t, `(?is)CREATE POLICY[^;]*public\.vault`, checked.SQL)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
	var n int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT count(polname)::int FROM pg_catalog.pg_policy WHERE polrelid = 'public.vault'::regclass AND polname LIKE $1`, "%_agent_bot").Scan(&n))
	require.Zero(t, n, "NONE makes no policy")
}

func TestRealInstallRunRefusesTablesThatChangedSinceTheCheck(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessWrite}}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	f.db.Exec(t, `DROP TABLE public.orders`)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	refusal(t, err, localsetup.CodeTablesChanged)
	_, statErr := os.Stat(f.config)
	require.ErrorIs(t, statErr, os.ErrNotExist, "nothing changed")
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
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)

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

// A kept credential for another server or database is never tried, even
// when it would log in as a role of that name: the engine's agent would
// point at the other database.
func TestRunNeverFinishesWithACredentialForAnotherTarget(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	role := f.db.Names.Prefix + "_agent_demo_bot"
	f.db.Exec(t, `CREATE ROLE `+role+` LOGIN PASSWORD 'kept-elsewhere'`)
	u, err := url.Parse(f.db.URL)
	require.NoError(t, err)
	kept := *u
	kept.User = url.UserPassword(role, "kept-elsewhere")
	cred := filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url")

	// The same role and password, but the credential names another host
	// than this run's admin string: one that reaches the same server under
	// another name, so it would log in as that role on that database. Only
	// the target check refuses it.
	alias := kept
	switch u.Hostname() {
	case "127.0.0.1":
		alias.Host = "localhost:" + u.Port()
	case "localhost":
		alias.Host = "127.0.0.1:" + u.Port()
	default:
		t.Skipf("the test server's host %s has no second name here", u.Hostname())
	}
	db := kept
	db.Path = "/another_db"
	for _, other := range []url.URL{alias, db} {
		require.NoError(t, config.WriteFile(cred, []byte(other.String()+"\n")))
		_, err = f.svc.Check(ctx, f.request())
		refusal(t, err, localsetup.CodeRoleExists)
	}

	// Pointing at this run's server and database, it is the engine's own.
	require.NoError(t, config.WriteFile(cred, []byte(kept.String()+"\n")))
	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.Contains(t, strings.Join(checked.Lines, "\n"), "this finishes its setup")
}

func TestRealInstallRefusesBadLabelsBeforeConnecting(t *testing.T) {
	t.Parallel()
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: origin,
		Users: okUsers{}, Dial: func(context.Context, string) (*pgx.Conn, error) { return nil, errors.New("not here") },
	})
	require.NoError(t, err)
	picked := []localsetup.TablePick{{Table: "public.people", Access: localsetup.AccessRead}}
	label := func(table, column, class string) localsetup.ColumnClass {
		return localsetup.ColumnClass{Table: table, Column: column, Class: class, Was: localsetup.Label{Class: "UNCLASSIFIED"}}
	}
	cases := map[string]localsetup.Request{
		"labels without picks":     {ColumnClasses: []localsetup.ColumnClass{label("public.people", "email", "SECRET")}},
		"restPublic without picks": {RestPublic: true},
		"a table not picked":       {Tables: picked, ColumnClasses: []localsetup.ColumnClass{label("public.other", "email", "SECRET")}},
		"a column twice":           {Tables: picked, ColumnClasses: []localsetup.ColumnClass{label("public.people", "email", "SECRET"), label("public.people", "email", "PUBLIC")}},
		"UNCLASSIFIED set":         {Tables: picked, ColumnClasses: []localsetup.ColumnClass{label("public.people", "email", "UNCLASSIFIED")}},
		"FREE_TEXT set":            {Tables: picked, ColumnClasses: []localsetup.ColumnClass{label("public.people", "email", "FREE_TEXT")}},
		"identifier no entity":     {Tables: picked, ColumnClasses: []localsetup.ColumnClass{label("public.people", "email", "IDENTIFIER")}},
		"no column":                {Tables: picked, ColumnClasses: []localsetup.ColumnClass{label("public.people", "", "SECRET")}},
	}
	many := make([]localsetup.ColumnClass, 501)
	for i := range many {
		many[i] = label("public.people", "c"+strings.Repeat("x", i%7)+strings.Repeat("y", i/7), "SECRET")
	}
	cases["more than 500"] = localsetup.Request{Tables: picked, ColumnClasses: many}
	cases["labels on the sample database"] = localsetup.Request{Demo: true, RestPublic: true}
	cases["a trustRoot on the sample database"] = localsetup.Request{Demo: true, TrustRoot: strings.Repeat("a", 64)}
	for name, extra := range cases {
		req := localsetup.Request{
			Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: unusedAdminURL,
			Demo: extra.Demo, TrustRoot: extra.TrustRoot, Tables: extra.Tables, ColumnClasses: extra.ColumnClasses, RestPublic: extra.RestPublic,
		}
		_, err := svc.Check(context.Background(), req)
		var r *localsetup.RefusalError
		require.True(t, errors.As(err, &r), name)
		require.Equal(t, localsetup.CodeAnswersInvalid, r.Code, name+": "+r.Message)
	}
}

func TestRealInstallListsColumnsWithSuggestionsAndWritesTheLabels(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.people (id bigint PRIMARY KEY, email text, nickname text);
INSERT INTO public.people SELECT g, 'person' || g || '@example.com', 'n' || g FROM generate_series(1, 30) g`)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.people", Access: localsetup.AccessWrite}}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.Len(t, checked.Columns, 3)
	by := map[string]localsetup.ColumnInfo{}
	for _, c := range checked.Columns {
		by[c.Column] = c
		require.Equal(t, "UNCLASSIFIED", c.Class, "a database with no guard has no class")
	}
	require.Equal(t, "IDENTIFIER", by["email"].SuggestedClass)
	require.Equal(t, "EMAIL", by["email"].SuggestedEntityType)
	require.NotEmpty(t, by["email"].Reason)
	raw, err := json.Marshal(checked)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "person1@example.com", "no sampled value reaches the answer")

	// The labels go in the challenge: the passkey made for no labels does not
	// fit labels, and a check with them issues its own.
	req.ColumnClasses = []localsetup.ColumnClass{{Table: "public.people", Column: "email", Class: "IDENTIFIER", EntityType: "EMAIL", Was: localsetup.Label{Class: "UNCLASSIFIED"}}}
	req.RestPublic = true
	other := req
	other.Challenge, other.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, other)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	labeled, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.Contains(t, labeled.SQL, "column labels")
	changed := req
	changed.RestPublic = false
	changed.Challenge, changed.Passkey = labeled.Challenge, register(t, *labeled.Challenge)
	_, err = f.svc.Run(ctx, changed)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	// A column that is no longer unclassified when the page saw it: nothing changes.
	stale := req
	stale.ColumnClasses = []localsetup.ColumnClass{{Table: "public.people", Column: "email", Class: "SECRET", Was: localsetup.Label{Class: "PUBLIC"}}}
	staleChecked, err := f.svc.Check(ctx, stale)
	require.NoError(t, err)
	stale.Challenge, stale.Passkey = staleChecked.Challenge, register(t, *staleChecked.Challenge)
	_, err = f.svc.Run(ctx, stale)
	refusal(t, err, localsetup.CodeClassesChanged)
	require.False(t, exists(t, f.db, "basalt_meta"))

	req.Challenge, req.Passkey = labeled.Challenge, register(t, *labeled.Challenge)
	done, err := f.svc.Run(ctx, req)
	require.NoError(t, err)
	require.Equal(t, []string{"agent bot ready: 1 tables it can change, 0 it can read", "3 columns labeled"}, done.Lines)
	rows, err := f.db.Admin.Query(ctx, `SELECT column_name::text, class::text, coalesce(entity_type::text, '') FROM basalt_meta.pii_columns
		WHERE table_name = 'people' ORDER BY column_name`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([3]string, error) {
		var v [3]string
		return v, r.Scan(&v[0], &v[1], &v[2])
	})
	require.NoError(t, err)
	require.Equal(t, [][3]string{{"email", "IDENTIFIER", "EMAIL"}, {"id", "PUBLIC", ""}, {"nickname", "PUBLIC", ""}}, got)
}

func TestRealInstallColumnsWithoutASampleStillAnswer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.people (id bigint PRIMARY KEY, email text, nickname text)`)
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix,
		Now: func() time.Time { return f.now },
		SampleColumn: func(_ context.Context, _ *pgx.Conn, col classify.Column) (classify.Sample, error) {
			if col.Name == "email" {
				return classify.Sample{}, errors.New("the connection failed")
			}
			return classify.Sample{Unavailable: classify.UnavailableTimeout}, nil
		},
	})
	require.NoError(t, err)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.people", Access: localsetup.AccessWrite}}
	checked, err := svc.Check(ctx, req)
	require.NoError(t, err, "a sample that fails or times out is not an error of the check")
	require.Len(t, checked.Columns, 3)
	for _, c := range checked.Columns {
		require.Empty(t, c.SuggestedClass, c.Column)
		require.Empty(t, c.Reason, c.Column)
		require.Equal(t, "UNCLASSIFIED", c.Class)
	}
}

func TestRealInstallFailsTheCheckWhenTheColumnsCannotBeRead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.people (id bigint PRIMARY KEY, email text)`)
	f.db.Init(t, guard.AgentSpec{Name: "first", Password: guard.NewPassword(), CreateOnly: true})
	f.db.Exec(t, `REVOKE ALL ON basalt_meta.pii_columns FROM `+f.db.Names.Guard())
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.people", Access: localsetup.AccessRead}}
	req.RestPublic = true
	_, err := f.svc.Check(ctx, req)
	refusal(t, err, localsetup.CodeSetupFailed)
}

// pinFixture is an install whose admin connection first fails on the
// certificate, a chain a test CA signed, and then logs in only through the
// pin it is given.
type pinFixture struct {
	*fixture
	svc        *localsetup.Service
	ca         *x509.Certificate
	adminURL   string
	pinnedWith []*trustprofile.Profile
	pinnedDSNs []string
	profiles   func() *trustprofile.Set
}

const pinHost = "db.pin.example"

func newPinFixture(t *testing.T) *pinFixture {
	t.Helper()
	f := newFixture(t)
	ca, leaf := trustprofiletest.Chain(t, pinHost)
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)
	p := &pinFixture{fixture: f, ca: ca, adminURL: "postgres://admin:" + mustPassword(t, f.db.URL) + "@" + pinHost + ":5432/app"}
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix,
		Now: func() time.Time { return f.now },
		Dial: func(context.Context, string) (*pgx.Conn, error) {
			return nil, x509.UnknownAuthorityError{}
		},
		Profiles: func() *trustprofile.Set {
			if p.profiles != nil {
				return p.profiles()
			}
			return trustprofile.NewSet(nil, nil, nil)
		},
		DialPinned: func(ctx context.Context, dsn string, pin *trustprofile.Profile) (*pgx.Conn, error) {
			p.pinnedWith = append(p.pinnedWith, pin)
			p.pinnedDSNs = append(p.pinnedDSNs, dsn)
			return pgdial.Connect(ctx, f.db.URL)
		},
		Probe: func(_ context.Context, host string, _ int) ([]*x509.Certificate, error) {
			require.Equal(t, pinHost, host)
			return []*x509.Certificate{leafCert, ca}, nil
		},
	})
	require.NoError(t, err)
	p.svc = svc
	return p
}

func (p *pinFixture) req() localsetup.Request {
	r := p.real()
	r.DatabaseURL = p.adminURL
	r.Tables = []localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessRead}}
	return r
}

func TestRealInstallOffersAnUnknownAuthorityAndRefusesAnyOtherTrustRoot(t *testing.T) {
	t.Parallel()
	p := newPinFixture(t)
	ctx := context.Background()
	p.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)

	_, err := p.svc.Check(ctx, p.req())
	var r *localsetup.RefusalError
	require.True(t, errors.As(err, &r))
	require.Equal(t, localsetup.CodeCertificateNotVerified, r.Code)
	require.NotNil(t, r.TrustRoot)
	require.Equal(t, trustprofile.DERSHA256(p.ca), r.TrustRoot.SHA256)
	require.Equal(t, "CN=trustprofiletest root", r.TrustRoot.Subject)
	require.NotEmpty(t, r.TrustRoot.ExpiresAt)
	require.Empty(t, p.pinnedWith, "no login before the person trusted it")

	for _, bad := range []string{"nothex", strings.Repeat("a", 64), strings.ToUpper(trustprofile.DERSHA256(p.ca))} {
		req := p.req()
		req.TrustRoot = bad
		_, err = p.svc.Check(ctx, req)
		refusal(t, err, localsetup.CodeTrustRootMismatch)
		req.Challenge = &localsetup.Challenge{ExpiresAt: p.now.Add(time.Hour)} // run reads the chain before it checks the binding
		_, err = p.svc.Run(ctx, req)
		refusal(t, err, localsetup.CodeTrustRootMismatch)
	}
	require.Empty(t, p.pinnedWith)
}

func TestRealInstallPinsTheTrustedAuthorityBeforeTheCommit(t *testing.T) {
	t.Parallel()
	p := newPinFixture(t)
	ctx := context.Background()
	p.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	req := p.req()
	req.TrustRoot = trustprofile.DERSHA256(p.ca)

	checked, err := p.svc.Check(ctx, req)
	require.NoError(t, err)
	require.Len(t, p.pinnedWith, 1)
	require.Equal(t, pinHost, checked.Host, "the confirm step names the string's host")
	require.Equal(t, 5432, checked.Port)
	require.Equal(t, "pin-db-pin-example", p.pinnedWith[0].Name, "the login trusts that one certificate")
	require.Contains(t, strings.Join(checked.Lines, " "), trustprofile.DERSHA256(p.ca))

	// The trustRoot is bound to the challenge.
	// Without it the database's certificate does not verify: the person is
	// offered it again, and nothing is pinned.
	other := req
	other.TrustRoot = ""
	other.Challenge, other.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = p.svc.Run(ctx, other)
	refusal(t, err, localsetup.CodeCertificateNotVerified)
	_, statErr := os.Stat(filepath.Join(filepath.Dir(p.config), "trust.d"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "nothing is pinned by a refused run")

	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = p.svc.Run(ctx, req)
	require.NoError(t, err)

	trustD := filepath.Join(filepath.Dir(p.config), "trust.d")
	entries, err := os.ReadDir(trustD)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Contains(t, names, "pin-db-pin-example.json")
	dsn, err := config.ReadCredential(filepath.Join(filepath.Dir(p.config), "agents", "bot.url"))
	require.NoError(t, err)
	require.Contains(t, dsn, "sslmode=verify-full", "the pin applies with verify-full only")
	var recorded int
	require.NoError(t, p.db.Admin.QueryRow(ctx, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED' AND detail ->> 'sha256' = $1`,
		trustprofile.DERSHA256(p.ca)).Scan(&recorded))
	require.Equal(t, 1, recorded, "the pin is recorded in the ledger")
}

func TestRealInstallRollsBackWhenTheHostIsCoveredByAnotherProfile(t *testing.T) {
	t.Parallel()
	p := newPinFixture(t)
	ctx := context.Background()
	p.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	req := p.req()
	req.TrustRoot = trustprofile.DERSHA256(p.ca)
	checked, err := p.svc.Check(ctx, req)
	require.NoError(t, err)
	// Another pin for the host appears between the check and the run.
	other, _ := trustprofiletest.Chain(t, pinHost)
	_, err = trustdir.PinNew(p.config, pinHost, other, false)
	require.NoError(t, err)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = p.svc.Run(ctx, req)
	refusal(t, err, localsetup.CodeSetupFailed)
	require.False(t, exists(t, p.db, "basalt_meta"), "the whole install rolled back")
	_, statErr := os.Stat(filepath.Join(filepath.Dir(p.config), "agents", "bot.url"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
	_, statErr = os.Stat(p.config)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestRealInstallBindsTheTrustRootToTheChallenge(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessRead}}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	req.TrustRoot = strings.Repeat("a", 64) // ignored: the certificate verifies without it, but it is bound
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	refusal(t, err, localsetup.CodeChallengeInvalid)
}

func TestRealInstallPinsOnVerifyFullWhateverModeTheStringNames(t *testing.T) {
	t.Parallel()
	p := newPinFixture(t)
	ctx := context.Background()
	p.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	req := p.req()
	req.DatabaseURL += "?sslmode=verify-ca"
	req.TrustRoot = trustprofile.DERSHA256(p.ca)
	checked, err := p.svc.Check(ctx, req)
	require.NoError(t, err)
	require.Len(t, p.pinnedDSNs, 1)
	require.Contains(t, p.pinnedDSNs[0], "sslmode=verify-full")
	require.NotContains(t, p.pinnedDSNs[0], "sslrootcert", "the pin is the root")
	require.NotContains(t, p.pinnedDSNs[0], "verify-ca")

	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = p.svc.Run(ctx, req)
	require.NoError(t, err)
	dsn, err := config.ReadCredential(filepath.Join(filepath.Dir(p.config), "agents", "bot.url"))
	require.NoError(t, err)
	require.Contains(t, dsn, "sslmode=verify-full")
	require.NotContains(t, dsn, "sslrootcert", "the agent's credential cannot name another root than the pin")
	require.NotContains(t, dsn, "verify-ca")
}

func TestRealInstallARunAfterAFailedCommitRecordsThePinAgain(t *testing.T) {
	t.Parallel()
	p := newPinFixture(t)
	ctx := context.Background()
	p.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	sha := trustprofile.DERSHA256(p.ca)
	// The pin a failed run left in trust.d, whose ledger record was rolled back.
	_, err := trustdir.PinNew(p.config, pinHost, p.ca, false)
	require.NoError(t, err)
	p.profiles = func() *trustprofile.Set { return trustdir.Set(p.config) }
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: p.config, Origin: origin, Users: fakeUsers{}, Prefix: p.db.Names.Prefix,
		Now:      func() time.Time { return p.now },
		Dial:     func(ctx context.Context, _ string) (*pgx.Conn, error) { return pgdial.Connect(ctx, p.db.URL) }, // verifies through the pin
		Profiles: func() *trustprofile.Set { return trustdir.Set(p.config) },
	})
	require.NoError(t, err)
	req := p.req()
	req.TrustRoot = sha
	checked, err := svc.Check(ctx, req)
	require.NoError(t, err)
	require.Contains(t, strings.Join(checked.Lines, " "), sha)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = svc.Run(ctx, req)
	require.NoError(t, err)
	var recorded int
	require.NoError(t, p.db.Admin.QueryRow(ctx, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED' AND detail ->> 'sha256' = $1`, sha).Scan(&recorded))
	require.Equal(t, 1, recorded)

	// Another trustRoot is not the pin that is there: nothing is recorded for it.
	other := p.req()
	other.TrustRoot = strings.Repeat("b", 64)
	_, err = svc.Check(ctx, other)
	require.Error(t, err, "the engine already has a config now")
}

// cutOnCommit is a connection that dies when the commit is sent: the
// server's answer is never read, so the outcome is unknown.
type cutOnCommit struct{ net.Conn }

func (c cutOnCommit) Write(b []byte) (int, error) {
	// A simple query message: 'Q', its length, then the text.
	if len(b) > 5 && b[0] == 'Q' && bytes.Equal(bytes.ToLower(b[5:]), []byte("commit\x00")) {
		_ = c.Close()
		return 0, errors.New("the connection was cut")
	}
	return c.Conn.Write(b)
}

func TestRealInstallKeepsTheCredentialWhenTheCommitOutcomeIsUnknown(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	cut := true
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix,
		Now: func() time.Time { return f.now },
		Dial: func(ctx context.Context, dsn string) (*pgx.Conn, error) {
			cfg, err := pgdial.ConnConfig(dsn)
			if err != nil {
				return nil, err
			}
			if cut {
				cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
					c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
					return cutOnCommit{c}, err
				}
			}
			return pgx.ConnectConfig(ctx, cfg)
		},
	})
	require.NoError(t, err)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessRead}}
	checked, err := svc.Check(ctx, req)
	require.NoError(t, err)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = svc.Run(ctx, req)
	var r *localsetup.RefusalError
	require.True(t, errors.As(err, &r))
	require.Equal(t, localsetup.CodeSetupFailed, r.Code)
	require.Contains(t, r.Message, "did not confirm")
	cred := filepath.Join(filepath.Dir(f.config), "agents", "bot.url")
	_, statErr := os.Stat(cred)
	require.NoError(t, statErr, "the credential of a role that may exist stays")

	// A run again, now that the connection holds: it overwrites the file, the
	// role was never made.
	cut = false
	checked, err = svc.Check(ctx, req)
	require.NoError(t, err)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = svc.Run(ctx, req)
	require.NoError(t, err)
	_, err = config.ReadCredential(cred)
	require.NoError(t, err)
}

func TestRealInstallDeletesTheCredentialWhenTheCommitKnownlyFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.db.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY)`)
	f.db.Init(t, guard.AgentSpec{Name: "first", Password: guard.NewPassword(), CreateOnly: true})
	// A deferred constraint that fails when the transaction commits.
	f.db.Exec(t, `CREATE FUNCTION public.refuse_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused at commit'; END $$;
CREATE CONSTRAINT TRIGGER refuse_at_commit AFTER INSERT ON basalt_meta.passkeys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.refuse_at_commit()`)
	req := f.real()
	req.Tables = []localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessRead}}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	var r *localsetup.RefusalError
	require.True(t, errors.As(err, &r))
	require.Equal(t, localsetup.CodeSetupFailed, r.Code)
	require.NotContains(t, r.Message, "did not confirm", "the server answered: the failure is known")
	_, statErr := os.Stat(filepath.Join(filepath.Dir(f.config), "agents", "bot.url"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the credential of a role that was rolled back is removed")
}

func TestInstallRefusesADatabaseNameToConfirm(t *testing.T) {
	t.Parallel()
	svc, err := localsetup.New(localsetup.Options{ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: origin, Users: fakeUsers{}, Prefix: "basalt"})
	require.NoError(t, err)
	req := localsetup.Request{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: "alice", Demo: true, DatabaseURL: unusedAdminURL, ConfirmName: "app"}
	_, err = svc.Check(context.Background(), req)
	refusal(t, err, localsetup.CodeAnswersInvalid)
}
