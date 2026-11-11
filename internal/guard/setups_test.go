package guard_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

const (
	setupLifetime = 24 * time.Hour
	setupSkew     = 5 * time.Minute
)

// uuidAt is a UUIDv7 whose time is at (milliseconds).
func uuidAt(t *testing.T, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(at.UnixMilli()))
	copy(id[:6], ms[2:])
	return id
}

func dbNow(t *testing.T, d *guardtest.DB) time.Time {
	t.Helper()
	return scalarOf[time.Time](t, d.Admin, `SELECT now()`)
}

// installSetup is an INSTALL setup made now by the database's clock.
func installSetup(t *testing.T, d *guardtest.DB, agent string) guard.Setup {
	t.Helper()
	now := dbNow(t, d)
	return guard.Setup{ID: uuidAt(t, now), Kind: guard.SetupInstall, Agent: agent,
		GuardVersion: guard.LatestVersion(), ExpiresAt: now.Add(setupLifetime).Truncate(time.Second)}
}

// initFromVerifier installs the guard and the agent bot from a verifier
// (an INSTALL setup code) and returns the password it was made from.
func initFromVerifier(t *testing.T, d *guardtest.DB) string {
	const name = "bot"
	t.Helper()
	pw := guard.NewPassword()
	d.Init(t, guard.AgentSpec{Name: name, Verifier: guardtest.NewSCRAMVerifier(t, pw), CreateOnly: true, Write: leads, Read: leads})
	return pw
}

func connectAs(ctx context.Context, d *guardtest.DB, name, password string) (*pgx.Conn, error) {
	role, err := d.Names.Agent(name)
	if err != nil {
		return nil, err
	}
	dsn, err := guard.AgentConnString(d.URL, role, password)
	if err != nil {
		return nil, err
	}
	return pgdial.Connect(ctx, dsn)
}

// requireLogin connects as the agent bot with password.
func requireLogin(t *testing.T, d *guardtest.DB, password string) *pgx.Conn {
	const name = "bot"
	t.Helper()
	c, err := connectAs(context.Background(), d, name, password)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func requireNoLogin(t *testing.T, d *guardtest.DB, name, password string) {
	t.Helper()
	c, err := connectAs(context.Background(), d, name, password)
	if err == nil {
		_ = c.Close(context.Background())
	}
	require.Equal(t, "28P01", guardtest.SQLState(err), "login must fail: %v", err)
}

func requireRefused(t *testing.T, err error, reason string) {
	t.Helper()
	requireCode(t, err, guard.CodeSetupRefused)
	got, ok := guard.SetupRefusal(err)
	require.True(t, ok)
	require.Equal(t, reason, got)
}

func TestSCRAMVerifierMatchesFixtures(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "mcp", "setup", "setup-code.fixtures.json"))
	require.NoError(t, err)
	var f struct {
		Verifiers []struct{ Password, Salt, Verifier string }
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Verifiers)
	for _, v := range f.Verifiers {
		salt, err := base64.StdEncoding.DecodeString(v.Salt)
		require.NoError(t, err)
		require.Equal(t, v.Verifier, guardtest.SCRAMVerifier(t, v.Password, salt))
		require.NoError(t, guard.CheckVerifier(v.Verifier))
	}
}

func TestCheckVerifier(t *testing.T) {
	t.Parallel()
	good := "SCRAM-SHA-256$4096:AQIDBAUGBwgJCgsMDQ4PEA==$y4XxY/znpvDP+WkJoPXFiQaG/KsJlTqLo8hZGlCuoO8=:g5lYDnJ4WoMr46iWhyqYncaDdRco7Mzv1FygHOyoh/E="
	require.NoError(t, guard.CheckVerifier(good))
	for name, v := range map[string]string{
		"empty":             "",
		"plaintext":         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"md5":               "md5a3556571e93b0d20722ba62be61e8c2d",
		"other iterations":  strings.Replace(good, "$4096:", "$8192:", 1),
		"short salt":        strings.Replace(good, "AQIDBAUGBwgJCgsMDQ4PEA==", "AQIDBAUGBwgJCgsMDQ4P", 1),
		"a quote":           strings.Replace(good, "y4Xx", "y4'x", 1),
		"trailing newline":  good + "\n",
		"non-canonical pad": strings.Replace(good, "DQ4PEA==", "DQ4PEB==", 1),
	} {
		require.ErrorIs(t, guard.CheckVerifier(v), guard.ErrInvalidAgent, name)
	}
}

func TestPlanInitRefusesBadVerifierSpecs(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	v := guardtest.NewSCRAMVerifier(t, guard.NewPassword())
	for name, spec := range map[string]guard.AgentSpec{
		"password and verifier": {Name: "bot", Password: guard.NewPassword(), Verifier: v, Write: leads},
		"plaintext as verifier": {Name: "bot", Verifier: guard.NewPassword(), Write: leads},
		"create without either": {Name: "bot", CreateOnly: true, Write: leads},
	} {
		_, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names, Agent: spec})
		require.ErrorIs(t, err, guard.ErrInvalidAgent, name)
	}
}

func TestAgentLogsInWithVerifierPassword(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	pw := guard.NewPassword()
	verifier := guardtest.NewSCRAMVerifier(t, pw)

	s, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names,
		Agent: guard.AgentSpec{Name: "bot", Verifier: verifier, CreateOnly: true, Write: leads, Read: leads}})
	require.NoError(t, err)
	shown := s.SQL()
	require.Contains(t, shown, "PASSWORD '"+verifier+"'", "the person reads the verifier")
	require.NotContains(t, shown, pw)
	require.NotContains(t, shown, "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '"+d.Names.Prefix+"_agent_bot')",
		"INSTALL creates the role with a plain CREATE ROLE")
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return s.Apply(ctx, tx) }))

	// Postgres stored the verifier as given, so the bot's password logs in
	// and nothing else does.
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	require.Equal(t, verifier, scalarOf[string](t, d.Admin, `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, role))
	bot := requireLogin(t, d, pw)
	require.Equal(t, 200, count(t, bot, `SELECT count(id)::int FROM public.leads`))
	requireNoLogin(t, d, "bot", guard.NewPassword())

	// An AGENT code with a verifier rotates the password.
	pw2 := guard.NewPassword()
	d.Init(t, guard.AgentSpec{Name: "bot", Verifier: guardtest.NewSCRAMVerifier(t, pw2), Write: leads, Read: leads})
	requireLogin(t, d, pw2)
	requireNoLogin(t, d, "bot", pw)
}

func TestInstallVerifierRefusesExistingRole(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)

	// ROLE_EXISTS, enforced in Postgres: CREATE ROLE fails, nothing changes.
	err := d.TryInit(guard.AgentSpec{Name: "bot", Verifier: guardtest.NewSCRAMVerifier(t, guard.NewPassword()),
		CreateOnly: true, Write: leads, Read: leads})
	require.Equal(t, "42710", guardtest.SQLState(err), "%v", err)
	requireLogin(t, d, a.Password)

	// ROLE_MISSING: an AGENT verifier for a role that does not exist.
	err = d.TryInit(guard.AgentSpec{Name: "other", Verifier: guardtest.NewSCRAMVerifier(t, guard.NewPassword()),
		Write: leads, Read: leads})
	require.Equal(t, "42704", guardtest.SQLState(err), "%v", err)
	exists, err := guard.AgentRoleExists(context.Background(), d.Admin, d.Names, "other")
	require.NoError(t, err)
	require.False(t, exists)
}

func TestRecordSetup(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	pw := initFromVerifier(t, d)
	s := installSetup(t, d, "bot")

	seq, err := guard.RecordSetup(ctx, d.Admin, d.Names, s)
	require.NoError(t, err)
	require.Positive(t, seq)

	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	var detail map[string]any
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT detail FROM basalt_meta.ledger
		WHERE seq = $1 AND kind = 'AGENT_SETUP' AND agent = $2`, seq, role).Scan(&detail))
	admin := scalarOf[string](t, d.Admin, `SELECT session_user::text`)
	require.Equal(t, map[string]any{"setupId": s.ID.String(), "kind": "INSTALL",
		"guardVersion": float64(guard.LatestVersion()), "by": admin}, detail)
	require.Zero(t, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE detail::text LIKE '%SCRAM%'`),
		"the ledger never holds a verifier")
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))

	var kind, usedBy string
	var guardVersion int
	var agentRole *string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT kind, agent_role::text, guard_version, used_by::text
		FROM basalt_meta.setups WHERE setup_id = $1`, s.ID).Scan(&kind, &agentRole, &guardVersion, &usedBy))
	require.Equal(t, "INSTALL", kind)
	require.Equal(t, role, *agentRole)
	require.Equal(t, guard.LatestVersion(), guardVersion)
	require.Equal(t, admin, usedBy)

	// The engine confirms the setup by logging in and finding it.
	bot := requireLogin(t, d, pw)
	require.Equal(t, 1, count(t, bot, `SELECT count(setup_id)::int FROM basalt_meta.agent_setups WHERE setup_id = $1`, s.ID))

	// An UPGRADE is recorded under the admin's name.
	now := dbNow(t, d)
	up := guard.Setup{ID: uuidAt(t, now), Kind: guard.SetupUpgrade, GuardVersion: guard.LatestVersion(), ExpiresAt: now.Add(time.Hour)}
	seq, err = guard.RecordSetup(ctx, d.Admin, d.Names, up)
	require.NoError(t, err)
	require.Equal(t, admin, scalarOf[string](t, d.Admin, `SELECT agent::text FROM basalt_meta.ledger WHERE seq = $1`, seq))
}

func TestRecordSetupRefusals(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	initFromVerifier(t, d)
	record := func(s guard.Setup) error {
		_, err := guard.RecordSetup(ctx, d.Admin, d.Names, s)
		return err
	}

	t.Run("used", func(t *testing.T) {
		s := installSetup(t, d, "bot")
		require.NoError(t, record(s))
		requireRefused(t, record(s), guard.SetupUsed)
	})
	t.Run("superseded", func(t *testing.T) {
		old := installSetup(t, d, "bot")
		newer := installSetup(t, d, "bot")
		newer.Kind = guard.SetupAgent
		newer.ID = uuidAt(t, dbNow(t, d).Add(time.Second))
		require.NoError(t, record(newer))
		requireRefused(t, record(old), guard.SetupSuperseded)
		// An UPGRADE is never superseded, and supersedes nothing.
		up := old
		up.Kind, up.Agent = guard.SetupUpgrade, ""
		require.NoError(t, record(up))
	})
	t.Run("expired", func(t *testing.T) {
		now := dbNow(t, d)
		s := guard.Setup{ID: uuidAt(t, now.Add(-2*time.Hour)), Kind: guard.SetupUpgrade,
			GuardVersion: guard.LatestVersion(), ExpiresAt: now.Add(-time.Second)}
		requireRefused(t, record(s), guard.SetupExpired)
		// Expiry has no skew: a code is expired from expiresAt on.
		s.ExpiresAt = now
		requireRefused(t, record(s), guard.SetupExpired)
	})
	t.Run("setup id in the future", func(t *testing.T) {
		now := dbNow(t, d)
		s := guard.Setup{ID: uuidAt(t, now.Add(setupSkew+time.Minute)), Kind: guard.SetupUpgrade,
			GuardVersion: guard.LatestVersion(), ExpiresAt: now.Add(time.Hour)}
		requireRefused(t, record(s), guard.SetupIDInFuture)
		// Within the skew it passes.
		s.ID = uuidAt(t, now.Add(setupSkew-time.Minute))
		require.NoError(t, record(s))
	})
	t.Run("expiry too far", func(t *testing.T) {
		now := dbNow(t, d).Truncate(time.Millisecond) // the setup id's precision
		s := guard.Setup{ID: uuidAt(t, now), Kind: guard.SetupUpgrade, GuardVersion: guard.LatestVersion(),
			ExpiresAt: now.Add(setupLifetime + setupSkew + time.Minute)}
		requireRefused(t, record(s), guard.SetupExpiryTooFar)
		// More than 24 hours after the setup id's time, though near now.
		s.ID = uuidAt(t, now.Add(-2*time.Hour))
		s.ExpiresAt = now.Add(setupLifetime - time.Hour)
		requireRefused(t, record(s), guard.SetupExpiryTooFar)
		s.ExpiresAt = now.Add(setupLifetime - 2*time.Hour)
		require.NoError(t, record(s))
	})
	t.Run("invalid input", func(t *testing.T) {
		now := dbNow(t, d)
		base := guard.Setup{ID: uuidAt(t, now), Kind: guard.SetupInstall, Agent: "bot",
			GuardVersion: guard.LatestVersion(), ExpiresAt: now.Add(time.Hour)}
		d.Exec(t, `CREATE ROLE `+d.Names.Prefix+`_agent_stranger NOLOGIN`)
		for name, mutate := range map[string]func(*guard.Setup){
			"no agent for INSTALL":       func(s *guard.Setup) { s.Agent = "" },
			"an agent for UPGRADE":       func(s *guard.Setup) { s.Kind = guard.SetupUpgrade },
			"a role that is no agent":    func(s *guard.Setup) { s.Agent = "stranger" },
			"a role that does not exist": func(s *guard.Setup) { s.Agent = "ghost" },
			"an unknown kind":            func(s *guard.Setup) { s.Kind = "REINSTALL" },
			"no guard version":           func(s *guard.Setup) { s.GuardVersion = 0 },
			"not a UUIDv7":               func(s *guard.Setup) { s.ID = uuid.New() },
		} {
			t.Run(name, func(t *testing.T) {
				s := base
				mutate(&s)
				requireCode(t, record(s), guard.CodeLedgerInputInvalid)
			})
		}
	})
}

func TestAgentCannotRecordOrWriteSetups(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	pw := initFromVerifier(t, d)
	other := d.NewAgent(t, "other", leads, leads)
	bot := requireLogin(t, d, pw)

	mine := installSetup(t, d, "bot")
	_, err := guard.RecordSetup(ctx, d.Admin, d.Names, mine)
	require.NoError(t, err)
	theirs := installSetup(t, d, "other")
	theirs.Kind = guard.SetupAgent
	_, err = guard.RecordSetup(ctx, d.Admin, d.Names, theirs)
	require.NoError(t, err)
	now := dbNow(t, d)
	up := guard.Setup{ID: uuidAt(t, now), Kind: guard.SetupUpgrade, GuardVersion: guard.LatestVersion(), ExpiresAt: now.Add(time.Hour)}
	_, err = guard.RecordSetup(ctx, d.Admin, d.Names, up)
	require.NoError(t, err)

	// record_setup is the admin's: an agent cannot call it, for itself or
	// another agent.
	next := installSetup(t, d, "bot")
	next.ID = uuidAt(t, now.Add(time.Second))
	_, err = guard.RecordSetup(ctx, bot, d.Names, next)
	require.Equal(t, "42501", guardtest.SQLState(err), "%v", err)
	// Only the owner may execute it: no grant to PUBLIC or any other role.
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(1)::int FROM pg_proc p
		LEFT JOIN LATERAL aclexplode(p.proacl) a ON true
		WHERE p.pronamespace = 'basalt_meta'::regnamespace AND p.proname IN ('record_setup', '_setup_refused')
		  AND (p.proacl IS NULL OR a.grantee <> p.proowner)`))
	for _, sql := range []string{
		`SELECT setup_id FROM basalt_meta.setups`,
		`INSERT INTO basalt_meta.setups (setup_id, kind, guard_version, expires_at) VALUES ('` + next.ID.String() + `', 'UPGRADE', 1, now())`,
		`UPDATE basalt_meta.setups SET used_at = now()`,
		`DELETE FROM basalt_meta.setups`,
	} {
		_, err := bot.Exec(ctx, sql)
		require.Equal(t, "42501", guardtest.SQLState(err), sql)
	}

	// Each agent sees its own setups and every UPGRADE, nothing else.
	ids := func(c *pgx.Conn) []string {
		rows, err := c.Query(ctx, `SELECT setup_id::text FROM basalt_meta.agent_setups ORDER BY setup_id`)
		require.NoError(t, err)
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return got
	}
	require.ElementsMatch(t, []string{mine.ID.String(), up.ID.String()}, ids(bot))
	require.ElementsMatch(t, []string{theirs.ID.String(), up.ID.String()}, ids(other.Conn))
}

func TestSetupsMigrationIsIdempotentAndRemovable(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	pw := initFromVerifier(t, d)
	s := installSetup(t, d, "bot")
	_, err := guard.RecordSetup(ctx, d.Admin, d.Names, s)
	require.NoError(t, err)

	// Running version 16 again keeps the rows and the checks.
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version >= 16`)
	d.Init(t, guard.AgentSpec{Name: "bot", Write: leads, Read: leads})
	bot := requireLogin(t, d, pw)
	require.Equal(t, 1, count(t, bot, `SELECT count(setup_id)::int FROM basalt_meta.agent_setups`))
	_, err = guard.RecordSetup(ctx, d.Admin, d.Names, s)
	requireRefused(t, err, guard.SetupUsed)

	require.NoError(t, bot.Close(ctx))
	d.Exec(t, `DROP SCHEMA basalt_meta CASCADE`)
	require.Zero(t, count(t, d.Admin, `SELECT ((SELECT count(1) FROM pg_class WHERE relname LIKE '%setups%')
		+ (SELECT count(1) FROM pg_proc WHERE proname IN ('record_setup', '_setup_refused')))::int`))
}
