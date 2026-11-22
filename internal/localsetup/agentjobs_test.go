package localsetup_test

import (
	"context"
	"fmt"
	"os"
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
)

// installed is a fixture after a first install from the page, with the
// setup of the engine that now runs with that config.
func installed(t *testing.T) (*fixture, *localsetup.Service) {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	req := f.request()
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true,
		Now: func() time.Time { return f.now },
	})
	require.NoError(t, err)
	return f, svc
}

func (f *fixture) agentJob(job string) localsetup.Request {
	return localsetup.Request{Job: job, Agent: "demo_bot", OSUser: "alice", DatabaseURL: f.db.URL}
}

// removeRun is a REMOVE run with the database's name typed, as the page
// sends it.
func (f *fixture) removeRun(t *testing.T) localsetup.Request {
	t.Helper()
	req := f.agentJob(localsetup.JobRemove)
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT pg_catalog.current_database()::text`).Scan(&req.ConfirmName))
	return req
}

func TestRemoveRunsOnlyWithTheDatabaseNameTyped(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	right := f.removeRun(t)
	for _, typed := range []string{"", "not_it", strings.ToUpper(right.ConfirmName), right.ConfirmName + " ", strings.Repeat("a", 64)} {
		req := f.agentJob(localsetup.JobRemove)
		req.ConfirmName = typed
		_, err := svc.Run(ctx, req)
		require.Error(t, err, "typed %q", typed)
		refusal(t, err, localsetup.CodeAnswersInvalid)
	}
	require.True(t, exists(t, f.db, "basalt_meta"), "nothing was removed")
	_, err := svc.Check(ctx, right)
	refusal(t, err, localsetup.CodeAnswersInvalid)
	update := f.agentJob(localsetup.JobUpdate)
	update.ConfirmName = right.ConfirmName
	_, err = svc.Run(ctx, update)
	refusal(t, err, localsetup.CodeAnswersInvalid)

	_, err = svc.Run(ctx, right)
	require.NoError(t, err)
	require.False(t, exists(t, f.db, "basalt_meta"))
}

func guardVersion(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	return v
}

func TestUpdateAddsOnlyTheMissingMigrations(t *testing.T) {
	f, svc := installed(t)
	ctx := context.Background()
	from := guardVersion(t, f.db)

	_, err := svc.Check(ctx, f.agentJob(localsetup.JobUpdate))
	refusal(t, err, localsetup.CodeGuardCurrent)

	next := guardtest.NextVersion(t, false)
	checked, err := svc.Check(ctx, f.agentJob(localsetup.JobUpdate))
	require.NoError(t, err)
	require.False(t, checked.PasskeyNeeded)
	require.Nil(t, checked.Challenge, "an update registers no passkey")
	require.Contains(t, checked.SQL, fmt.Sprintf("upgrade_probe_v%d", next))
	require.NotContains(t, strings.ToUpper(checked.SQL), "PASSWORD", "an update rotates no password")
	require.Contains(t, checked.Lines[0], fmt.Sprintf("from version %d to %d", from, next))
	require.Equal(t, from, guardVersion(t, f.db), "check changes nothing")

	done, err := svc.Run(ctx, f.agentJob(localsetup.JobUpdate))
	require.NoError(t, err)
	require.Equal(t, next, guardVersion(t, f.db))
	require.Equal(t, "basalt mcp --agent demo_bot", done.MCPCommand)
	require.Empty(t, done.Passkeys)
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1, "an update leaves the engine's config as it is")

	_, err = svc.Run(ctx, f.agentJob(localsetup.JobUpdate))
	refusal(t, err, localsetup.CodeGuardCurrent)
}

func TestAgentJobsRefuseWhatIsNotTheAgentsBeforeConnecting(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		edit func(*localsetup.Request)
		code string
	}{
		"an install":      {func(r *localsetup.Request) { r.Job = localsetup.JobInstall }, localsetup.CodeJobUnavailable},
		"a change link":   {func(r *localsetup.Request) { r.Job = localsetup.JobChange }, localsetup.CodeInvalidArgument},
		"no job":          {func(r *localsetup.Request) { r.Job = "" }, localsetup.CodeJobUnavailable},
		"another agent":   {func(r *localsetup.Request) { r.Agent = "other_bot" }, localsetup.CodeInvalidArgument},
		"another OS user": {func(r *localsetup.Request) { r.OSUser = "carol" }, localsetup.CodeInvalidArgument},
		"the demo flag":   {func(r *localsetup.Request) { r.Demo = true }, localsetup.CodeInvalidArgument},
		"a passkey":       {func(r *localsetup.Request) { r.Passkey = &localsetup.Passkey{} }, localsetup.CodeAnswersInvalid},
		"schemas":         {func(r *localsetup.Request) { r.Schemas = []string{"public"} }, localsetup.CodeAnswersInvalid},
		"tables":          {func(r *localsetup.Request) { r.Tables = []localsetup.TablePick{{Table: "public.a", Access: "READ"}} }, localsetup.CodeAnswersInvalid},
		"column labels": {func(r *localsetup.Request) {
			r.ColumnClasses = []localsetup.ColumnClass{{Table: "public.a", Column: "b"}}
		}, localsetup.CodeAnswersInvalid},
		"restPublic":       {func(r *localsetup.Request) { r.RestPublic = true }, localsetup.CodeAnswersInvalid},
		"no admin string":  {func(r *localsetup.Request) { r.DatabaseURL = "" }, localsetup.CodeConnectionStringRefused},
		"another database": {func(r *localsetup.Request) { r.DatabaseURL = unusedAdminURL }, localsetup.CodeTargetMismatch},
	} {
		for _, job := range []string{localsetup.JobUpdate, localsetup.JobRemove} {
			req := f.agentJob(job)
			tc.edit(&req)
			_, err := svc.Check(ctx, req)
			refusal(t, err, tc.code)
			_, err = svc.Run(ctx, req)
			refusal(t, err, tc.code)
			if err != nil {
				require.NotContains(t, err.Error(), "admin"+":", name)
			}
		}
	}
	require.True(t, exists(t, f.db, "basalt_meta"), "nothing was removed")
}

func TestAgentJobsNeedAnEngineWithAConfig(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, job := range []string{localsetup.JobUpdate, localsetup.JobRemove} {
		_, err := f.svc.Check(context.Background(), f.agentJob(job))
		refusal(t, err, localsetup.CodeJobUnavailable)
	}
}

func TestRemoveDropsBasaltAndForgetsTheAgent(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	cred := filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url")

	checked, err := svc.Check(ctx, f.agentJob(localsetup.JobRemove))
	require.NoError(t, err)
	require.Nil(t, checked.Challenge)
	require.Contains(t, checked.SQL, "DROP SCHEMA IF EXISTS basalt_meta CASCADE;")
	require.Contains(t, checked.SQL, "DROP TABLE basalt_demo.leads;")
	require.Contains(t, checked.SQL, "DROP ROLE ")
	require.NotContains(t, checked.SQL, "basalt_demo CASCADE", "the sample schema is dropped without CASCADE")
	require.True(t, exists(t, f.db, "basalt_meta"), "check changes nothing")
	require.True(t, exists(t, f.db, "basalt_demo"), "check changes nothing")

	done, err := svc.Run(ctx, f.removeRun(t))
	require.NoError(t, err)
	require.Contains(t, done.Lines, "removed from this engine: demo_bot")
	require.Empty(t, done.MCPCommand)
	require.False(t, exists(t, f.db, "basalt_meta"))
	require.False(t, exists(t, f.db, "basalt_demo"))
	var roles int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT count(*)::int FROM pg_catalog.pg_roles WHERE starts_with(rolname, $1)`,
		f.db.Names.Prefix+"_").Scan(&roles))
	require.Zero(t, roles, "every role of the prefix is dropped")
	_, err = os.Stat(f.config)
	require.ErrorIs(t, err, os.ErrNotExist, "the engine's last agent is gone, and so is its config")
	_, err = os.Stat(cred)
	require.ErrorIs(t, err, os.ErrNotExist, "the agent's credential is deleted")

	// The engine that ran with that config never installs: it loads a
	// config only at its start.
	_, err = svc.Check(ctx, f.request())
	refusal(t, err, localsetup.CodeJobUnavailable)
}

func TestRemoveKeepsOtherAgentsOfTheEngine(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	// An agent of another database on the same engine.
	other := guardtest.New(t)
	otherCred := filepath.Join(filepath.Dir(f.config), "agents", "other_bot.url")
	require.NoError(t, config.WriteFile(otherCred, []byte(other.URL+"\n")))
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	a := cfg.Agents[0]
	a.Name, a.Store = "other_bot", config.PostgresStore(otherCred)
	require.NoError(t, config.UpdateConfig(f.config, config.Change{Apply: func(c *config.Config) error {
		c.Agents = append(c.Agents, a)
		return nil
	}}))

	_, err = svc.Run(ctx, f.removeRun(t))
	require.NoError(t, err)
	cfg, err = config.Load(f.config)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	require.Equal(t, "other_bot", cfg.Agents[0].Name)
	_, err = os.Stat(otherCred)
	require.NoError(t, err)
}

func TestRemoveFinishesOnADatabaseBasaltIsGoneFrom(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	// The database part of an earlier removal committed; the engine's
	// files were not changed.
	require.NoError(t, guard.Uninstall(ctx, f.db.Admin, f.db.Names))

	checked, err := svc.Check(ctx, f.agentJob(localsetup.JobRemove))
	require.NoError(t, err)
	require.Contains(t, checked.Lines[0], "Basalt is no longer in the database")
	_, err = svc.Run(ctx, f.removeRun(t))
	require.NoError(t, err)
	_, err = os.Stat(f.config)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRemoveKeepsASampleSchemaSomethingDependsOn(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	f.db.Exec(t, `CREATE VIEW public.my_leads AS SELECT id FROM basalt_demo.leads`)
	done, err := svc.Run(context.Background(), f.removeRun(t))
	require.NoError(t, err)
	require.Contains(t, done.Warnings, "the sample schema basalt_demo stays: another object depends on it")
	require.True(t, exists(t, f.db, "basalt_demo"), "the person's view keeps the sample schema")
	require.False(t, exists(t, f.db, "basalt_meta"), "the rest is removed")
}

func TestRemoveRefusesTheAdminStringOfAnotherRealDatabase(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	other := guardtest.New(t)
	other.Exec(t, `CREATE SCHEMA keep_me`)
	req := f.agentJob(localsetup.JobRemove)
	req.DatabaseURL = other.URL
	_, err := svc.Run(context.Background(), req)
	refusal(t, err, localsetup.CodeTargetMismatch)
	require.True(t, exists(t, other, "keep_me"), "the other database is as it was")
	require.True(t, exists(t, f.db, "basalt_meta"), "and so is the agent's")
	_, err = os.Stat(f.config)
	require.NoError(t, err)
}

func TestRemoveLeavesASampleSchemaTheDemoDidNotMake(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	f.db.Exec(t, `COMMENT ON SCHEMA basalt_demo IS NULL`)
	checked, err := svc.Check(context.Background(), f.agentJob(localsetup.JobRemove))
	require.NoError(t, err)
	require.NotContains(t, checked.SQL, "basalt_demo")
	_, err = svc.Run(context.Background(), f.removeRun(t))
	require.NoError(t, err)
	require.True(t, exists(t, f.db, "basalt_demo"), "a schema the demo did not make stays")
	require.False(t, exists(t, f.db, "basalt_meta"))
}

func TestRemoveDropsAPolicyOnASampleTableBeforeTheTable(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	role, err := f.db.Names.Agent("demo_bot")
	require.NoError(t, err)
	ident := pgx.Identifier{role}.Sanitize()
	f.db.Exec(t, `CREATE POLICY `+ident+` ON basalt_demo.leads AS PERMISSIVE FOR SELECT TO `+ident+` USING (true)`)
	checked, err := svc.Check(context.Background(), f.agentJob(localsetup.JobRemove))
	require.NoError(t, err)
	require.Less(t, strings.Index(checked.SQL, "DROP POLICY"), strings.Index(checked.SQL, "DROP TABLE basalt_demo.leads"))
	_, err = svc.Run(context.Background(), f.removeRun(t))
	require.NoError(t, err)
	require.False(t, exists(t, f.db, "basalt_demo"))
	require.False(t, exists(t, f.db, "basalt_meta"))
}

func TestRemoveForgetsEveryAgentOfTheSameDatabase(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	dir := filepath.Dir(f.config)
	cred, err := config.ReadCredential(filepath.Join(dir, "agents", "demo_bot.url"))
	require.NoError(t, err)
	twinCred := filepath.Join(dir, "agents", "twin_bot.url")
	require.NoError(t, config.WriteFile(twinCred, []byte(cred+"\n")))
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	twin := cfg.Agents[0]
	twin.Name, twin.Store = "twin_bot", config.PostgresStore(twinCred)
	require.NoError(t, config.UpdateConfig(f.config, config.Change{Apply: func(c *config.Config) error {
		c.Agents = append(c.Agents, twin)
		return nil
	}}))

	checked, err := svc.Check(context.Background(), f.agentJob(localsetup.JobRemove))
	require.NoError(t, err)
	require.Contains(t, strings.Join(checked.Lines, "\n"), "demo_bot, twin_bot")
	done, err := svc.Run(context.Background(), f.removeRun(t))
	require.NoError(t, err)
	require.Contains(t, done.Lines, "removed from this engine: demo_bot, twin_bot")
	_, err = os.Stat(f.config)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(twinCred)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAgentJobsRefuseAnEngineRunningAsRoot(t *testing.T) {
	t.Parallel()
	f, _ := installed(t)
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true,
		Euid: func() int { return 0 },
	})
	require.NoError(t, err)
	for _, job := range []string{localsetup.JobUpdate, localsetup.JobRemove} {
		_, err := svc.Check(context.Background(), f.agentJob(job))
		refusal(t, err, localsetup.CodeJobUnavailable)
		_, err = svc.Run(context.Background(), f.agentJob(job))
		refusal(t, err, localsetup.CodeJobUnavailable)
	}
	require.True(t, exists(t, f.db, "basalt_meta"))
}

func TestRemoveAlsoDropsAnAgentWhoseCredentialCannotBeRead(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	cfg, err := config.Load(f.config)
	require.NoError(t, err)
	lost := cfg.Agents[0]
	lost.Name, lost.Store = "lost_bot", config.PostgresStore(filepath.Join(filepath.Dir(f.config), "agents", "lost_bot.url"))
	require.NoError(t, config.UpdateConfig(f.config, config.Change{Apply: func(c *config.Config) error {
		c.Agents = append(c.Agents, lost)
		return nil
	}}))
	done, err := svc.Run(context.Background(), f.removeRun(t))
	require.NoError(t, err)
	require.Contains(t, done.Lines, "removed from this engine: demo_bot, lost_bot")
	_, err = os.Stat(f.config)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAgentJobsCheckTheAgentBeforeTheAdminString(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	probe := f.agentJob(localsetup.JobUpdate)
	probe.DatabaseURL = ""
	_, err := svc.Check(ctx, probe)
	refusal(t, err, localsetup.CodeConnectionStringRefused)
	probe.Agent = "sales_bot"
	_, err = svc.Check(ctx, probe)
	refusal(t, err, localsetup.CodeInvalidArgument)
	require.Contains(t, err.Error(), "basalt init --agent NAME")
}
