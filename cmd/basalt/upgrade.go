package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// basalt upgrade (CONTRACT.md, CLI; owner decision AE-11): the missing
// basalt_meta migrations, applied with the admin connection string in one
// transaction. Nothing else: no password rotation, no policies, no
// passkey, and no engine restart (the engine reads the guard's version on
// every call).

type upgradeFlags struct {
	agent, configPath string
	yes, dryRun       bool
}

func parseUpgrade(c *cliIO, args []string) (upgradeFlags, error) {
	var f upgradeFlags
	fs := c.flags("upgrade")
	fs.StringVar(&f.agent, "agent", "", "the agent whose database's guard to upgrade")
	fs.StringVar(&f.configPath, "config", config.DefaultPath(c.goos), "engine config file")
	fs.BoolVar(&f.yes, "yes", false, "do not ask before running the SQL")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print what the upgrade does and its SQL, and run nothing")
	if err := parse(fs, args); err != nil {
		return f, err
	}
	if !config.ValidAgentName(f.agent) {
		return f, fmt.Errorf("%w: --agent is required (the agent whose database's guard to upgrade)", errUsage)
	}
	return f, nil
}

// agentGuard is what basalt upgrade learns with the agent's own credential
// before it asks for the admin connection string: the database the
// credential connects to, the guard as the agent sees it, and who operates
// the engine.
type agentGuard struct {
	target     setupcode.Target
	guard      guard.Status
	operatedBy string
}

func runUpgrade(c *cliIO, args []string) int {
	f, err := parseUpgrade(c, args)
	if err != nil {
		return c.fail(err)
	}
	seen, err := readAgentGuard(c, f)
	if err != nil {
		return c.fail(err)
	}
	done, err := checkUpgradable(c, f.agent, seen)
	if err != nil || done {
		return exitCode(c, err)
	}
	admin, err := c.adminURL()
	if err != nil {
		return c.fail(err)
	}
	if err := checkUpgradeTarget(f.agent, seen.target, admin); err != nil {
		return c.fail(err)
	}
	conn, err := c.dial(c.ctx, admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	if err := upgradeGuard(c, conn, f); err != nil {
		return c.fail(err)
	}
	return exitOK
}

func exitCode(c *cliIO, err error) int {
	if err != nil {
		return c.fail(err)
	}
	return exitOK
}

// readAgentGuard asks the engine over the person socket in service mode,
// else reads the config and logs in with the agent's credential.
func readAgentGuard(c *cliIO, f upgradeFlags) (agentGuard, error) {
	if c.serviceMode(f.agent, "", f.configPath) {
		return personAgentGuard(c, f.agent)
	}
	cfg, a, err := configAgentOf(f.agent, f.configPath)
	if err != nil {
		return agentGuard{}, err
	}
	dsn, err := config.ReadCredential(a.CredentialFile)
	if err != nil {
		return agentGuard{}, err
	}
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		// The parse error can echo the URL, which holds the password.
		return agentGuard{}, fmt.Errorf("the credential of agent %s is not a valid Postgres URL", f.agent)
	}
	seen := agentGuard{
		target:     setupcode.ConnTarget(pc.Host, int(pc.Port), pc.Database, pc.User),
		operatedBy: cfg.OperatedBy,
	}
	if cfg.AgentOperated() {
		return seen, nil // refused before the database is touched
	}
	conn, err := connect(c.ctx, dsn)
	if err != nil {
		return agentGuard{}, fmt.Errorf("the agent's credential does not log in, so the guard cannot be checked (%w); basalt status %s says what to do",
			err, statusFlags(f, c.goos))
	}
	defer conn.Close(c.ctx)
	if seen.guard, err = guard.AgentStatus(c.ctx, conn, guard.Migrations()); err != nil {
		return agentGuard{}, err
	}
	return seen, nil
}

// personAgentGuard is readAgentGuard through the engine: its status tool
// and the database the agent's credential names (TARGET).
func personAgentGuard(c *cliIO, agentName string) (agentGuard, error) {
	client := person.Client{Path: c.engine.personSocket}
	target, err := client.Target(c.ctx, agentName)
	if err != nil {
		return agentGuard{}, personError(c, agentName, err)
	}
	report, _, err := personStatus(c, agentName)
	if err != nil {
		return agentGuard{}, err
	}
	st := guard.Status{
		State: report.Guard.State, Build: report.Guard.Build,
		MissingBreaking: report.Guard.MissingBreaking, MissingNonBreaking: report.Guard.MissingNonBreaking,
	}
	if report.Guard.Installed != nil {
		st.Installed = *report.Guard.Installed
	}
	return agentGuard{target: setupcode.Target(target), guard: st, operatedBy: report.OperatedBy}, nil
}

// configAgentOf loads the config and finds agent in it.
func configAgentOf(agentName, configPath string) (config.Config, config.Agent, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, config.Agent{}, err
	}
	for _, a := range cfg.Agents {
		if a.Name == agentName {
			return cfg, a, nil
		}
	}
	return config.Config{}, config.Agent{}, fmt.Errorf("agent %q is not in %s; run basalt init --agent %s", agentName, configPath, agentName)
}

func statusFlags(f upgradeFlags, goos string) string {
	out := "--agent " + f.agent
	if f.configPath != config.DefaultPath(goos) {
		out += " --config " + shellQuote(f.configPath)
	}
	return out
}

// checkUpgradable refuses, before the admin connection string is asked
// for, an upgrade that is not this command's to make. done is true when
// the guard is already current: nothing to do.
func checkUpgradable(c *cliIO, agentName string, seen agentGuard) (done bool, err error) {
	if seen.operatedBy == mcpcontract.OperatedByAgent {
		// CO-9: no command on an agent-operated engine's machine asks for
		// the admin connection string.
		return false, fmt.Errorf("%s is operated by its agent, so the admin connection string never goes on its machine. "+
			"Upgrade with a setup code: run basalt init --remote --agent %s there, then basalt init --setup-code <code> on your own computer",
			agentName, agentName)
	}
	st := seen.guard
	switch st.State {
	case guard.GuardOK:
		fmt.Fprintf(c.stderr, "basalt: the guard is up to date (version %d); nothing to upgrade\n", st.Installed)
		return true, nil
	case guard.GuardMissing:
		return false, fmt.Errorf("the guard is not installed in %s's database, and basalt upgrade only adds migrations to an installed one; "+
			"install it with basalt init (basalt status --agent %s shows the command)", agentName, agentName)
	case guard.GuardNewer:
		return false, newerGuardError(st.Installed, st.Build)
	case guard.GuardUnknown:
		return false, fmt.Errorf("the engine cannot read the guard with %s's credential; basalt status --agent %s says why", agentName, agentName)
	}
	return false, nil
}

func newerGuardError(installed, build int) error {
	return fmt.Errorf("the guard (version %d) is newer than this basalt (version %d); install the newer basalt instead. Nothing changed", installed, build)
}

// checkUpgradeTarget refuses an admin connection string for another
// database than the agent's credential connects to, before connecting
// (CONTRACT.md, CLI, basalt upgrade). Both are compared as pgx would
// connect: host, port and database, or the Supabase project ref and
// database, so a pooler and a direct host of one project match.
func checkUpgradeTarget(agentName string, want setupcode.Target, admin string) error {
	if _, err := guard.AgentConnString(admin, "", ""); err != nil {
		return err
	}
	cfg, err := pgconn.ParseConfig(admin)
	if err != nil {
		return errors.New("the admin connection string cannot be used (pgx refuses it); check its parameters")
	}
	got := setupcode.ConnTarget(cfg.Host, int(cfg.Port), cfg.Database, cfg.User)
	for _, fb := range cfg.Fallbacks {
		if !strings.EqualFold(fb.Host, cfg.Host) || fb.Port != cfg.Port {
			return errors.New("the admin connection string names more than one host; give the one database host the agent connects to")
		}
	}
	if sameDatabase(want, got) {
		return nil
	}
	return fmt.Errorf("%s connects to database %s of %s, but your admin connection string points at database %s of %s. "+
		"Run basalt upgrade with the admin connection string of %s's database; nothing changed",
		agentName, want.Database, targetWords(want), got.Database, targetWords(got), agentName)
}

// upgradeGuard plans the missing migrations on the admin connection, shows
// them, asks, and applies them in one transaction (applyInit).
func upgradeGuard(c *cliIO, conn *pgx.Conn, f upgradeFlags) error {
	ctx := c.ctx
	prefix, err := guard.InstalledPrefix(ctx, conn)
	if err != nil {
		return err
	}
	installed, err := guard.InstalledVersion(ctx, conn)
	if err != nil {
		return err
	}
	latest := guard.LatestVersion()
	names := guard.Names{Prefix: prefix}
	switch {
	case installed == 0 || prefix == "":
		return fmt.Errorf("this database has no guard; install it with basalt init (basalt status --agent %s shows the command)", f.agent)
	case installed > latest:
		return newerGuardError(installed, latest)
	case installed == latest:
		fmt.Fprintf(c.stderr, "basalt: the guard is up to date (version %d); nothing to upgrade\n", installed)
		return nil
	case names.Validate() != nil:
		return fmt.Errorf("basalt_meta in this database is owned by %s, not by a Basalt guard role; nothing changed", prefix)
	}
	if exists, err := guard.AgentRoleExists(ctx, conn, names, f.agent); err != nil || !exists {
		if err != nil {
			return err
		}
		return fmt.Errorf("this database has no agent %s (prefix %s): the admin connection string is for another database than %s's; nothing changed",
			f.agent, prefix, f.agent)
	}
	script, err := guard.PlanInit(ctx, conn, guard.InitOptions{Names: names})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, setupcode.UpgradeLine(installed, latest))
	fmt.Fprintf(c.stdout, "Prefix %s. Missing versions: %s.\n\n", prefix, joinInts(missingVersions(installed)))
	fmt.Fprint(c.stdout, script.SQL())
	if f.dryRun {
		fmt.Fprintln(c.stderr, "basalt: dry run; nothing ran")
		return nil
	}
	if !f.yes {
		ok, err := c.confirm("Run this?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("upgrade canceled; nothing changed")
		}
	}
	if err := applyInit(ctx, conn, script); err != nil {
		return fmt.Errorf("%w; nothing changed", err)
	}
	fmt.Fprintf(c.stderr, "basalt: guard upgraded from version %d to %d (applied %s); the engine serves %s again without a restart\n",
		installed, latest, joinInts(missingVersions(installed)), f.agent)
	return nil
}

// missingVersions are the build's versions after installed.
func missingVersions(installed int) []int {
	var out []int
	for _, m := range guard.Migrations() {
		if m.Version > installed {
			out = append(out, m.Version)
		}
	}
	return out
}

func joinInts(vs []int) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}
