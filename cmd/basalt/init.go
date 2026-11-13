package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// initFlags are basalt init's flags after parsing.
type initFlags struct {
	agent, write, read, prefix, configPath, socketDir, osUser, credFile, engineUser string
	passkeyOrigin, passkeyLabel                                                     string
	agentRLS                                                                        AgentRLSMode
	spec                                                                            guard.AgentSpec
	dryRun, yes, skipPasskey, addPasskey, noService                                 bool
	// demo is --demo: create and guard the sample schema (demo.go).
	demo bool
	// pathsGiven is true when --config, --socket-dir or --credential-file
	// was given: the person runs the engine in the foreground themselves.
	pathsGiven bool
	// rotatePassword sets a new password even when the agent's role exists.
	rotatePassword bool
	// keepCredential: the role exists and keeps its password, so the
	// credential file the engine reads is left as it is.
	keepCredential bool
	// rotated: an existing role got a new password, so a running engine
	// holds a stale one until it restarts.
	rotated bool
	// initArgs are the flags saved to engine.json (savedArgs).
	initArgs []string
	// personUIDs are the OS users the engine's person socket admits
	// (--person-uid; else the person running init, see persons).
	personUIDs []uint32
	// vaultFlag is --vault as given ("" when not); vault is what init
	// asks the config's vault to be (chooseVault).
	vaultFlag VaultMode
	vault     vaultChoice
}

// runInit: basalt init. Shows the setup SQL, installs or upgrades
// basalt_meta with the admin connection string, creates or rotates the
// agent role, writes the agent's own connection string to a 0600
// credential file and adds the agent to the engine config, then installs
// the engine service with one sudo (or prints the foreground command; see
// setupEngine). The admin connection string is never stored.
func runInit(c *cliIO, args []string) int {
	if isRemote(args) {
		return runInitRemote(c, args)
	}
	if isSetupCode(args) {
		return runInitSetupCode(c, args)
	}
	f, err := parseInit(c, args)
	if err != nil {
		return c.fail(err)
	}
	if _, err := f.commands(c.goos); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	names := guard.Names{Prefix: f.prefix}
	role, err := names.Agent(f.agent)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if mayInstallService(c, f) {
		if _, err := checkedExecutable(c); err != nil {
			return c.fail(err)
		}
	}
	admin, err := c.adminURL()
	if err != nil {
		return c.fail(err)
	}
	// The agent's connection string is built from the admin's: refuse one
	// it cannot be built from before anything changes in the database.
	if _, err := guard.AgentConnString(admin, role, ""); err != nil {
		return c.fail(err)
	}
	conn, err := c.dial(c.ctx, admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)

	exists, err := guard.AgentRoleExists(c.ctx, conn, names, f.agent)
	if err != nil {
		return c.fail(err)
	}
	f.keepCredential = exists && !f.rotatePassword
	if f.keepCredential && (f.noService || f.pathsGiven) && !fileExists(f.credFile) {
		// A mistyped path must not rotate the password.
		return c.fail(fmt.Errorf("role %s exists but there is no credential file %s; check the path, or run init with --rotate-password", role, f.credFile))
	}
	f.rotated = exists && f.rotatePassword
	if !f.keepCredential {
		f.spec.Password = guard.NewPassword()
	}
	// With --demo the plan needs the sample tables to exist, so it is made in
	// a transaction that is rolled back; the apply below seeds again in a
	// fresh one. Nothing is held open while the person decides.
	var q guard.Querier = conn
	var demoSQL string
	rollback := func() {}
	if f.demo {
		q, demoSQL, rollback, err = planDemoTx(c, conn)
		if err != nil {
			return c.fail(err)
		}
		defer rollback()
	}
	policies, err := agentPolicies(c, q, names, f)
	if err != nil {
		return c.fail(missingTablesHint(err, conn.Config().Database))
	}
	script, err := guard.PlanInit(c.ctx, q, guard.InitOptions{Names: names, Agent: f.spec, AgentPolicies: policies})
	if err != nil {
		return c.fail(missingTablesHint(err, conn.Config().Database))
	}
	rollback() // the plan is made; hold nothing open while the person decides
	fmt.Fprint(c.stdout, demoSQL+script.SQL())
	printWarnings(c.stderr, script)
	if f.dryRun {
		if err := printSetupPlan(c, f); err != nil {
			return c.fail(err)
		}
		return exitOK
	}
	if !f.yes {
		ok, err := c.confirm(fmt.Sprintf("Run this SQL as %s?", conn.Config().User))
		if err != nil {
			return c.fail(err)
		}
		if !ok {
			return c.fail(errors.New("init canceled; nothing changed"))
		}
	}
	if f.demo {
		err = applyDemo(c.ctx, conn, script)
	} else {
		err = applyInit(c.ctx, conn, script)
	}
	if err != nil {
		return c.fail(err)
	}
	var dsn string
	if !f.keepCredential {
		dsn, err = guard.AgentConnString(admin, role, f.spec.Password)
		if err != nil {
			return c.fail(err)
		}
	}
	fmt.Fprintf(c.stderr, "basalt: guard installed; agent role %s\n", role)
	warnRLSBlind(c, conn, role, f.spec)
	// A failed passkey step must not leave the role without its credential
	// file: the rerun it asks for would refuse a role that exists. The
	// engine is set up first, then the failure is reported.
	passkeyErr := passkeyStep(c, conn, f)
	if f.demo {
		leads, notes, err := demoCounts(c.ctx, conn)
		if err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.stderr, "basalt: demo ready: leads %d, lead_notes %d\n", leads, notes)
	}
	if err := setupEngine(c, f, dsn); err != nil {
		return c.fail(err)
	}
	if passkeyErr != nil {
		return c.fail(fmt.Errorf("the guard is installed and the engine is set up, but no passkey was registered, so held writes cannot be approved until you register one (run basalt init again): %w", passkeyErr))
	}
	return exitOK
}

// AgentRLSMode is the value of --agent-rls: what init does about agent
// tables where row-level security hides every row from the agent role.
// CLI input spelling only (AGENTS.md, Wire format): it is never stored;
// the ledger records the policy itself (AGENT_POLICY_ADDED).
type AgentRLSMode string

// --agent-rls values.
const (
	// AgentRLSAsk asks once per table at a terminal (the default).
	AgentRLSAsk AgentRLSMode = "ask"
	// AgentRLSAllRows adds the agent policy on every such table, for scripts.
	AgentRLSAllRows AgentRLSMode = "all-rows"
	// AgentRLSNone never adds an agent policy and does not ask.
	AgentRLSNone AgentRLSMode = "none"
)

// agentRLSRule is the validator rule of --agent-rls.
const agentRLSRule = "oneof=ask all-rows none"

// String implements flag.Value.
func (a *AgentRLSMode) String() string { return string(*a) }

// Set implements flag.Value, refusing anything but the three values.
func (a *AgentRLSMode) Set(v string) error {
	if err := validator.New().Var(v, agentRLSRule); err != nil {
		return fmt.Errorf("must be %s, %s or %s", AgentRLSAsk, AgentRLSAllRows, AgentRLSNone)
	}
	*a = AgentRLSMode(v)
	return nil
}

// agentPolicies picks the agent's tables where row-level security hides
// every row from its role and the person lets the agent see all rows
// (decision "Agent RLS", Nov 12): asked once per table at a terminal,
// default no; never without a terminal, with --yes or on a dry run unless
// --agent-rls=all-rows. Tables without RLS are never asked about. The
// rest get warnRLSBlind's warning after init.
func agentPolicies(c *cliIO, conn guard.Querier, names guard.Names, f initFlags) ([]guard.BlindTable, error) {
	if f.agentRLS == AgentRLSNone {
		return nil, nil
	}
	blind, err := guard.AgentBlindTables(c.ctx, conn, names, f.spec)
	if err != nil {
		return nil, err
	}
	if f.agentRLS == AgentRLSAllRows {
		return blind, nil
	}
	if !c.interactive || f.yes || f.dryRun {
		return nil, nil
	}
	var out []guard.BlindTable
	for _, b := range blind {
		ok, err := c.confirm(fmt.Sprintf("%s hides its rows with row-level security. Let %s see all %s of this table?",
			b.Table, f.agent, rowCount(b.Rows)))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, b)
		}
	}
	return out, nil
}

// rowCount is "1 row" or "n rows".
func rowCount(n int64) string {
	if n == 1 {
		return "1 row"
	}
	return fmt.Sprintf("%d rows", n)
}

// warnRLSBlind warns about every --write and --read table where row-level
// security still hides all rows from the agent role: Supabase can turn
// RLS on for new tables, and the agent then reads 0 rows without any
// error. A failed check is a warning too: the guard is installed either
// way.
func warnRLSBlind(c *cliIO, conn *pgx.Conn, role string, spec guard.AgentSpec) {
	tables := append(append([]string{}, spec.Write...), spec.Read...)
	blind, err := guard.RLSBlindTables(c.ctx, conn, role, tables)
	if err != nil {
		fmt.Fprintf(c.stderr, "basalt: warning: could not check row-level security on the agent's tables: %v\n", err)
		return
	}
	for _, t := range blind {
		fmt.Fprintf(c.stderr, "basalt: warning: row-level security is on for %s and no policy lets %s see rows; "+
			"the agent will read 0 rows. Add a policy for that role, or disable RLS on the table.\n", t, role)
	}
}

// printSetupPlan is the dry run's account of the engine setup init would
// do after the SQL: the one sudo command and its steps, or the foreground
// command. It asks nothing and runs nothing.
func printSetupPlan(c *cliIO, f initFlags) error {
	if f.noService || f.pathsGiven {
		fmt.Fprintf(c.stderr, "basalt: dry run; then init writes %s and %s, and prints:\n", f.credFile, f.configPath)
		fmt.Fprint(c.stderr, f.vault.dryRunLine())
		fmt.Fprint(c.stderr, foregroundNext(f, c.goos))
		return nil
	}
	f.initArgs = f.savedArgs(c.goos)
	uids, err := persons(c, f)
	if err != nil {
		return err
	}
	f.personUIDs = uids
	bin, err := c.host.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: dry run; then init asks to install the engine service, which runs (the credential on stdin):\n  sudo %s\nwith these steps:\n",
		shellJoin(serviceInstallArgs(f, bin)))
	fmt.Fprint(c.stderr, f.vault.dryRunLine())
	return applyServiceInstall(c, bin, f.configPath, f.engineUser, f.agentInstall(""), true)
}

// shellQuote quotes s for a POSIX shell when it has anything but plain
// path characters.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func parseInit(c *cliIO, args []string) (initFlags, error) {
	var f initFlags
	fs := c.flags("init")
	fs.StringVar(&f.agent, "agent", "", "agent name (lowercase letters, digits, _); its role is <prefix>_agent_<name>")
	fs.StringVar(&f.write, "write", "", "comma-separated schema.table the agent may read and write")
	fs.StringVar(&f.read, "read", "", "comma-separated schema.table the agent may only read")
	fs.StringVar(&f.prefix, "prefix", guard.DefaultPrefix, "role name prefix")
	fs.DurationVar(&f.spec.StatementTimeout, "statement-timeout", guard.DefaultStatementTimeout, "query time limit of the agent role")
	fs.StringVar(&f.configPath, "config", config.DefaultPath(c.goos), "engine config file to add the agent to; another path means you run the engine yourself")
	fs.StringVar(&f.socketDir, "socket-dir", config.DefaultSocketDir(c.goos), "engine socket directory, when the config is new")
	fs.StringVar(&f.osUser, "os-user", "", "OS user the agent runs as, the only one allowed on its socket (default: you)")
	fs.StringVar(&f.engineUser, "engine-user", service.DefaultUser(c.goos), "OS user the engine service runs as")
	fs.StringVar(&f.credFile, "credential-file", "", "where to write the agent's connection string (default <config dir>/agents/NAME.url)")
	fs.BoolVar(&f.rotatePassword, "rotate-password", false, "set a new password for an agent role that exists (init keeps it by default); restart the engine after")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the SQL and the engine setup, and exit")
	fs.BoolVar(&f.yes, "yes", false, "do not ask before running the SQL or installing the engine service")
	fs.BoolVar(&f.noService, "no-service", false, "do not install the engine service; print the foreground command")
	fs.BoolVar(&f.demo, "demo", false, "create and guard the sample schema basalt_demo and an agent (demo_bot) that can write only there")
	fs.BoolVar(&f.skipPasskey, "skip-passkey", false, "do not register the passkey that approves held writes now")
	fs.BoolVar(&f.addPasskey, "add-passkey", false, "register another passkey even if one is registered")
	fs.StringVar(&f.passkeyOrigin, "passkey-origin", links.DefaultLocal,
		"pages origin the passkey belongs to: the engine's local pages http://localhost:<port> (RP ID localhost), or "+links.HostedConsole+" (RP ID basaltvault.app)")
	fs.StringVar(&f.passkeyLabel, "passkey-label", "", "name of the passkey in the picker (default: the database name)")
	fs.Func(flagPersonUID, "service: an OS user id the engine's person socket admits for basalt log, approve and revert (repeatable; default: you)", func(v string) error {
		uid, err := parseUID(v)
		if err != nil {
			return err
		}
		f.personUIDs = append(f.personUIDs, uid)
		return nil
	})
	f.agentRLS = AgentRLSAsk
	fs.Var(&f.agentRLS, "agent-rls",
		"on agent tables where row-level security hides every row: ask at a terminal, all-rows adds a policy letting the agent see them all, none skips the question")
	fs.Var(&f.vaultFlag, flagVault, "on or off: whether the engine reaches the portal's pages through the Vault (default off; on needs the portal's pages)")
	if err := parse(fs, args); err != nil {
		return f, err
	}
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "config", "socket-dir", "credential-file":
			f.pathsGiven = true
		}
	})
	if f.demo {
		if f.write != "" || f.read != "" {
			return f, fmt.Errorf("%w: --demo sets the agent's tables; drop --write and --read", errUsage)
		}
		if f.agent == "" {
			f.agent = demoAgent
		}
		f.write = demoTables
	}
	if f.agent == "" {
		return f, fmt.Errorf("%w: --agent is required", errUsage)
	}
	if _, err := relyingParty(f.passkeyOrigin); err != nil {
		return f, err
	}
	// basalt init is person-operated: --operated-by=agent is init --remote's.
	vc, err := chooseVault(f.vaultFlag, OperatedByPerson, f.passkeyOrigin, personDefaultWhy)
	if err != nil {
		return f, err
	}
	f.vault = vc
	if !config.ValidAgentName(f.agent) {
		return f, fmt.Errorf("%w: agent name %q is not valid for the engine", errUsage, f.agent)
	}
	if err := config.CheckSocketPath(config.SocketPath(f.socketDir, f.agent)); err != nil {
		return f, fmt.Errorf("%w: --socket-dir: %w", errUsage, err)
	}
	if f.credFile == "" {
		f.credFile = filepath.Join(filepath.Dir(f.configPath), "agents", f.agent+".url")
	}
	if f.osUser == "" {
		u, err := invokingUser()
		if err != nil {
			return f, err
		}
		f.osUser = u
	}
	f.spec.Name = f.agent
	f.spec.Write = splitList(f.write)
	f.spec.Read = splitList(f.read)
	return f, nil
}

// invokingUser is the person running init: under sudo, the user who ran
// sudo, not root.
func invokingUser() (string, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		return name, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// demoSchema is the schema of the M4 demo data (docs/m4/seed.sql).
const demoSchema = "basalt_demo."

// missingTablesHint turns the guard's list of missing --write and --read
// tables into one message naming the database, and points at the demo
// seed when a demo table is missing. Other errors pass through.
func missingTablesHint(err error, database string) error {
	var missing *guard.MissingTablesError
	if !errors.As(err, &missing) {
		return err
	}
	noun, verb := "table", "it"
	if len(missing.Tables) > 1 {
		noun, verb = "tables", "them"
	}
	msg := fmt.Sprintf("%s %s not found in database %q; create %s first", noun, strings.Join(missing.Tables, ", "), database, verb)
	for _, t := range missing.Tables {
		if strings.HasPrefix(t, demoSchema) {
			msg += " (basalt init --demo creates the sample tables)"
			break
		}
	}
	return errors.New(msg)
}

// stateDirName is the engine's state directory next to a per-user config.
const stateDirName = "state"

// engineSettings are what init writes to the engine config besides the
// agent. A config outside the platform default is a per-user setup, run
// with basalt engine in the foreground, so its state directory sits next
// to it instead of in a system directory the user cannot create. A
// development passkey origin serves the approval page too, so held writes
// link to the page that knows the registered passkey.
func engineSettings(f initFlags, goos string) config.Settings {
	s := f.vault.settings(config.Settings{SocketDir: f.socketDir, Mode: config.ModeSameUser})
	if f.configPath != config.DefaultPath(goos) {
		s.StateDir = filepath.Join(filepath.Dir(f.configPath), stateDirName)
	}
	s.PagesURL = f.passkeyOrigin
	return s
}

// applyInit runs the script in one transaction and refuses to commit while
// any agent-writable table or cascade target is left unguarded. The after
// statements run last, once that check passed (a setup code's
// record_setup). basalt init, init --setup-code and upgrade all apply
// through it.
func applyInit(ctx context.Context, conn *pgx.Conn, script guard.Script, after ...guard.Statement) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return applyInitTx(ctx, tx, script, after...) })
}

// applyInitTx is applyInit on a transaction the caller commits.
func applyInitTx(ctx context.Context, tx pgx.Tx, script guard.Script, after ...guard.Statement) error {
	if err := script.Apply(ctx, tx); err != nil {
		return err
	}
	if err := checkCovered(ctx, tx); err != nil {
		return err
	}
	for _, st := range after {
		if _, err := tx.Exec(ctx, st.SQL); err != nil {
			return fmt.Errorf("record the setup: %w", err)
		}
	}
	return nil
}

// checkCovered refuses, inside the install's transaction, while any
// agent-writable table or cascade target is left unguarded.
func checkCovered(ctx context.Context, tx pgx.Tx) error {
	uncovered, err := guard.UncoveredTables(ctx, tx)
	if err != nil {
		return err
	}
	if len(uncovered) > 0 {
		tables := make([]string, 0, len(uncovered))
		for _, u := range uncovered {
			tables = append(tables, u.Table+" ("+u.Why+")")
		}
		return fmt.Errorf("tables left unguarded: %s", strings.Join(tables, ", "))
	}
	return nil
}

// savedArgs are the flags init writes to engine.json for the agent: the ones
// whose value is not the default, plus --agent and --os-user, in `--flag=value`
// form. Never the admin connection string, a password or a one-shot flag.
func (f initFlags) savedArgs(goos string) []string {
	args := []string{"--agent=" + f.agent}
	addIf := func(name, value, def string) {
		if value != "" && value != def {
			args = append(args, "--"+name+"="+value)
		}
	}
	addIf("write", f.write, "")
	addIf("read", f.read, "")
	addIf("prefix", f.prefix, guard.DefaultPrefix)
	addIf("statement-timeout", f.spec.StatementTimeout.String(), guard.DefaultStatementTimeout.String())
	addIf("socket-dir", f.socketDir, config.DefaultSocketDir(goos))
	addIf("os-user", f.osUser, "")
	addIf("engine-user", f.engineUser, service.DefaultUser(goos))
	addIf("credential-file", f.credFile, filepath.Join(filepath.Dir(f.configPath), "agents", f.agent+".url"))
	addIf("passkey-origin", f.passkeyOrigin, links.DefaultLocal)
	addIf("agent-rls", string(f.agentRLS), string(AgentRLSAsk))
	return args
}

// commands are the agent's commands for what init saves. It refuses saved
// arguments the engine would not accept (a connection URL, a password), so
// init fails before it writes them.
func (f initFlags) commands(goos string) (agent.Commands, error) {
	path, err := filepath.Abs(f.configPath)
	if err != nil {
		return agent.Commands{}, err
	}
	return agent.NewCommands(f.agent, path, goos, f.savedArgs(goos))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// printWarnings prints what the plan wants the person to know before it
// runs (guard.Script.Warnings), one line each on stderr.
func printWarnings(w io.Writer, s guard.Script) {
	for _, warning := range s.Warnings {
		fmt.Fprintf(w, "basalt: warning: %s\n", warning)
	}
}
