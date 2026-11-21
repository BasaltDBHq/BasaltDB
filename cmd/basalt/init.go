package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/rlspick"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// initFlags are basalt init's flags after parsing.
type initFlags struct {
	agent, write, read, prefix, configPath, socketDir, osUser, credFile, engineUser string
	passkeyOrigin, passkeyLabel                                                     string
	// devLocalPages is --dev-local-pages: an agent-operated engine on local
	// pages, for development only (CONTRACT.md, Page origins).
	devLocalPages                                            bool
	agentRLS                                                 AgentRLSMode
	spec                                                     guard.AgentSpec
	dryRun, yes, showSQL, skipPasskey, addPasskey, noService bool
	// trustRoot is --trust-root; pin is the database chain's top the
	// person accepted, which setupEngine writes to the engine's trust.d.
	trustRoot string
	pin       *pinChoice
	// operatedBy is --operated-by; operatedByGiven is true when it was passed.
	operatedBy      OperatedBy
	operatedByGiven bool
	// demo is --demo: create and guard the sample schema (demo.go).
	demo bool
	// pathsGiven is true when the engine config found is not the system
	// one: the person runs the engine in the foreground themselves.
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

// runInit: basalt init. Prints a short summary of the setup SQL (the
// full SQL, passwords redacted, with --show-sql), installs or upgrades
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
	// Under an agent, init with the admin credential is refused before
	// anything else, a usage error included: the agent makes a setup code.
	if !helpAsked(args) {
		if err := c.agentContextError("basalt init without --remote", hintAgentInit); err != nil {
			return c.fail(err)
		}
	}
	f, err := parseInit(c, args)
	if err != nil {
		return c.fail(err)
	}
	if _, err := f.commands(c.goos); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if f.devLocalPages {
		fmt.Fprintln(c.stderr, "basalt: "+config.DevLocalPagesWarning)
	}
	if err := checkServiceAnswer(c, f); err != nil {
		return c.fail(err)
	}
	names := guard.Names{Prefix: f.prefix}
	role, err := names.Agent(f.agent)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if mayInstallService(c, f) {
		if err := checkAgentOSUser(f.osUser, f.engineUser); err != nil {
			return c.fail(err)
		}
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
	// Before the admin connection sends anything: offer to pin a chain no
	// authority here verifies (only the TLS handshake reaches the server).
	if !f.dryRun {
		choice, ok, err := c.initPin(admin, f.trustRoot, f.configPath, f.operatedBy == OperatedByAgent)
		if err != nil {
			return c.fail(err)
		}
		if ok {
			// The admin connection itself verifies against the accepted
			// certificate, so the admin password never reaches a server
			// that did not present it.
			if admin, err = c.trustInMemory(choice, admin, f.configPath); err != nil {
				return c.fail(err)
			}
			f.pin = &choice
		}
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
	if f.keepCredential {
		if f.keepCredential, err = keepOrReplaceCredential(c, f, role); err != nil {
			return c.fail(err)
		}
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
	printInitSQL(c, f, role, demoSQL, script)
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
	if f.pin != nil {
		// The pin applies with verify-full only, and its chain verified
		// (the admin string is verify-full already, and dsn is built on it).
		dsn = withVerifyFull(dsn)
		recordPin(c, conn, *f.pin)
		if f.keepCredential {
			fmt.Fprintf(c.stderr, "basalt: the agent keeps its credential %s, whose sslmode stays as it was, so the pin applies to it only "+
				"with sslmode=verify-full: run basalt init again with --rotate-password to write one that verifies\n", f.credFile)
		}
	} else {
		recordExistingPin(c, conn, admin, f.configPath)
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

// printInitSQL writes a short summary of the setup SQL, or the full
// redacted SQL when the person asked for it with --show-sql or --dry-run.
func printInitSQL(c *cliIO, f initFlags, role, demoSQL string, script guard.Script) {
	if f.showSQL || f.dryRun {
		fmt.Fprint(c.stdout, demoSQL+script.SQL())
		return
	}
	fmt.Fprint(c.stdout, initSQLSummary(f, role, demoSQL != ""))
}

// initSQLSummary is the short account of what the setup SQL will do,
// at most a screenful. The full SQL is behind --show-sql.
func initSQLSummary(f initFlags, role string, hasDemoSQL bool) string {
	var b strings.Builder
	b.WriteString("basalt: this setup SQL will:\n")
	if hasDemoSQL {
		b.WriteString("- create the sample schema basalt_demo\n")
	}
	b.WriteString("- install or upgrade the guard (basalt_meta)\n")
	switch {
	case f.rotated:
		b.WriteString("- set a new password for the existing agent role " + role + "\n")
	case f.keepCredential:
		b.WriteString("- keep the existing agent role " + role + " (its password is unchanged)\n")
	default:
		b.WriteString("- create the agent role " + role + "\n")
	}
	if len(f.spec.Write) > 0 {
		b.WriteString("- let the agent write " + strings.Join(f.spec.Write, ", ") + "\n")
	}
	if len(f.spec.Read) > 0 {
		b.WriteString("- let the agent read " + strings.Join(f.spec.Read, ", ") + "\n")
	}
	b.WriteString("Pass --show-sql to print the SQL (passwords redacted).\n")
	return b.String()
}

// AgentRLSMode is the value of --agent-rls: what init does about agent
// tables where row-level security hides every row from the agent role.
// CLI input spelling only (AGENTS.md, Wire format): it is never stored;
// the ledger records the policy itself (AGENT_POLICY_ADDED).
type AgentRLSMode string

// --agent-rls values.
const (
	// AgentRLSAsk shows a checklist at a terminal, or reads one line from
	// piped input (the default).
	AgentRLSAsk AgentRLSMode = "ask"
	// AgentRLSAllRows adds the agent policy on every such table, for scripts.
	AgentRLSAllRows AgentRLSMode = "all-rows"
	// AgentRLSNone never adds an agent policy and does not ask.
	AgentRLSNone AgentRLSMode = "none"
)

// String implements flag.Value.
func (a *AgentRLSMode) String() string { return string(*a) }

// Set implements flag.Value: ask, all-rows, none, or a list of tables
// (schema.table, schema.* separated by commas).
func (a *AgentRLSMode) Set(v string) error {
	switch AgentRLSMode(v) {
	case AgentRLSAsk, AgentRLSAllRows, AgentRLSNone:
	default:
		if _, err := rlspick.ParseList(v); err != nil {
			return fmt.Errorf("must be %s, %s, %s or a list like us.*,public.orders: %w", AgentRLSAsk, AgentRLSAllRows, AgentRLSNone, err)
		}
	}
	*a = AgentRLSMode(v)
	return nil
}

// isList is true when the mode is a list of tables.
func (a AgentRLSMode) isList() bool {
	return a != AgentRLSAsk && a != AgentRLSAllRows && a != AgentRLSNone
}

// agentPolicies picks the agent's tables where row-level security hides
// every row from its role and the person lets the agent see all rows
// (decision "Agent RLS", Nov 12): a checklist at a terminal or one line on
// piped input, every table checked by default; with --yes or on a dry run
// all of them (and one line says which) unless --agent-rls=none or a list. Tables without RLS are never asked about. The
// rest get warnRLSBlind's warning after init.
func agentPolicies(c *cliIO, conn guard.Querier, names guard.Names, f initFlags) ([]guard.BlindTable, error) {
	if f.agentRLS == AgentRLSNone {
		return nil, nil
	}
	blind, err := guard.AgentBlindTables(c.ctx, conn, names, f.spec)
	if err != nil {
		return nil, err
	}
	asks := make([]rlsAsk, 0, len(blind))
	for _, b := range blind {
		asks = append(asks, rlsAsk{Table: b.Table, Rows: b.Rows, Text: setuprun.RLSQuestion(b, f.agent)})
	}
	yes, err := rlsAnswers(c, f.agentRLS, f.yes || f.dryRun, f.agent, append(slices.Clone(f.spec.Write), f.spec.Read...), asks)
	if err != nil {
		return nil, err
	}
	var out []guard.BlindTable
	for i, b := range blind {
		if yes[i] {
			out = append(out, b)
		}
	}
	return out, nil
}

// warnRLSBlind warns about every --write and --read table where row-level
// security still hides all rows from the agent role
// (setuprun.RLSBlindWarnings).
func warnRLSBlind(c *cliIO, conn *pgx.Conn, role string, spec guard.AgentSpec) {
	printWarningLines(c.stderr, setuprun.RLSBlindWarnings(c.ctx, conn, role, spec))
}

// printSetupPlan is the dry run's account of the engine setup init would
// do after the SQL: the one sudo command and its steps, or the foreground
// command. It asks nothing and runs nothing.
func printSetupPlan(c *cliIO, f initFlags) error {
	if f.noService || f.pathsGiven {
		fmt.Fprintf(c.stderr, "basalt: dry run; then init writes %s and %s, and prints:\n", f.credFile, f.configPath)
		fmt.Fprint(c.stderr, f.vault.dryRunLine())
		fmt.Fprint(c.stderr, foregroundNext(f, c.host))
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
	fs.StringVar(&f.osUser, "os-user", "", "OS user the agent runs as, the only one allowed on its socket (default: you)")
	fs.StringVar(&f.engineUser, "engine-user", service.DefaultUser(c.goos), "OS user the engine service runs as")
	fs.BoolVar(&f.rotatePassword, "rotate-password", false, "set a new password for an agent role that exists (init keeps it by default); restart the engine after")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the SQL and the engine setup, and exit")
	fs.BoolVar(&f.showSQL, "show-sql", false, "print the setup SQL (passwords redacted)")
	fs.BoolVar(&f.yes, "yes", false, "do not ask before running the SQL or installing the engine service")
	fs.BoolVar(&f.noService, "no-service", false, "do not install the engine service; print the foreground command")
	fs.BoolVar(&f.demo, "demo", false, "create and guard the sample schema basalt_demo and an agent (demo_bot) that can write only there")
	fs.BoolVar(&f.skipPasskey, "skip-passkey", false, "do not register the passkey that approves held writes now")
	fs.BoolVar(&f.addPasskey, "add-passkey", false, "register another passkey even if one is registered")
	fs.StringVar(&f.passkeyOrigin, "passkey-origin", links.DefaultLocal,
		"pages origin the passkey belongs to: the engine's local pages http://localhost:<port> (RP ID localhost), or the portal "+links.Portal+" (RP ID basaltvault.app; the default with --operated-by=agent)")
	fs.BoolVar(&f.devLocalPages, flagDevLocalPages, false,
		"development only, with --operated-by=agent: use local pages (--passkey-origin http://localhost:<port>) instead of the portal; never with a bot you do not control")
	fs.StringVar(&f.passkeyLabel, "passkey-label", "", "name of the passkey in the picker (default: <database> · <agent> · <date>)")
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
		"on agent tables where row-level security hides every row: ask (a checklist at a terminal, one line from piped input), all-rows adds a policy letting the agent see them all, none adds none, or a list such as us.*,public.orders adds it on those tables only")
	fs.Var(&f.vaultFlag, flagVault, "on or off: whether the engine reaches the portal's pages through the Vault (default off, on with --operated-by=agent)")
	f.operatedBy = OperatedByPerson
	fs.Var(&f.operatedBy, "operated-by", "who runs this engine's machine steps: person or agent (agent: you run init here, then hand the engine to a bot; the pages are the portal's)")
	fs.Usage = func() {
		if c.agentFacing() {
			fmt.Fprint(c.stderr, agentInitUsage)
			return
		}
		fmt.Fprint(c.stderr, "usage: basalt init --agent NAME [--write schema.table,...] [--read schema.table,...] [flags]\n"+
			"       basalt init --remote [flags]            the engine's machine, for a bot that sets up with a code (see basalt init --remote -h)\n"+
			"       basalt init --setup-code CODE [flags]   run the setup code an agent made (see basalt init --setup-code -h)\n\n"+
			manyAgentsHelp+"\nRun init again with a new --agent NAME for each database you add.\n\nflags:\n")
		fs.PrintDefaults()
	}
	trustRoot := trustRootFlag(fs)
	if err := parse(fs, args); err != nil {
		return f, err
	}
	f.trustRoot = *trustRoot
	// The config is found by itself: the system one, else the person's.
	var err error
	if f.configPath, err = c.findConfig(); err != nil {
		return f, err
	}
	f.pathsGiven = f.configPath != c.systemConfig() || c.paths.config != ""
	if f.noService && !f.pathsGiven {
		// A foreground setup writes the person's own config: refuse before any SQL.
		if err := c.refuseSecondConfig(); err != nil {
			return f, err
		}
	}
	f.socketDir = config.DefaultSocketDir(c.goos)
	if f.pathsGiven && c.paths.config == "" {
		// The system socket directory is not this person's to write.
		f.socketDir = filepath.Join(filepath.Dir(f.configPath), "run")
	}
	f.socketDir = cmp.Or(c.paths.socketDir, f.socketDir)
	var originGiven bool
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "operated-by":
			f.operatedByGiven = true
		case "passkey-origin":
			originGiven = true
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
	// An agent-operated engine serves the portal's pages (CONTRACT.md, Who
	// operates the engine): the bot's machine has no pages the person can reach.
	if err := f.agentPages(originGiven); err != nil {
		return f, err
	}
	vc, err := chooseVault(f.vaultFlag, f.operatedBy, f.passkeyOrigin, personDefaultWhy)
	if err != nil {
		return f, err
	}
	f.vault = vc
	if !config.ValidAgentName(f.agent) {
		return f, fmt.Errorf("%w: agent name %q is not valid for the engine", errUsage, f.agent)
	}
	if err := config.CheckSocketPath(config.SocketPath(f.socketDir, f.agent)); err != nil {
		return f, fmt.Errorf("%w: %w", errUsage, err)
	}
	f.credFile = cmp.Or(c.paths.credFile, filepath.Join(filepath.Dir(f.configPath), "agents", f.agent+".url"))
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

// missingTablesHint turns the guard's list of missing --write and --read
// tables into one message naming the database
// (setuprun.MissingTablesHint).
func missingTablesHint(err error, database string) error {
	return setuprun.MissingTablesHint(err, database)
}

// stateDirName is the engine's state directory next to a per-user config.
const stateDirName = "state"

// flagDevLocalPages is init's and service install's development exception.
const flagDevLocalPages = "dev-local-pages"

// agentPages applies the closed origin list to init's flags (CONTRACT.md,
// Page origins; CO-8): an agent-operated engine uses the portal's pages,
// the default with --operated-by=agent, and local pages only with
// --dev-local-pages, which is for nothing else.
func (f *initFlags) agentPages(originGiven bool) error {
	agentOperated := f.operatedBy == OperatedByAgent
	switch {
	case f.devLocalPages && !agentOperated:
		return fmt.Errorf("%w: --dev-local-pages is only for --operated-by=agent; a person-operated engine uses local pages without it", errUsage)
	case f.devLocalPages && !originGiven:
		f.passkeyOrigin = links.DefaultLocal
	case f.devLocalPages && f.passkeyOrigin == links.Portal:
		return fmt.Errorf("%w: --dev-local-pages needs a local --passkey-origin (http://localhost:<port>), not the portal", errUsage)
	case f.devLocalPages:
		// relyingParty has checked the origin is the portal or local.
		return nil
	case agentOperated && !originGiven:
		f.passkeyOrigin = links.Portal
	case agentOperated && f.passkeyOrigin != links.Portal:
		return fmt.Errorf("%w: --operated-by=agent uses the portal's pages (%s); drop --passkey-origin or set it to that "+
			"(local pages would be on the agent's machine)", errUsage, links.Portal)
	}
	return nil
}

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
	s.PagesURL, s.DevLocalPages = f.passkeyOrigin, f.devLocalPages
	if f.operatedByGiven {
		s.OperatedBy = f.operatedBy.enum()
	}
	return s
}

// applyInit runs the script in one transaction and refuses to commit while
// any agent-writable table or cascade target is left unguarded, the after
// statements last (setuprun.ApplyInit).
func applyInit(ctx context.Context, conn *pgx.Conn, script guard.Script, after ...guard.Statement) error {
	return setuprun.ApplyInit(ctx, conn, script, after...)
}

// withGuardDetail adds the Detail and Hint of a database error to its text
// (setuprun.WithGuardDetail).
func withGuardDetail(err error) error { return setuprun.WithGuardDetail(err) }

// nothingChanged ends a failed install's error with "nothing changed"
// (setuprun.NothingChanged).
func nothingChanged(err error) error { return setuprun.NothingChanged(err) }

// applyInitTx is applyInit on a transaction the caller commits.
func applyInitTx(ctx context.Context, tx pgx.Tx, script guard.Script, after ...guard.Statement) error {
	return setuprun.ApplyInitTx(ctx, tx, script, after...)
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
	addIf("os-user", f.osUser, "")
	addIf("engine-user", f.engineUser, service.DefaultUser(goos))
	addIf("passkey-origin", f.passkeyOrigin, links.DefaultLocal)
	addIf("operated-by", string(f.operatedBy), string(OperatedByPerson))
	addIf("agent-rls", string(f.agentRLS), string(AgentRLSAsk))
	if f.devLocalPages {
		args = append(args, "--"+flagDevLocalPages+"=true")
	}
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

// keepOrReplaceCredential decides, for an agent role that exists, whether
// init keeps its password (true) or sets a new one. It keeps it unless the
// credential file is missing everywhere the engine setup may look, as when
// an earlier init stopped before writing it: then init asks to set a new
// password (default yes; --yes and --dry-run answer yes) and refuses
// without a terminal.
func keepOrReplaceCredential(c *cliIO, f initFlags, role string) (bool, error) {
	paths := credentialPaths(c, f)
	for _, p := range paths {
		if !credentialMissing(p) {
			return true, nil
		}
	}
	fmt.Fprintf(c.stderr, "basalt: role %s exists but its credential file (%s) is missing; an earlier init may have stopped before writing it\n",
		role, strings.Join(paths, " or "))
	refused := fmt.Errorf("role %s keeps its password but has no credential file; run init with --rotate-password to set a new one", role)
	switch {
	case f.yes || f.dryRun:
		return false, nil
	case !c.interactive:
		return false, fmt.Errorf("%w (or pass --yes)", refused)
	}
	ok, err := c.confirmYes("Set a new password for it and write the credential?")
	if err != nil {
		return false, err
	}
	if !ok {
		return false, refused
	}
	return false, nil
}

// credentialPaths are where the engine setup reads the agent's credential:
// the given or system path, and, unless paths were given, the person's own
// config directory, where a foreground engine keeps it (perUserPaths; with
// --no-service too).
func credentialPaths(c *cliIO, f initFlags) []string {
	paths := []string{f.credFile}
	if f.pathsGiven {
		return paths
	}
	if pf, err := perUserPaths(c, f); err == nil && pf.credFile != f.credFile {
		paths = append(paths, pf.credFile)
	}
	return paths
}

// credentialMissing reports whether path surely does not exist. A file
// init cannot look at (the service's directories belong to the engine's
// user) may exist, and is kept.
func credentialMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// printWarnings prints what the plan wants the person to know before it
// runs (guard.Script.Warnings), one line each on stderr.
func printWarnings(w io.Writer, s guard.Script) { printWarningLines(w, s.Warnings) }

// printWarningLines prints each warning on its own line.
func printWarningLines(w io.Writer, warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(w, "basalt: warning: %s\n", warning)
	}
}

// withVerifyFull is dsn with sslmode=verify-full ("" stays ""): a pinned
// chain verified for the host, and a profile applies with verify-full only.
func withVerifyFull(dsn string) string {
	if dsn == "" {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	q.Set(paramSSLMode, sslVerifyFull)
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return u.String()
}

// recordPin records the pin on the admin connection
// (basalt_meta.record_trust_pin): the ledger keeps it, and status compares
// the engine's pin with it. A failure is said, not fatal: the pin is the
// engine's file, the record is only for audit.
func recordPin(c *cliIO, conn guard.Querier, p pinChoice) {
	if err := guard.RecordTrustPin(c.ctx, conn, p.host, p.port, p.sha256); err != nil {
		fmt.Fprintf(c.stderr, "basalt: the pin for %s is not recorded in the ledger (the guard is older than schema version %d, "+
			"or the record was refused); the pin itself is written\n", terminalText(p.host), guard.TrustPinsVersion)
		return
	}
	fmt.Fprintf(c.stderr, "basalt: recorded the pin for %s:%d in the ledger\n", terminalText(p.host), p.port)
}

// recordExistingPin records the engine's pin for the admin string's host
// when the host is pinned already and the ledger records another
// certificate or none: after basalt trust pin accepted a new root, a rerun
// of basalt init clears TRUST_PIN_MISMATCH.
func recordExistingPin(c *cliIO, conn guard.Querier, admin, configPath string) {
	t, ok := targetOf(admin)
	if !ok {
		return
	}
	p := trustdir.Set(configPath).For(t.host)
	if p == nil || p.Name != trustprofile.PinName(t.host) || len(p.Certificates()) == 0 {
		return
	}
	sha := trustprofile.DERSHA256(p.Certificates()[0])
	recorded, found, err := guard.RecordedTrustPin(c.ctx, conn, t.host, t.port)
	if err != nil || (found && recorded == sha) {
		return
	}
	if found {
		// The ledger records another certificate: a rotation the person
		// accepted, or a change someone made. Never replaced silently.
		fmt.Fprintf(c.stderr, "basalt: the ledger records SHA-256 %s for %s:%d, but the engine pins SHA-256 %s\n", recorded, terminalText(t.host), t.port, sha)
		if !c.interactive {
			fmt.Fprintln(c.stderr, "basalt: the record is left as it is; run basalt init at a terminal to record the engine's pin")
			return
		}
		ok, err := c.confirm("Record the engine's pin in the ledger in place of the recorded one?")
		if err != nil || !ok {
			return
		}
	}
	recordPin(c, conn, pinChoice{pinTarget: t, top: p.Certificates()[0], sha256: sha})
}
