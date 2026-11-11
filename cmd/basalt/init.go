package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// initFlags are basalt init's flags after parsing.
type initFlags struct {
	agent, write, read, prefix, configPath, socketDir, osUser, credFile, engineUser string
	passkeyOrigin, passkeyLabel                                                     string
	spec                                                                            guard.AgentSpec
	dryRun, yes, skipPasskey, addPasskey, noService                                 bool
	// pathsGiven is true when --config, --socket-dir or --credential-file
	// was given: the person runs the engine in the foreground themselves.
	pathsGiven bool
}

// runInit: basalt init. Shows the setup SQL, installs or upgrades
// basalt_meta with the admin connection string, creates or rotates the
// agent role, writes the agent's own connection string to a 0600
// credential file and adds the agent to the engine config, then installs
// the engine service with one sudo (or prints the foreground command; see
// setupEngine). The admin connection string is never stored.
func runInit(c *cliIO, args []string) int {
	f, err := parseInit(c, args)
	if err != nil {
		return c.fail(err)
	}
	names := guard.Names{Prefix: f.prefix}
	role, err := names.Agent(f.agent)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	admin, err := c.adminURL()
	if err != nil {
		return c.fail(err)
	}
	conn, err := connect(c.ctx, admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)

	f.spec.Password = guard.NewPassword()
	script, err := guard.PlanInit(c.ctx, conn, guard.InitOptions{Names: names, Agent: f.spec})
	if err != nil {
		return c.fail(missingTablesHint(err, conn.Config().Database))
	}
	fmt.Fprint(c.stdout, script.SQL())
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
	if err := applyInit(c.ctx, conn, script); err != nil {
		return c.fail(err)
	}
	dsn, err := guard.AgentConnString(admin, role, f.spec.Password)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stderr, "basalt: guard installed; agent role %s\n", role)
	warnRLSBlind(c, conn, role, f.spec)
	if err := passkeyStep(c, conn, f); err != nil {
		return c.fail(fmt.Errorf("the guard is installed but no passkey was registered (run basalt init again): %w", err))
	}
	if err := setupEngine(c, f, dsn); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// warnRLSBlind warns about every --write and --read table where row-level
// security hides all rows from the agent role: Supabase can turn RLS on
// for new tables, and the agent then reads 0 rows without any error. Init
// never adds a policy for the agent (decision N12-7). A failed check is a
// warning too: the guard is installed either way.
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
		fmt.Fprint(c.stderr, foregroundNext(f, c.goos))
		return nil
	}
	bin, err := c.host.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: dry run; then init asks to install the engine service, which runs (the credential on stdin):\n  sudo %s\nwith these steps:\n",
		shellJoin(serviceInstallArgs(f, bin)))
	return applyServiceInstall(c, bin, f.configPath, f.engineUser, agentInstall{name: f.agent, osUser: f.osUser}, true)
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
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the SQL and the engine setup, and exit")
	fs.BoolVar(&f.yes, "yes", false, "do not ask before running the SQL or installing the engine service")
	fs.BoolVar(&f.noService, "no-service", false, "do not install the engine service; print the foreground command")
	fs.BoolVar(&f.skipPasskey, "skip-passkey", false, "do not register the passkey that approves held writes now")
	fs.BoolVar(&f.addPasskey, "add-passkey", false, "register another passkey even if one is registered")
	fs.StringVar(&f.passkeyOrigin, "passkey-origin", "", "development only: the registration page at http://localhost:<port> (RP ID localhost)")
	fs.StringVar(&f.passkeyLabel, "passkey-label", "", "name of the passkey in the picker (default: the database name)")
	if err := parse(fs, args); err != nil {
		return f, err
	}
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "config", "socket-dir", "credential-file":
			f.pathsGiven = true
		}
	})
	if f.agent == "" {
		return f, fmt.Errorf("%w: --agent is required", errUsage)
	}
	if _, err := relyingParty(f.passkeyOrigin); err != nil {
		return f, err
	}
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
			msg += " (the M4 demo: docs/m4/seed.sql)"
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
	s := config.Settings{SocketDir: f.socketDir}
	if f.configPath != config.DefaultPath(goos) {
		s.StateDir = filepath.Join(filepath.Dir(f.configPath), stateDirName)
	}
	if f.passkeyOrigin != "" {
		s.ApprovalPage = f.passkeyOrigin + approvePath
	}
	return s
}

// applyInit runs the script in one transaction and refuses to commit while
// any agent-writable table or cascade target is left unguarded.
func applyInit(ctx context.Context, conn *pgx.Conn, script guard.Script) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if err := script.Apply(ctx, tx); err != nil {
			return err
		}
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
	})
}
