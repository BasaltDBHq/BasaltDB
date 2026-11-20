package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engineaddr"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// basalt init --setup-code runs on the person's own computer (CONTRACT.md,
// Setup from your laptop). It runs a setup code that basalt init --remote
// made on the agent's machine, with the admin connection string, which is
// asked here and never stored (CO-9). The SQL comes from this binary, never
// from the code: the code gives only parameters, each checked. It writes no
// engine config and no credential file: the agent's machine keeps those and
// its own operatedBy, so this command takes no --operated-by.

const flagSetupCode = "setup-code"

// setupCodeOS are the platforms basalt init --setup-code runs on in M4
// (CO-19).
var setupCodeOS = map[string]bool{"darwin": true, "linux": true}

// setupCodeFlags are basalt init --setup-code's flags after parsing.
type setupCodeFlags struct {
	code, passkeyLabel string
	// engineURL is --engine-url in its written form, "" when not given.
	engineURL               string
	agentRLS                AgentRLSMode
	yes, addPasskey, dryRun bool
}

// isSetupCode reports whether args ask for basalt init --setup-code.
func isSetupCode(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && name == flagSetupCode {
			return true
		}
	}
	return false
}

func parseInitSetupCode(c *cliIO, args []string) (setupCodeFlags, error) {
	var f setupCodeFlags
	fs := c.flags("init --setup-code")
	fs.StringVar(&f.code, flagSetupCode, "", "the setup code your agent gave you (basalt-setup.1....)")
	fs.BoolVar(&f.yes, "yes", false, "do not ask before running the SQL")
	fs.BoolVar(&f.addPasskey, "add-passkey", false, "register another portal passkey even if one is registered")
	fs.StringVar(&f.passkeyLabel, "passkey-label", "", "name of the passkey in the picker (default: <database> · <agent> · <date>)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print what the code does and its SQL, and run nothing")
	fs.StringVar(&f.engineURL, "engine-url", "", "your tunnel's address for the agent's engine (https://<host>[:<port>]), recorded with the engine's key")
	f.agentRLS = AgentRLSAsk
	fs.Var(&f.agentRLS, "agent-rls",
		"on agent tables where row-level security hides every row: ask at a terminal, all-rows adds a policy letting the agent see them all, none skips the question")
	if err := parse(fs, args); err != nil {
		return f, err
	}
	if strings.TrimSpace(f.code) == "" {
		return f, fmt.Errorf("%w: --setup-code needs the code", errUsage)
	}
	if f.engineURL != "" {
		u, err := engineaddr.Parse(f.engineURL)
		if err != nil {
			return f, fmt.Errorf("%w: --engine-url: %w", errUsage, err)
		}
		f.engineURL = u
	}
	return f, nil
}

// laptopSetup is one run of basalt init --setup-code, on pkg/setup.
type laptopSetup struct {
	c    *cliIO
	f    setupCodeFlags
	p    setupcode.Payload
	desc setup.Description
	conn *pgx.Conn
}

// runInitSetupCode: basalt init --setup-code, in the contract's order.
// Every refusal before the transaction leaves the database as it was.
func runInitSetupCode(c *cliIO, args []string) int {
	if !helpAsked(args) {
		if err := c.agentContextError("basalt init --setup-code", hintAgentSetupCode); err != nil {
			return c.fail(err)
		}
	}
	f, err := parseInitSetupCode(c, args)
	if err != nil {
		return c.fail(err)
	}
	if !setupCodeOS[c.goos] {
		return c.fail(errors.New("basalt init --setup-code runs on macOS and Linux only for now"))
	}
	l, err := newLaptopSetup(c, f)
	if err != nil {
		return c.fail(err)
	}
	admin, err := c.adminURL()
	if err != nil {
		return c.fail(err)
	}
	if err := checkSetupTarget(l.p, admin); err != nil {
		return c.fail(err)
	}
	conn, err := c.dial(c.ctx, admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	l.conn = conn
	if err := l.run(); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// newLaptopSetup applies the checks that need no database (step 1,
// setup.Describe) and keeps the decoded code for the target check, which
// reads the admin connection string before anything connects.
func newLaptopSetup(c *cliIO, f setupCodeFlags) (*laptopSetup, error) {
	desc, err := setup.Describe(setup.Request{Code: f.code, Now: c.now(), EngineURL: f.engineURL})
	if err != nil {
		return nil, err
	}
	p, err := setupcode.Decode(f.code)
	if err != nil {
		return nil, err
	}
	return &laptopSetup{c: c, f: f, p: p, desc: desc}, nil
}

func (l *laptopSetup) request() setup.Request {
	return setup.Request{Code: l.f.code, Now: l.c.now(), EngineURL: l.f.engineURL}
}

// errDryRun stops a dry run after the SQL is shown.
var errDryRun = errors.New("dry run")

// run checks the database, shows the summary, asks the questions, shows
// the SQL, asks, and runs it all in one transaction, then registers the
// portal passkey (steps 4 to 8).
func (l *laptopSetup) run() error {
	c := l.c
	checked, err := setup.Check(c.ctx, l.conn, l.request())
	if err != nil {
		return err
	}
	if n := checked.NothingToDo; n != nil {
		l.nothingToDo(*n)
		return nil
	}
	for _, line := range checked.Summary {
		fmt.Fprintln(c.stdout, line)
	}
	var answers setup.Answers
	if answers.Revoke, err = l.engineSummary(checked); err != nil {
		return err
	}
	fmt.Fprintln(c.stdout)
	if answers.AllRows, err = l.rowSecurity(checked.Questions.RowSecurity); err != nil {
		return err
	}
	res, err := setup.Run(c.ctx, l.conn, l.request(), setup.RunInput{
		Answers: answers, AddPasskey: l.f.addPasskey, Approve: l.approve, Committed: l.committed, AskPasskey: l.portalPasskey,
	})
	if errors.Is(err, errDryRun) {
		return nil
	}
	if err != nil {
		return err
	}
	if n := res.NothingToDo; n != nil { // the guard was upgraded since Check
		l.nothingToDo(*n)
		return nil
	}
	if res.Passkey != nil {
		fmt.Fprintf(c.stderr, "basalt: passkey registered for %s\n", res.Passkey.RPID)
	}
	fmt.Fprintf(c.stdout, "Done. Tell %s to check its status.\n", l.desc.AgentWord)
	if res.EngineRecorded && l.f.engineURL != "" {
		fmt.Fprintln(c.stdout, "Pin it on each device you approve from:")
		fmt.Fprintln(c.stdout, pinAddURL)
	}
	return nil
}

// nothingToDo says an UPGRADE code has nothing to upgrade.
func (l *laptopSetup) nothingToDo(n setup.NothingToDo) {
	fmt.Fprintf(l.c.stderr, "basalt: the guard is already at version %d and this code upgrades it to version %d: nothing to upgrade; nothing changed\n",
		n.Installed, n.To)
}

// rowSecurity answers the row-level security questions as basalt init does
// (agentPolicies): the tables the person lets the agent see all rows of.
func (l *laptopSetup) rowSecurity(questions []setup.RowSecurityQuestion) ([]string, error) {
	texts := make([]string, 0, len(questions))
	for _, q := range questions {
		texts = append(texts, q.Text)
	}
	yes, err := rlsAnswers(l.c, l.f.agentRLS, l.f.yes || l.f.dryRun, texts)
	if err != nil {
		return nil, err
	}
	var out []string
	for i, q := range questions {
		if yes[i] {
			out = append(out, q.Table)
		}
	}
	return out, nil
}

// approve shows the SQL and the plan's warnings, then stops a dry run, or
// asks "Run this?" unless --yes.
func (l *laptopSetup) approve(plan setup.Plan) error {
	c := l.c
	fmt.Fprint(c.stdout, plan.SQL)
	printWarningLines(c.stderr, plan.Warnings)
	if l.f.dryRun {
		fmt.Fprintln(c.stderr, "basalt: dry run; nothing ran")
		return errDryRun
	}
	if l.f.yes {
		return nil
	}
	ok, err := c.confirm("Run this?")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("canceled; nothing changed")
	}
	return nil
}

// committed says the setup is recorded, with the warnings about tables
// the agent cannot see.
func (l *laptopSetup) committed(res setup.Result) {
	fmt.Fprintf(l.c.stderr, "basalt: setup %s recorded\n", res.SetupID)
	printWarningLines(l.c.stderr, res.Warnings)
}

// portalPasskey is the passkey step (step 7): print and open the portal's
// registration link, read the pasted code and verify it.
func (l *laptopSetup) portalPasskey(context.Context) (setup.Passkey, error) {
	c := l.c
	db := l.conn.Config().Database
	req, err := setup.NewPasskeyRequest(c.rand, setupPasskeyLabel(l.f.passkeyLabel, l.p, db, c.now()), db)
	if err != nil {
		return setup.Passkey{}, err
	}
	link, err := req.Link()
	if err != nil {
		return setup.Passkey{}, err
	}
	if err := showRegistrationLink(c, link, c.interactive); err != nil {
		return setup.Passkey{}, err
	}
	code, err := pastedRegistrationCode(c)
	if err != nil {
		return setup.Passkey{}, err
	}
	return req.Verify(code)
}

// plan is the setup's SQL as Run builds it, with no row-level security
// policy and no engine revoked.
func (l *laptopSetup) plan() (guard.Script, error) {
	s, err := setuprun.New(l.f.code, l.c.now(), l.f.engineURL)
	if err != nil {
		return guard.Script{}, err
	}
	p, err := s.Prepare(l.c.ctx, l.conn)
	if err != nil {
		return guard.Script{}, err
	}
	return p.Plan(l.c.ctx, nil, nil)
}

// upgradeDone is whether an UPGRADE code has nothing to add
// (setuprun.UpgradeDone).
func upgradeDone(p setupcode.Payload, installed int) bool { return setuprun.UpgradeDone(p, installed) }

// applySetup runs script in one transaction, record_setup last
// (setuprun.ApplySetup).
func applySetup(ctx context.Context, conn *pgx.Conn, script guard.Script) error {
	return setuprun.ApplySetup(ctx, conn, script)
}

// refused turns a failed transaction into what the person reads
// (setuprun.Refused).
func (l *laptopSetup) refused(err error) error {
	ctx := context.Background()
	if l.c != nil {
		ctx = l.c.ctx
	}
	return setuprun.Refused(ctx, l.conn, l.p, err)
}

// setupPasskeyLabel is the passkey's name: the flag, or the default. An
// UPGRADE code carries no agent, so its default has no agent part.
func setupPasskeyLabel(flagLabel string, p setupcode.Payload, database string, now time.Time) string {
	if flagLabel != "" {
		return flagLabel
	}
	agent := ""
	if p.Agent != nil {
		agent = p.Agent.Name
	}
	return defaultPasskeyLabel(database, agent, now)
}

// checkSetupTarget refuses an admin connection string that names another
// database than the code's target (step 3, CO-17), before anything
// connects. It first applies the admin URL rules basalt init has (a
// postgres:// URL that parses), and refuses a URL whose parameters, a
// service file or the environment would make pgx connect elsewhere than
// the URL itself names; setuprun.CheckTarget compares the databases.
func checkSetupTarget(p setupcode.Payload, admin string) error {
	if _, err := guard.AgentConnString(admin, "", ""); err != nil {
		return err
	}
	u, err := url.Parse(admin)
	if err != nil {
		return guard.ErrAdminURLParse
	}
	got, err := setupcode.TargetOf(u)
	if err != nil {
		return fmt.Errorf("the admin %w", err)
	}
	if err := sameEffectiveTarget(admin, got); err != nil {
		return err
	}
	return setuprun.CheckTarget(p, got, u)
}

// sameEffectiveTarget refuses an admin string that pgx would connect
// somewhere else than its URL names (PGPORT when the URL has no port, a
// service file): the target check must compare where init really goes.
func sameEffectiveTarget(admin string, t setupcode.Target) error {
	cfg, err := pgconn.ParseConfig(admin)
	if err != nil {
		return errors.New("the admin connection string cannot be used (pgx refuses it); check its parameters")
	}
	same := func(host string, port uint16) bool {
		return strings.EqualFold(host, t.Host) && int(port) == t.Port
	}
	ok := same(cfg.Host, cfg.Port) && cfg.Database == t.Database
	for _, fb := range cfg.Fallbacks {
		ok = ok && same(fb.Host, fb.Port)
	}
	if !ok {
		return errors.New("the admin connection string would connect elsewhere than its URL names (PGPORT or PGDATABASE in the environment, or a service file); put the host, port and database in the URL and drop service=")
	}
	return nil
}

// sameDatabase compares by database identity (setuprun.SameDatabase).
func sameDatabase(want, got setupcode.Target) bool { return setuprun.SameDatabase(want, got) }
