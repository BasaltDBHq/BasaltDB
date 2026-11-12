package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
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

// portalRP is the relying party of an agent-operated engine's passkeys:
// the portal, RP ID basaltvault.app (CO-8).
var portalRP = passkey.Relying{RPID: passkey.RPID, Origin: links.Portal}

// setupCodeFlags are basalt init --setup-code's flags after parsing.
type setupCodeFlags struct {
	code, passkeyLabel      string
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
	fs.StringVar(&f.passkeyLabel, "passkey-label", "", "name of the passkey in the picker (default: the database name)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print what the code does and its SQL, and run nothing")
	f.agentRLS = AgentRLSAsk
	fs.Var(&f.agentRLS, "agent-rls",
		"on agent tables where row-level security hides every row: ask at a terminal, all-rows adds a policy letting the agent see them all, none skips the question")
	if err := parse(fs, args); err != nil {
		return f, err
	}
	if strings.TrimSpace(f.code) == "" {
		return f, fmt.Errorf("%w: --setup-code needs the code", errUsage)
	}
	return f, nil
}

// laptopSetup is one run of basalt init --setup-code.
type laptopSetup struct {
	c       *cliIO
	f       setupCodeFlags
	p       setupcode.Payload
	names   guard.Names
	id      uuid.UUID
	expires time.Time
	conn    *pgx.Conn
}

// runInitSetupCode: basalt init --setup-code, in the contract's order.
// Every refusal before the transaction leaves the database as it was.
func runInitSetupCode(c *cliIO, args []string) int {
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

// newLaptopSetup decodes and validates the code, then applies this
// computer's checks: its clock and this binary's guard (step 1).
func newLaptopSetup(c *cliIO, f setupCodeFlags) (*laptopSetup, error) {
	p, err := setupcode.Decode(f.code)
	if err != nil {
		return nil, err
	}
	if err := setupcode.CheckLocal(p, c.now(), guard.LatestVersion()); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(p.SetupID)
	if err != nil {
		return nil, err
	}
	expires, err := p.ExpiresTime()
	if err != nil {
		return nil, err
	}
	return &laptopSetup{c: c, f: f, p: p, names: guard.Names{Prefix: p.Prefix}, id: id, expires: expires}, nil
}

// run reads the database's state, shows the summary and the SQL, asks,
// and runs it all in one transaction, then registers the portal passkey.
func (l *laptopSetup) run() error {
	c := l.c
	db, state, err := l.readDatabase()
	if err != nil {
		return err
	}
	if err := setupcode.CheckDatabase(l.p, db); err != nil {
		return err
	}
	if upgradeDone(l.p, state.GuardVersion) {
		fmt.Fprintf(c.stderr, "basalt: the guard is already at version %d and this code upgrades it to version %d: nothing to upgrade; nothing changed\n",
			state.GuardVersion, l.p.Guard.To)
		return nil
	}
	for _, line := range setupcode.Summary(l.p, state) {
		fmt.Fprintln(c.stdout, line)
	}
	fmt.Fprintln(c.stdout)
	script, err := l.plan()
	if err != nil {
		return missingTablesHint(err, l.conn.Config().Database)
	}
	fmt.Fprint(c.stdout, script.SQL())
	if l.f.dryRun {
		fmt.Fprintln(c.stderr, "basalt: dry run; nothing ran")
		return nil
	}
	if !l.f.yes {
		ok, err := c.confirm("Run this?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("canceled; nothing changed")
		}
	}
	if err := applySetup(c.ctx, l.conn, script); err != nil {
		return l.refused(err)
	}
	fmt.Fprintf(c.stderr, "basalt: setup %s recorded\n", l.p.SetupID)
	if l.p.Agent != nil {
		role := l.p.Role()
		warnRLSBlind(c, l.conn, role, l.spec())
	}
	if err := l.passkey(); err != nil {
		return fmt.Errorf("the setup ran but no passkey was registered: %w. Ask %s for a new code; running it registers the passkey", err, agentWord(l.p))
	}
	fmt.Fprintf(c.stdout, "Done. Tell %s to check its status.\n", agentWord(l.p))
	return nil
}

// upgradeDone is whether an UPGRADE code has nothing to add: the installed
// guard already has every migration up to the code's guard.to (or is
// newer). No guard installed is not done: the code installs it.
func upgradeDone(p setupcode.Payload, installed int) bool {
	if p.Kind != setupcode.KindUpgrade || installed == 0 {
		return false
	}
	var upTo []guard.Migration
	for _, m := range guard.Migrations() {
		if m.Version <= p.Guard.To {
			upTo = append(upTo, m)
		}
	}
	st := guard.StatusAt(installed, upTo)
	return st.State == guard.GuardOK || st.State == guard.GuardNewer
}

// agentWord names the agent in messages: its name, or "your agent" for an
// UPGRADE code.
func agentWord(p setupcode.Payload) string {
	if p.Agent == nil {
		return "your agent"
	}
	return p.Agent.Name
}

// readDatabase reads what the checks and the summary need (step 4).
func (l *laptopSetup) readDatabase() (setupcode.Database, setupcode.SummaryState, error) {
	ctx, q := l.c.ctx, l.conn
	var db setupcode.Database
	var state setupcode.SummaryState
	var err error
	if db.Prefix, err = guard.InstalledPrefix(ctx, q); err != nil {
		return db, state, err
	}
	if state.GuardVersion, err = guard.InstalledVersion(ctx, q); err != nil {
		return db, state, err
	}
	role := l.p.Role()
	if db.Setups, err = guard.SetupsFor(ctx, q, l.id, role); err != nil {
		return db, state, err
	}
	if role == "" {
		return db, state, nil
	}
	exists, err := guard.AgentRoleExists(ctx, q, l.names, l.p.Agent.Name)
	if err != nil || !exists {
		return db, state, err
	}
	db.Roles = []string{role}
	if l.p.Kind == setupcode.KindAgent {
		now, err := guard.RoleStatementTimeout(ctx, q, role)
		if err != nil {
			return db, state, err
		}
		want := l.p.Agent.StatementTimeoutMs
		state.TimeoutNow = timeoutNow(now.AllDatabases, want)
		if now.ThisDatabase != "" {
			state.TimeoutThisDatabase = timeoutNow(now.ThisDatabase, want)
		}
	}
	return db, state, nil
}

// timeoutNow is the role's current statement_timeout as the summary shows
// it, or "" when it is the code's.
func timeoutNow(setting string, want int64) string {
	if setting == "" {
		return "not set"
	}
	ms, ok := settingMillis(setting)
	switch {
	case ok && ms == want:
		return ""
	case ok:
		return strconv.FormatInt(ms, 10) + " ms"
	default:
		return printableLabel(setting)
	}
}

// settingMillis reads a time setting as Postgres stores it: a number of
// milliseconds, or a number with a unit.
func settingMillis(s string) (int64, bool) {
	units := []struct {
		suffix string
		ms     int64
	}{{"ms", 1}, {"min", 60000}, {"s", 1000}, {"h", 3600000}, {"d", 86400000}, {"", 1}}
	for _, u := range units {
		num, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64); err == nil {
			return n * u.ms, true
		}
	}
	return 0, false
}

// spec is the agent part of the code as an install input.
func (l *laptopSetup) spec() guard.AgentSpec {
	a := l.p.Agent
	return guard.AgentSpec{
		Name: a.Name, Write: a.Write, Read: a.Read, Verifier: a.Verifier,
		CreateOnly: l.p.Kind == setupcode.KindInstall, Change: l.p.Kind == setupcode.KindAgent,
		StatementTimeout: time.Duration(a.StatementTimeoutMs) * time.Millisecond,
	}
}

// plan asks the row-level security questions and builds the SQL: the
// migrations up to the code's guard.to, the role (taken over only when it
// is a plain agent: agentAdoptSQL runs first), the grants, the confirmed
// policies, attach, and record_setup last (step 6).
func (l *laptopSetup) plan() (guard.Script, error) {
	opts := guard.InitOptions{Names: l.names, UpTo: l.p.Guard.To}
	if l.p.Agent != nil {
		opts.Agent = l.spec()
		policies, err := agentPolicies(l.c, l.conn, l.names, initFlags{
			agent: l.p.Agent.Name, spec: opts.Agent, agentRLS: l.f.agentRLS, yes: l.f.yes, dryRun: l.f.dryRun,
		})
		if err != nil {
			return guard.Script{}, err
		}
		opts.AgentPolicies = policies
	}
	script, err := guard.PlanInit(l.c.ctx, l.conn, opts)
	if err != nil {
		return guard.Script{}, err
	}
	agent := ""
	if l.p.Agent != nil {
		agent = l.p.Agent.Name
	}
	record, err := guard.RecordSetupStatement(l.names, guard.Setup{
		ID: l.id, Kind: string(l.p.Kind), Agent: agent, GuardVersion: l.p.Guard.To, ExpiresAt: l.expires,
	})
	if err != nil {
		return guard.Script{}, err
	}
	script.Statements = append(script.Statements, record)
	return script, nil
}

// applySetup runs script in one transaction. Its last statement is
// record_setup, run after every other one and after the coverage check, so
// the setup is recorded only with everything it sets up; any failure rolls
// all of it back.
func applySetup(ctx context.Context, conn *pgx.Conn, script guard.Script) error {
	n := len(script.Statements)
	if n == 0 {
		return errors.New("nothing to run")
	}
	return applyInit(ctx, conn, guard.Script{Statements: script.Statements[:n-1]}, script.Statements[n-1])
}

// refused turns a failed transaction into what the person reads. Nothing
// changed: the transaction rolled back. A refusal by record_setup gets the
// contract's words (USED and SUPERSEDED with the time, read again).
func (l *laptopSetup) refused(err error) error {
	agent := agentWord(l.p)
	if detail, ok := guard.SetupRefusal(err); ok {
		switch setupcode.Refusal(detail) {
		case setupcode.RefusalUsed, setupcode.RefusalSuperseded:
			if db, _, rerr := l.readDatabase(); rerr == nil {
				if cerr := setupcode.CheckDatabase(l.p, db); cerr != nil {
					return cerr
				}
			}
			return fmt.Errorf("the database refused this setup code (%s): it, or a newer one for %s, already ran. Ask %s for a new one", detail, agent, agent)
		case setupcode.RefusalExpired:
			return fmt.Errorf("this setup code expired on %s by the database's clock. Ask %s for a new one", l.expires.UTC().Format("2006-01-02 15:04 UTC"), agent)
		default:
			return fmt.Errorf("the database's clock refuses this setup code (%s): check the database's and this computer's clocks, or ask %s for a new code", detail, agent)
		}
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Detail != "" || pg.Hint != "") {
		return fmt.Errorf("%w: %s Nothing changed.", err, sentences(pg.Detail, pg.Hint)) //nolint:staticcheck // full sentences after Postgres's message, shown as is
	}
	return fmt.Errorf("%w; nothing changed", err)
}

// passkey registers a portal passkey when no active one belongs to the
// portal, or with --add-passkey (step 7).
// sentences joins the non-empty parts with one space, each ending with a
// period.
func sentences(parts ...string) string {
	var out []string
	for _, s := range parts {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.HasSuffix(s, ".") {
			s += "."
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func (l *laptopSetup) passkey() error {
	keys, err := guard.ActivePasskeys(l.c.ctx, l.conn)
	if err != nil {
		return err
	}
	has := false
	for _, k := range keys {
		has = has || k.Origin == portalRP.Origin
	}
	if has && !l.f.addPasskey {
		return nil
	}
	label := l.f.passkeyLabel
	if label == "" {
		label = l.conn.Config().Database
	}
	if err := registerPasskey(l.c, l.conn, portalRP, label, l.c.interactive); err != nil {
		return err
	}
	fmt.Fprintf(l.c.stderr, "basalt: passkey registered for %s\n", portalRP.RPID)
	return nil
}

// checkSetupTarget refuses an admin connection string that names another
// database than the code's target (step 3, CO-17): with a Supabase project
// ref, the same ref and database; otherwise the same host, port and
// database. It first applies the admin URL rules basalt init has (a
// postgres:// URL that parses), and refuses a URL whose parameters, a
// service file or the environment would make pgx connect elsewhere than
// the URL itself names.
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
	if sameDatabase(p.Target, got) {
		return nil
	}
	want := targetWords(p.Target)
	return fmt.Errorf("This setup code is for database %s of %s (the agent connects there). Your admin connection string points at database %s of %s. "+ //nolint:staticcheck // the contract's sentence, shown as is
		"Either run this command with the admin connection string of %s, or ask %s for a new code for the database you meant "+
		"(basalt init --remote --new-code --database-url %s).",
		p.Target.Database, want, got.Database, targetWords(got), want, agentWord(p), withoutPassword(u))
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

// sameDatabase compares by database identity (CO-17): a Supabase project
// by its ref and database name, so its pooler and direct hosts match;
// anything else by host, port and database.
func sameDatabase(want, got setupcode.Target) bool {
	if want.SupabaseRef != "" {
		return got.SupabaseRef == want.SupabaseRef && got.Database == want.Database
	}
	return strings.EqualFold(got.Host, want.Host) && got.Port == want.Port && got.Database == want.Database
}

// targetWords names where a target is: a Supabase project, or host:port.
func targetWords(t setupcode.Target) string {
	if t.SupabaseRef != "" {
		return "Supabase project " + t.SupabaseRef
	}
	return fmt.Sprintf("%s:%d", printableLabel(t.Host), t.Port)
}

// withoutPassword is the admin URL's scheme, user, host, port and database,
// with no password and no parameters: what the person may give the agent.
func withoutPassword(u *url.URL) string {
	out := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	if name := u.User.Username(); name != "" {
		out.User = url.User(name)
	}
	return out.String()
}
