package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// basalt init --remote runs on the engine's machine, which the agent may
// control, with no admin credential (CONTRACT.md, Setup from your laptop;
// CO-9). It keeps the agent's password here, writes the credential file and
// engine.json with the pending setup, and prints a setup code carrying only
// the password's SCRAM verifier. The person runs the code on their own
// computer with the admin connection string (basalt init --setup-code).

const (
	flagRemote      = "remote"
	flagDatabaseURL = "database-url"
	// pendingSuffix names the new password's file while an AGENT code that
	// rotates it waits: the old password keeps working until the person runs
	// the code (RI-5).
	pendingSuffix = ".pending"
	// lockSuffix names the lock file that keeps two runs of init --remote
	// for one agent apart.
	lockSuffix = ".lock"
	// releasePage is where the person installs basalt on their own computer.
	releasePage = "https://github.com/BasaltDBHq/BasaltDB/releases"
	// loginTimeout bounds the agent's login that decides the code's kind.
	loginTimeout = 15 * time.Second
	toolStatus   = "status"
)

// sqlstateClassAuth is the SQLSTATE class of a refused login:
// invalid_password (28P01) and invalid_authorization_specification (28000:
// no such role, a pg_hba refusal).
const sqlstateClassAuth = "28"

// sqlstateInternal is internal_error, which Supabase's pooler raises for a
// user it does not know (supavisorNoTenant).
const sqlstateInternal = "XX000"

// OperatedBy is the value of --operated-by: who runs the machine steps on
// this engine's machine. CLI input spelling only; engine.json holds the
// enum (mcpcontract.OperatedByPerson or OperatedByAgent).
type OperatedBy string

// --operated-by values.
const (
	OperatedByPerson OperatedBy = "person"
	OperatedByAgent  OperatedBy = "agent"
)

// String implements flag.Value.
func (o *OperatedBy) String() string { return string(*o) }

// Set implements flag.Value, refusing anything but the two values.
func (o *OperatedBy) Set(v string) error {
	switch OperatedBy(v) {
	case OperatedByPerson, OperatedByAgent:
		*o = OperatedBy(v)
		return nil
	}
	return fmt.Errorf("must be %s or %s", OperatedByPerson, OperatedByAgent)
}

// settingOf is the enum when given, else "" (the config's stays).
func (o OperatedBy) settingOf(given bool) string {
	if !given {
		return ""
	}
	return o.enum()
}

// enum is the value engine.json stores.
func (o OperatedBy) enum() string {
	if o == OperatedByAgent {
		return mcpcontract.OperatedByAgent
	}
	return mcpcontract.OperatedByPerson
}

// remoteFlags are basalt init --remote's flags after parsing.
type remoteFlags struct {
	agent, write, read, prefix, configPath, databaseURL string
	timeout                                             time.Duration
	operatedBy                                          OperatedBy
	newCode, json, configGiven                          bool
	spec                                                guard.AgentSpec
	// vaultFlag is --vault as given ("" when not); vault is what init
	// asks the config's vault to be (chooseVault).
	vaultFlag VaultMode
	vault     vaultChoice
}

// RemoteInitResult is what basalt init --remote --json prints
// (api/mcp/setup/remote-init-result.schema.json).
type RemoteInitResult struct {
	Agent         string           `json:"agent"`
	SetupID       string           `json:"setupId"`
	Kind          string           `json:"kind"`
	Code          string           `json:"code"`
	Fingerprint   string           `json:"fingerprint"`
	Reused        bool             `json:"reused,omitempty"`
	ExpiresAt     string           `json:"expiresAt"`
	PersonMessage string           `json:"personMessage"`
	NextSteps     []agent.NextStep `json:"nextSteps"`
}

// isRemote reports whether args ask for basalt init --remote.
func isRemote(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != flagRemote {
			continue
		}
		on, err := strconv.ParseBool(value)
		return !hasValue || (err == nil && on)
	}
	return false
}

// databaseURLArg is the value of --database-url in args, read before the
// flags are parsed so a password is refused before anything else.
func databaseURLArg(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != flagDatabaseURL {
			continue
		}
		if !hasValue && i+1 < len(args) {
			i++
			value = args[i]
		}
		out = append(out, value)
	}
	return out
}

// runInitRemote: basalt init --remote.
func runInitRemote(c *cliIO, args []string) int {
	for _, v := range databaseURLArg(args) {
		if setupcode.HasPassword(v) {
			return c.fail(setupcode.ErrHasPassword)
		}
	}
	f, err := parseInitRemote(c, args)
	if err != nil {
		return c.fail(err)
	}
	r, err := newRemoteInit(c, f)
	if err != nil {
		return c.fail(err)
	}
	res, err := r.run()
	r.unlock()
	if err != nil {
		return c.fail(err)
	}
	if err := printRemoteResult(c, f, res); err != nil {
		return c.fail(err)
	}
	return exitOK
}

func parseInitRemote(c *cliIO, args []string) (remoteFlags, error) {
	var f remoteFlags
	var remote bool
	fs := c.flags("init --remote")
	fs.BoolVar(&remote, flagRemote, false, "make a setup code on this machine, which has no admin credential; the person runs it on their own computer")
	fs.StringVar(&f.agent, "agent", "", "agent name (lowercase letters, digits, _); its role is <prefix>_agent_<name>")
	fs.StringVar(&f.write, "write", "", "comma-separated schema.table the agent may read and write")
	fs.StringVar(&f.read, "read", "", "comma-separated schema.table the agent may only read")
	fs.StringVar(&f.prefix, "prefix", guard.DefaultPrefix, "role name prefix")
	fs.DurationVar(&f.timeout, "statement-timeout", guard.DefaultStatementTimeout, "query time limit of the agent role")
	f.operatedBy = OperatedByPerson
	fs.Var(&f.operatedBy, "operated-by", "who runs this engine's machine steps: person or agent")
	fs.StringVar(&f.databaseURL, flagDatabaseURL, "", "the database's connection string WITHOUT a password; needed on the agent's first run")
	fs.BoolVar(&f.newCode, "new-code", false, "make a new code (and a new agent password) even when one is pending")
	fs.StringVar(&f.configPath, "config", config.DefaultPath(c.goos), "engine config file")
	fs.BoolVar(&f.json, "json", false, "print the result as JSON (remote-init-result.schema.json)")
	fs.Var(&f.vaultFlag, flagVault, "on or off: whether the engine reaches the portal's pages through the Vault (default on with --operated-by=agent, else off)")
	if err := parse(fs, args); err != nil {
		return f, err
	}
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "config" {
			f.configGiven = true
		}
	})
	if f.agent == "" {
		return f, fmt.Errorf("%w: --agent is required", errUsage)
	}
	if !config.ValidAgentName(f.agent) {
		return f, fmt.Errorf("%w: agent name %q is not valid for the engine", errUsage, f.agent)
	}
	if _, err := (guard.Names{Prefix: f.prefix}).Agent(f.agent); err != nil {
		return f, fmt.Errorf("%w: %w", errUsage, err)
	}
	f.spec = guard.AgentSpec{Name: f.agent, Write: splitList(f.write), Read: splitList(f.read), StatementTimeout: f.timeout}
	vc, err := chooseVault(f.vaultFlag, f.operatedBy, links.Portal, "default for --operated-by=person; --vault=on to turn it on")
	if err != nil {
		return f, err
	}
	f.vault = vc
	return f, nil
}

// savedArgs are the flags --remote saves to engine.json for the agent: the
// ones whose value is not the default, plus --agent and --os-user. Never
// the connection string, a password or a one-shot flag.
func (f remoteFlags) savedArgs(osUser string) []string {
	args := []string{"--agent=" + f.agent}
	addIf := func(name, value, def string) {
		if value != "" && value != def {
			args = append(args, "--"+name+"="+value)
		}
	}
	addIf("write", f.write, "")
	addIf("read", f.read, "")
	addIf("prefix", f.prefix, guard.DefaultPrefix)
	addIf("statement-timeout", f.timeout.String(), guard.DefaultStatementTimeout.String())
	addIf("os-user", osUser, "")
	addIf("operated-by", string(f.operatedBy), string(OperatedByPerson))
	return args
}

// requestFlags are the saved flags whose change asks for a new AGENT code.
var requestFlags = []string{"write", "read", "prefix", "statement-timeout"}

// sameRequest reports whether two saved flag lists ask for the same tables,
// prefix and statement timeout.
func sameRequest(a, b []string) bool {
	for _, name := range requestFlags {
		if savedValue(a, name) != savedValue(b, name) {
			return false
		}
	}
	return true
}

// savedValue is the value of --name=value in saved flags, "" when absent.
func savedValue(args []string, name string) string {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v
		}
	}
	return ""
}

// remoteInit is one run of basalt init --remote: the paths, the existing
// config and credential, and what logging in as the agent found.
type remoteInit struct {
	c        *cliIO
	f        remoteFlags
	names    guard.Names
	role     string
	settings config.Settings
	entry    *config.Agent
	credFile string
	osUser   string
	base     *url.URL
	target   setupcode.Target
	// password is the agent's password this machine holds for this
	// database: the one that logs in, else the newest (.pending first);
	// "" when it holds none.
	password string
	// credExists: the credential file exists, so a new password goes to
	// .pending (writeCredential).
	credExists bool
	// unlock releases the lock that keeps two runs for the agent apart.
	unlock func()
	// loggedIn: the role logs in with the credential (or its .pending one,
	// then moved over the credential file). installed is the guard version
	// it sees, recorded whether the pending setup is recorded.
	loggedIn, recorded bool
	installed          int
}

func newRemoteInit(c *cliIO, f remoteFlags) (*remoteInit, error) {
	r := &remoteInit{c: c, f: f, names: guard.Names{Prefix: f.prefix}}
	r.role, _ = r.names.Agent(f.agent) // checked by parseInitRemote
	if err := r.paths(); err != nil {
		return nil, err
	}
	unlock, err := lockFile(r.credFile + lockSuffix)
	if err != nil {
		return nil, err
	}
	r.unlock = unlock
	if err := r.connection(); err != nil {
		unlock()
		return nil, err
	}
	return r, nil
}

// paths finds the config, the agent's entry, its credential file and the
// settings of a new config. Without --config and not as root, the config
// lives in the user's own config directory, as init's foreground setup.
func (r *remoteInit) paths() error {
	dir := filepath.Dir(r.f.configPath)
	r.settings = r.f.vault.settings(config.Settings{SocketDir: config.DefaultSocketDir(r.c.goos), PagesURL: links.Portal, OperatedBy: r.f.operatedBy.enum()})
	if !r.f.configGiven && r.c.host.Euid() != 0 {
		base, err := r.c.host.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, perUserDirName)
		r.f.configPath = filepath.Join(dir, "engine.json")
		r.settings.SocketDir = filepath.Join(dir, "run")
	}
	if r.f.configPath != config.DefaultPath(r.c.goos) {
		r.settings.StateDir = filepath.Join(dir, stateDirName)
	}
	cfg, err := config.Load(r.f.configPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		r.settings.SocketDir = cfg.SocketDir
		for i := range cfg.Agents {
			if cfg.Agents[i].Name == r.f.agent {
				r.entry = &cfg.Agents[i]
			}
		}
	}
	if err := config.CheckSocketPath(config.SocketPath(r.settings.SocketDir, r.f.agent)); err != nil {
		return fmt.Errorf("%w; pass --config in a shorter directory", err)
	}
	r.credFile = filepath.Join(dir, "agents", r.f.agent+".url")
	r.osUser = ""
	if r.entry != nil {
		r.credFile, r.osUser = r.entry.CredentialFile, r.entry.OSUser
	}
	if r.osUser == "" {
		u, err := invokingUser()
		if err != nil {
			return err
		}
		r.osUser = u
	}
	return nil
}

// credential is a credential file as read: its connection string, the
// database it names, and the file it was read from (to check, before
// moving it, that the path still names that file).
type credential struct {
	dsn    string
	url    *url.URL
	target setupcode.Target
	file   os.FileInfo
}

func (c *credential) password() string {
	pw, _ := c.url.User.Password()
	return pw
}

// connection settles the database: --database-url, else the .pending
// credential's (a setup for another database may be waiting), else the
// credential file's. It logs in as the agent with the credentials for that
// database, .pending first.
func (r *remoteInit) connection() error {
	cred, err := readCredentialIfAny(r.credFile)
	if err != nil {
		return err
	}
	pending, err := readCredentialIfAny(r.credFile + pendingSuffix)
	if err != nil {
		return err
	}
	switch {
	case r.f.databaseURL != "":
		if r.base, r.target, err = setupcode.ParseConnURL(r.f.databaseURL); err != nil {
			return fmt.Errorf("%w: --database-url: %w", errUsage, err)
		}
	case pending != nil:
		r.base, r.target = pending.url, pending.target
	case cred != nil:
		r.base, r.target = cred.url, cred.target
	default:
		return fmt.Errorf("%w: --database-url is required on the agent's first run (the connection string without its password)", errUsage)
	}
	r.credExists = cred != nil
	if pending != nil && pending.target != r.target {
		pending = nil
	}
	if cred != nil && cred.target != r.target {
		cred = nil
	}
	// The password this machine holds for the database: the newest one.
	for _, c := range []*credential{cred, pending} {
		if c != nil {
			r.password = c.password()
		}
	}
	return r.login(pending, cred)
}

// readCredentialIfAny reads a credential file with the no-follow checks,
// or nil when there is none.
func readCredentialIfAny(path string) (*credential, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil //nolint:nilnil // no file is no credential
	}
	dsn, fi, err := readOwnCredential(path)
	if err != nil {
		return nil, fmt.Errorf("the credential file %s is not usable: %w", path, err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("the credential file %s does not hold a connection URL", path)
	}
	t, err := setupcode.TargetOf(u)
	var pe *setupcode.TargetParamError
	if errors.As(err, &pe) {
		// basalt init keeps these parameters; --remote can't target them.
		// The file is the running engine's credential: never treat it as
		// absent, or a new one would overwrite it.
		return nil, fmt.Errorf("the credential file %s was written by basalt init for a connection string with a %s= parameter, "+
			"which basalt init --remote can't target; it was left as is. Use another --agent name, or another --config", path, pe.Param)
	}
	if err != nil {
		return nil, fmt.Errorf("the credential file %s: %w", path, err)
	}
	return &credential{dsn: dsn, url: u, target: t, file: fi}, nil
}

// login logs in as the agent: with the .pending credential first (a
// setup the person may have run), which then replaces the credential
// file, else with the credential file. A refused login is not an error:
// the role cannot log in. An unreachable database is, and changes nothing.
func (r *remoteInit) login(pending, cred *credential) error {
	if pending != nil {
		conn, err := r.c.agentLogin(r.c.ctx, pending.dsn)
		switch {
		case err == nil:
			defer conn.Close(r.c.ctx)
			if err := r.promote(pending); err != nil {
				return err
			}
			r.password = pending.password()
			return r.inspect(conn)
		case !errors.Is(err, errLoginRefused):
			return err
		}
	}
	if cred == nil {
		return nil
	}
	conn, err := r.c.agentLogin(r.c.ctx, cred.dsn)
	switch {
	case errors.Is(err, errLoginRefused):
		return nil // the role cannot log in
	case err != nil:
		return err
	}
	r.password = cred.password()
	defer conn.Close(r.c.ctx)
	return r.inspect(conn)
}

// promote moves the .pending credential, which logs in, over the
// credential file, once the .pending path still names the file read.
func (r *remoteInit) promote(pending *credential) error {
	pendingFile := r.credFile + pendingSuffix
	now, err := os.Lstat(pendingFile)
	if err != nil {
		return err
	}
	if !os.SameFile(now, pending.file) {
		return fmt.Errorf("%s changed while basalt init ran; nothing changed, run it again", pendingFile)
	}
	if err := os.Rename(pendingFile, r.credFile); err != nil {
		return err
	}
	r.credExists = true
	return nil
}

// agentConn is the agent's own connection init --remote reads with.
type agentConn interface {
	guard.Querier
	Close(ctx context.Context) error
}

// errLoginRefused is a login the database refused: the agent's role does
// not exist or has another password.
var errLoginRefused = errors.New("the database refused the agent's login")

// supavisorNoTenant is what Supabase's pooler answers (SQLSTATE XX000) for a
// user it does not know, such as an agent role not created yet.
const supavisorNoTenant = "Tenant or user not found"

// loginAsAgent connects with dsn: errLoginRefused when the database
// refuses the login (class 28, or the pooler not knowing the role).
func loginAsAgent(ctx context.Context, dsn string) (agentConn, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	conn, err := connect(ctx, dsn)
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return conn, nil
	case errors.As(err, &pg) && (strings.HasPrefix(pg.Code, sqlstateClassAuth) ||
		(pg.Code == sqlstateInternal && strings.Contains(pg.Message, supavisorNoTenant))):
		return nil, errLoginRefused
	}
	return nil, fmt.Errorf("cannot reach the database to check the agent's role (nothing changed): %w", err)
}

// inspect reads, as the agent, the guard version and whether the pending
// setup is recorded.
func (r *remoteInit) inspect(conn agentConn) error {
	r.loggedIn = true
	v, err := guard.AgentVersion(r.c.ctx, conn)
	if err != nil {
		return err
	}
	r.installed = v
	if r.entry == nil || r.entry.Setup == nil {
		return nil
	}
	id, err := uuid.Parse(r.entry.Setup.SetupID)
	if err != nil {
		return nil //nolint:nilerr // a malformed pending setup is replaced, not reused
	}
	r.recorded, err = guard.SetupRecorded(r.c.ctx, conn, id)
	return err
}

// reusable is the pending setup init prints again: unexpired, not yet run,
// for the same tables, and no --new-code.
func (r *remoteInit) reusable(saved []string) *config.Setup {
	if r.entry == nil || r.entry.Setup == nil || r.f.newCode || r.recorded || r.password == "" {
		return nil
	}
	s := r.entry.Setup
	expires, err := s.Expires()
	if err != nil || !r.c.now().Before(expires) || !sameRequest(r.entry.InitArgs, saved) {
		return nil
	}
	return s
}

// plan is the code init makes: its kind, the password whose verifier it
// carries (rotate), whether that password is new (and so written: see
// writeCredential), and the guard versions.
type plan struct {
	kind                setupcode.Kind
	password            string
	rotate, newPassword bool
	from                int
}

// decide picks the kind (CONTRACT.md, basalt init --remote, item 3; RI-6).
// INSTALL when the role cannot log in, keeping the password this machine
// already holds for it so any of its INSTALL codes matches the credential.
// With --new-code after a setup that was not an INSTALL, a role that does
// not log in gets an AGENT code with a new password (RI-17). A role that
// logs in: AGENT for a change of tables or timeout, or with --new-code (a
// new password); else
// UPGRADE when its guard is older than this build's; else an AGENT code
// with no change.
func (r *remoteInit) decide(saved []string) (plan, error) {
	latest := guard.LatestVersion()
	pendingInstall := r.entry != nil && r.entry.Setup != nil && r.entry.Setup.Kind == string(setupcode.KindInstall)
	if !r.loggedIn {
		if r.f.newCode && r.password != "" && !pendingInstall {
			return r.withNewPassword(plan{kind: setupcode.KindAgent})
		}
		if r.password != "" {
			return plan{kind: setupcode.KindInstall, password: r.password, rotate: true}, nil
		}
		return r.withNewPassword(plan{kind: setupcode.KindInstall})
	}
	if r.installed > latest {
		return plan{}, fmt.Errorf("the database's guard (version %d) is newer than this basalt (version %d): update basalt on this machine first", r.installed, latest)
	}
	p := plan{from: r.installed}
	changed := r.entry == nil || !sameRequest(r.entry.InitArgs, saved)
	switch {
	case r.f.newCode:
		p.kind = setupcode.KindAgent
		return r.withNewPassword(p)
	case changed:
		p.kind = setupcode.KindAgent
	case r.installed < latest:
		p.kind = setupcode.KindUpgrade
	default:
		p.kind = setupcode.KindAgent
	}
	return p, nil
}

func (r *remoteInit) withNewPassword(p plan) (plan, error) {
	pw, err := setupcode.NewPassword()
	if err != nil {
		return plan{}, err
	}
	p.password, p.rotate, p.newPassword = pw, true, true
	return p, nil
}

// payload builds the setup code's content.
func (r *remoteInit) payload(p plan) (setupcode.Payload, error) {
	id, expires, err := setupcode.NewSetupID(r.c.now(), r.c.rand)
	if err != nil {
		return setupcode.Payload{}, err
	}
	out := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: p.kind, Prefix: r.f.prefix, Target: r.target,
		Guard: setupcode.Guard{From: p.from, To: guard.LatestVersion()}, Build: buildVersion(), ExpiresAt: expires,
	}
	if p.kind == setupcode.KindUpgrade {
		return out, nil
	}
	a := &setupcode.Agent{Name: r.f.agent, Write: r.f.spec.Write, Read: r.f.spec.Read, StatementTimeoutMs: r.f.timeout.Milliseconds()}
	if p.rotate {
		if a.Verifier, err = setupcode.NewVerifier(p.password); err != nil {
			return setupcode.Payload{}, err
		}
	}
	out.Agent = a
	return out, nil
}

// buildVersion is this build's version in the code's form (no leading v,
// no build metadata).
func buildVersion() string {
	v := strings.TrimPrefix(buildinfo.Version, "v")
	v, _, _ = strings.Cut(v, "+")
	return v
}

// run makes (or reuses) the code, writes the credential and the config,
// and returns the result.
func (r *remoteInit) run() (RemoteInitResult, error) {
	saved := r.f.savedArgs(r.osUser)
	if s := r.reusable(saved); s != nil {
		if err := r.writeConfig(saved, s); err != nil {
			return RemoteInitResult{}, err
		}
		return r.result(*s, true)
	}
	p, err := r.decide(saved)
	if err != nil {
		return RemoteInitResult{}, err
	}
	payload, err := r.payload(p)
	if err != nil {
		return RemoteInitResult{}, err
	}
	code, err := setupcode.Encode(payload)
	switch {
	case errors.Is(err, setupcode.ErrCodeTooLong):
		return RemoteInitResult{}, fmt.Errorf("the setup code would be longer than %d characters: name fewer tables", setupcode.MaxCodeLen)
	case err != nil:
		return RemoteInitResult{}, fmt.Errorf("%w: %s", errUsage, setupcode.InvalidDetail(err))
	}
	if err := r.writeCredential(p); err != nil {
		return RemoteInitResult{}, err
	}
	s := config.Setup{
		SetupID: payload.SetupID, Kind: string(p.kind), GuardVersion: payload.Guard.To,
		ExpiresAt: payload.ExpiresAt, Code: code, Fingerprint: payload.Fingerprint(),
	}
	if err := r.writeConfig(saved, &s); err != nil {
		return RemoteInitResult{}, err
	}
	return r.result(s, false)
}

// writeCredential writes a new password's connection string. It never
// replaces a credential file that exists: a login refused now may be a
// transient error, and the old password may still be the one that works,
// so the new one waits in .pending until a login proves it (the engine,
// or the next run of init, then moves it over). Only the first credential
// goes straight to the credential file. Both 0600, atomic, never through
// a symlink (config.WriteFile). A password this machine already holds is
// not written again.
func (r *remoteInit) writeCredential(p plan) error {
	if !p.newPassword {
		return nil
	}
	dsn, err := guard.AgentConnString(r.base.String(), r.role, p.password)
	if err != nil {
		return err
	}
	path := r.credFile
	if r.credExists {
		path += pendingSuffix
	}
	return config.WriteFile(path, []byte(dsn+"\n"))
}

// writeConfig upserts the agent and prints the vault value it wrote.
func (r *remoteInit) writeConfig(saved []string, s *config.Setup) error {
	v, err := config.UpsertAgentVault(r.f.configPath, r.settings, config.Agent{
		Name: r.f.agent, OSUser: r.osUser, CredentialFile: r.credFile, InitArgs: saved, Setup: s,
	})
	if err != nil {
		return err
	}
	fmt.Fprint(r.c.stderr, r.f.vault.line(v))
	return nil
}

// result is the remote-init result: the code, what the person does with
// it, and the steps (P RUN_COMMAND, P TELL_AGENT, A END_TURN, A CALL_TOOL
// status, as the catalog's SETUP_NOT_RUN).
func (r *remoteInit) result(s config.Setup, reused bool) (RemoteInitResult, error) {
	steps, err := setupSteps(s.Code)
	if err != nil {
		return RemoteInitResult{}, err
	}
	return RemoteInitResult{
		Agent: r.f.agent, SetupID: s.SetupID, Kind: s.Kind, Code: s.Code, Fingerprint: s.Fingerprint,
		Reused: reused, ExpiresAt: s.ExpiresAt, PersonMessage: setupPersonMessage(r.f.agent, s.Fingerprint), NextSteps: steps,
	}, nil
}

// setupCommand is what the person runs on their own computer.
func setupCommand(code string) string { return "basalt init --setup-code " + code }

func setupSteps(code string) ([]agent.NextStep, error) {
	return agent.NewSteps().
		RunCommand(setupCommand(code), "On your own computer, not the agent's machine: install basalt from the official release page, run this, and check it shows the same fingerprint.").
		TellAgent("Tell the agent once the command says Done.").
		EndTurn("End your turn: the person runs the setup code on their own computer and tells you when it is done.").
		CallTool(toolStatus, map[string]any{}, "When the person says it is done, call status to check that the setup finished.").
		Build()
}

// setupPersonMessage is what the agent shows the person verbatim, within
// agent.MaxPersonMessageLength for the longest agent name: it names the
// agent once.
func setupPersonMessage(name, fingerprint string) string {
	return fmt.Sprintf("Finish setting up Basalt for %s on your own computer, not the agent's machine. "+
		"Install basalt from the official release page:\n%s\n"+
		"then run the basalt init --setup-code command the agent gave you. Check that it shows the setup fingerprint %s, "+
		"then tell the agent it is done. Never paste your database password into this chat.",
		name, releasePage, fingerprint)
}

// printRemoteResult prints the result: JSON, or the code in a block of its
// own, its fingerprint and what the person does.
func printRemoteResult(c *cliIO, f remoteFlags, res RemoteInitResult) error {
	if res.Reused {
		fmt.Fprintln(c.stderr, "basalt: a setup code is pending for this agent; here it is again (--new-code makes a new one)")
	}
	if f.json {
		enc := json.NewEncoder(c.stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(res)
	}
	expires, err := time.Parse(time.RFC3339, res.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.stdout, "Setup code for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, expires.UTC().Format("2006-01-02 15:04 UTC"), res.Code, res.Fingerprint, res.PersonMessage)
	return err
}
