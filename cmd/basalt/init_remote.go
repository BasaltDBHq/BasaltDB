package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"

	"github.com/basaltdbhq/basaltdb/internal/app"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// basalt init --remote runs on the engine's machine, which the agent may
// control, with no admin credential (CONTRACT.md, basalt init --remote;
// CO-9). It takes --agent and nothing else: it keeps the agent's password
// here, writes engine.json with the pending setup, and prints the connect
// link of a setup code carrying only the password's SCRAM verifier. The
// person runs the code on the connect page. A pending setup that expired,
// was refused or names an address the engine refused is forgotten and
// replaced by a fresh code on the next run, with no flag.

const (
	flagRemote = "remote"
	// secretSuffix names the file that keeps the agent's password while a
	// connect-only code waits for the database's address (CONTRACT.md,
	// Connect-only setup codes): agents/<agent>.secret.
	secretSuffix = config.SecretSuffix
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

// enum is the value engine.json stores.
func (o OperatedBy) enum() string {
	if o == OperatedByAgent {
		return mcpcontract.OperatedByAgent
	}
	return mcpcontract.OperatedByPerson
}

// remoteVaultWhy says why the vault is off by default for an engine
// another init made person-operated.
const remoteVaultWhy = "default for a person-operated engine"

// remoteFlags are what basalt init --remote asks for: --agent, and the
// fixed values the removed flags used to change. The agent's tables are
// never among them: an INSTALL code lets the person tick them on the
// connect page, and an AGENT code keeps the role's grants (the database's
// grants are the only record of them).
type remoteFlags struct {
	agent, prefix, configPath string
	timeout                   time.Duration
	operatedBy                OperatedBy
	// vault is what init asks the config's vault to be (chooseVault).
	vault vaultChoice
}

// RemoteInitResult is what basalt init --remote prints.
type RemoteInitResult struct {
	Agent       string
	SetupID     string
	Kind        string
	Code        string
	Fingerprint string
	Reused      bool
	ExpiresAt   string
	// ConnectOnly is a connect-only code: only the connect page runs it.
	ConnectOnly   bool
	PersonMessage string
	// ConnectURL is the connect link, set when the engine is agent-operated
	// with the Vault on and the whole link fits the link budget
	// (CONTRACT.md, Connect, The connect link).
	ConnectURL string
	// MCPCommand is the basalt mcp command the agent registers, as argv.
	MCPCommand []string
	// pasteAtPortal: the engine would hand the connect link but the whole
	// link does not fit the budget, so the text output says to paste the
	// code at the connect page instead.
	pasteAtPortal bool
	// osUser is the OS user the MCP command runs as, for the text output.
	osUser string
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

// runInitRemote: basalt init --remote.
func runInitRemote(c *cliIO, args []string) int {
	res, err := initRemote(c, args)
	if err != nil {
		return c.fail(err)
	}
	if err := printRemoteResult(c, res); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// initRemote runs basalt init --remote and returns what it prints.
func initRemote(c *cliIO, args []string) (RemoteInitResult, error) {
	f, err := parseInitRemote(c, args)
	if err != nil {
		return RemoteInitResult{}, err
	}
	if c.getenv(envAdminURL) != "" {
		// Never used here, but whoever can read this environment holds
		// the admin password (CONTRACT.md, Agents and the admin credential).
		fmt.Fprintln(c.stderr, "basalt: warning: "+remoteAdminEnvSet)
	}
	if err := checkBuildVersion(buildVersion()); err != nil {
		return RemoteInitResult{}, err
	}
	r, err := newRemoteInit(c, f)
	if err != nil {
		return RemoteInitResult{}, err
	}
	res, err := r.run()
	r.unlock()
	return res, err
}

// parseInitRemote reads basalt init --remote's flags: --remote and
// --agent only (CONTRACT.md, CLI). The role's prefix and its statement
// timeout are fixed values.
func parseInitRemote(c *cliIO, args []string) (remoteFlags, error) {
	f := remoteFlags{prefix: cmp.Or(c.rolePrefix, guardmodel.DefaultPrefix), timeout: guardmodel.DefaultStatementTimeout, operatedBy: OperatedByAgent}
	var remote bool
	fs := c.flags("init --remote")
	fs.BoolVar(&remote, flagRemote, false, "set up an agent on a bot's machine: prints the connect link the person opens")
	fs.StringVar(&f.agent, "agent", "", "the agent's name (lowercase letters, digits, _); needed only when the engine serves more than one agent")
	if err := parse(fs, args); err != nil {
		return f, fmt.Errorf("%w (basalt init --remote takes only --agent; the connect page asks for the rest)", err)
	}
	f.configPath = cmp.Or(c.paths.config, c.systemConfig())
	return f, nil
}

// remoteAgentName is the agent a run without --agent sets up: the one
// agent the config has, else the default name. With more than one, --agent
// is required.
func remoteAgentName(agents []config.Agent) (string, error) {
	switch len(agents) {
	case 0:
		return app.DemoAgent, nil
	case 1:
		return agents[0].Name, nil
	}
	return "", fmt.Errorf("%w: this engine serves more than one agent: give --agent NAME", errUsage)
}

// remoteInit is one run of basalt init --remote: the paths, the existing
// config and credential, and what logging in as the agent found.
type remoteInit struct {
	c        *cliIO
	f        remoteFlags
	names    guardmodel.Names
	role     string
	settings config.Settings
	entry    *config.Agent
	credFile string
	// files reads and writes credFile, its .pending and its .lock: by
	// path, or as root through agents/ opened without following a link.
	files credFiles
	// configDir is, as root, the config directory opened without following
	// a link anyone but root controls: engine.json is locked, read and
	// written relative to it (nil not as root: by path).
	configDir *rootConfigDir
	osUser    string
	base      *url.URL
	target    setupcode.Target
	// password is the agent's password this machine holds for this
	// database: the one that logs in, else the newest (.pending first);
	// "" when it holds none.
	password string
	// credExists: the credential file exists, so a new password goes to
	// .pending (writeCredential).
	credExists bool
	// unlock releases the lock that keeps two runs for the agent apart,
	// and closes files.
	unlock func()
	// loggedIn: the role logs in with the credential (or its .pending one,
	// then moved over the credential file). installed is the guard version
	// it sees, recorded whether the pending setup is recorded.
	loggedIn, recorded bool
	installed          int
	// stateDir is the engine's state directory, where its key file is.
	stateDir string
	// serviceNote says root's run made the config a service one (paths);
	// writeConfig prints it once engine.json is written. "" otherwise.
	serviceNote string
	// connectBudget is the link budget for the connect link, 0 when this
	// engine hands none (not agent-operated, the Vault off, or development
	// pages). Known once writeConfig has written the vault.
	connectBudget int
	// linkBudget is the engine's configured link budget.
	linkBudget int
	// prev is the engine config as read (zero when there is none, then
	// existed is false): the vault this run writes depends on it.
	prev    config.Config
	existed bool
	// connectOnly: no credential file, so this run makes a connect-only
	// code (CONTRACT.md, Connect-only setup codes).
	connectOnly bool
	// certChanged: the agent's login failed on the certificate of its
	// pinned host, which presents another chain top (TRUST_ROOT_CHANGED):
	// this run makes an AGENT code with no change, marked
	// certificateChanged, never a new password.
	certChanged bool
}

func newRemoteInit(c *cliIO, f remoteFlags) (*remoteInit, error) {
	r := &remoteInit{c: c, f: f}
	if err := r.paths(); err != nil {
		return nil, err
	}
	unlock, err := r.files.lock(r.credFile + lockSuffix)
	if err != nil {
		r.files.close()
		return nil, err
	}
	r.unlock = func() {
		unlock()
		r.files.close()
		if r.configDir != nil {
			r.configDir.close()
		}
	}
	if err := r.connection(); err != nil {
		r.unlock()
		return nil, err
	}
	return r, nil
}

// paths finds the config, the agent's entry, its credential file and the
// settings of a new config. Not as root, the config lives in the user's own
// config directory, as init's foreground setup, with the sockets next to it.
func (r *remoteInit) paths() error {
	dir := filepath.Dir(r.f.configPath)
	r.settings = config.Settings{SocketDir: config.DefaultSocketDir(r.c.goos), PagesURL: links.Portal}
	if r.c.host.Euid() != 0 && r.c.paths.config == "" {
		if _, err := r.c.findConfig(); err != nil {
			return err
		}
		if err := r.c.refuseSecondConfig(); err != nil {
			return err
		}
		base, err := r.c.host.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, perUserDirName)
		r.f.configPath = filepath.Join(dir, "engine.json")
		r.settings.SocketDir = filepath.Join(dir, "run")
	}
	if r.f.configPath != r.c.systemConfig() {
		if r.c.paths.config != "" && r.c.host.Euid() != 0 {
			// Not root, the system socket directory is not writable: keep
			// the sockets next to a config in another place.
			r.settings.SocketDir = filepath.Join(dir, "run")
		}
		r.settings.StateDir = filepath.Join(dir, stateDirName)
	}
	r.stateDir = config.Config{StateDir: r.settings.StateDir}.StateDirFor(r.c.goos)
	// As root, the hardened read (loadEngineConfig): the config must be a
	// plain file owned by root or its directory's owner, not writable by
	// group or others and reached without links, before any field is read.
	cfg, err := loadEngineConfig(r.c, r.f.configPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		r.prev, r.existed = cfg.Config, true
		r.stateDir = cfg.StateDirFor(r.c.goos)
		r.settings.SocketDir = cfg.SocketDir
		r.linkBudget = cfg.LinkBudgetOrDefault()
	}
	if r.f.agent == "" {
		name, err := remoteAgentName(r.prev.Agents)
		if err != nil {
			return err
		}
		r.f.agent = name
	}
	if !config.ValidAgentName(r.f.agent) {
		return fmt.Errorf("%w: agent name %q is not valid for the engine (lowercase letters, digits and _)", errUsage, r.f.agent)
	}
	for i := range r.prev.Agents {
		if r.prev.Agents[i].Name == r.f.agent {
			r.entry = &r.prev.Agents[i]
		}
	}
	if err := r.settle(); err != nil {
		return err
	}
	if err := config.CheckSocketPath(config.SocketPath(r.settings.SocketDir, r.f.agent)); err != nil {
		return fmt.Errorf("%w; use a shorter agent name", err)
	}
	asRoot := r.c.host.Euid() == 0
	if asRoot {
		// The user who ran sudo is the person on this machine
		// (CONTRACT.md, Recording the person). Never root.
		person, err := invokingUID(r.c)
		if err == nil && person != 0 {
			r.settings.PersonUIDs = []uint32{person}
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		dir = abs
	}
	r.credFile = filepath.Join(dir, "agents", r.f.agent+".url")
	r.osUser = ""
	if r.entry != nil {
		if asRoot {
			// As root the computed path is used, never the config's
			// string: agents/sub/../bot.url passes the check but would
			// resolve through agents/sub.
			if _, err := config.RootCredentialPath(r.f.configPath, r.f.agent, r.entry.Store.CredentialFile); err != nil {
				return fmt.Errorf("%w; as root, basalt init --remote uses only that path. Fix the agent's store.credentialFile in the config", err)
			}
		} else {
			r.credFile = r.entry.Store.CredentialFile
		}
		r.osUser = r.entry.OSUser
	}
	if r.osUser == "" {
		u, err := invokingUser()
		if err != nil {
			return err
		}
		r.osUser = u
	}
	r.files = pathCredFiles{}
	if asRoot {
		trusted, err := rootTrustedOwner(dir)
		if err != nil {
			return err
		}
		// A config directory another OS user owns (not root, not the user
		// who ran sudo) is an engine user's, as basalt service install
		// makes it: the engine runs as that user, so the config is a
		// service one. Only with a person to record (SUDO_UID).
		// writeConfig says so once engine.json is written, never on a run
		// that refuses before writing it.
		if trusted > 0 && len(r.settings.PersonUIDs) > 0 && uint32(trusted) != r.settings.PersonUIDs[0] {
			r.settings.Mode = config.ModeService
			r.serviceNote = fmt.Sprintf("basalt: %s belongs to uid %d, not root or you (uid %d): this config is a service one (mode %s). "+
				"The engine runs as uid %d and records you as its person; restart its service after this run\n",
				dir, trusted, r.settings.PersonUIDs[0], config.ModeService, trusted)
		}
		files, err := openRootCredFiles(filepath.Dir(r.credFile), trusted)
		if err != nil {
			return err
		}
		r.files = files
		if r.configDir, err = openRootConfigDir(dir, trusted); err != nil {
			files.close()
			return err
		}
	}
	return nil
}

// credFiles reads and writes the agent's credential file, its .pending and
// its .lock for init --remote, each named by its full path.
type credFiles interface {
	lock(path string) (func(), error)
	// read reads a credential file this process wrote (readOwnCredential's
	// checks); an error wrapping fs.ErrNotExist when there is none.
	read(path string) (string, os.FileInfo, error)
	// stat is the file at path, not following a link.
	stat(path string) (os.FileInfo, error)
	write(path string, data []byte) error
	rename(from, to string) error
	// remove removes the file at path, not following a link.
	remove(path string) error
	close()
}

// pathCredFiles reaches the credential files by path: init --remote not as
// root, in the user's own directories.
type pathCredFiles struct{}

func (pathCredFiles) lock(path string) (func(), error) { return lockFile(path) }

func (pathCredFiles) read(path string) (string, os.FileInfo, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", nil, err
	}
	return readOwnCredential(path)
}

func (pathCredFiles) stat(path string) (os.FileInfo, error) { return os.Lstat(path) }

func (pathCredFiles) write(path string, data []byte) error { return config.WriteFile(path, data) }

func (pathCredFiles) rename(from, to string) error { return os.Rename(from, to) }

func (pathCredFiles) remove(path string) error { return os.Remove(path) }

func (pathCredFiles) close() {}

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

// connection settles the database: the .pending credential's (a setup for
// another password may be waiting), else the credential file's, else none:
// a connect-only code, whose engine collects the address. It logs in as the
// agent with the credentials for that database, .pending first.
func (r *remoteInit) connection() error {
	cred, err := readCredentialIfAny(r.files, r.credFile)
	if err != nil {
		return err
	}
	pending, err := readCredentialIfAny(r.files, r.credFile+pendingSuffix)
	if err != nil {
		return err
	}
	switch {
	case pending != nil:
		r.base, r.target = pending.url, pending.target
	case cred != nil:
		r.base, r.target = cred.url, cred.target
	default:
		// No address and no credential: a code for the connect page, which
		// collects the address (CONTRACT.md, Connect-only setup codes).
		if err := r.connectOnlyAllowed(); err != nil {
			return err
		}
		r.connectOnly = true
		return nil
	}
	r.credExists = cred != nil
	if prefix := credentialPrefix(r.base, r.f.agent, r.target.SupabaseRef); prefix != "" && prefix != r.f.prefix {
		if err := r.setPrefix(prefix); err != nil {
			return err
		}
	}
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
	// Before any login sends a startup message: say that a chain no
	// authority here verifies is trusted on the connect page. Nothing is
	// pinned here.
	r.noteUnknownAuthority()
	return r.login(pending, cred)
}

// readCredentialIfAny reads a credential file with the no-follow checks,
// or nil when there is none.
func readCredentialIfAny(files credFiles, path string) (*credential, error) {
	dsn, fi, err := files.read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil //nolint:nilnil // no file is no credential
	}
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
			"which basalt init --remote can't target; it was left as is. Use another --agent name", path, pe.Param)
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
		case r.rootChanged(pending.dsn, err):
			r.certChanged = true
			return nil
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
	case r.rootChanged(cred.dsn, err):
		// Not a refused credential: the pinned host presents another
		// certificate. The connect page asks the person.
		r.certChanged = true
		return nil
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
	now, err := r.files.stat(pendingFile)
	if err != nil {
		return err
	}
	if !os.SameFile(now, pending.file) {
		return fmt.Errorf("%s changed while basalt init ran; nothing changed, run it again", pendingFile)
	}
	if err := r.files.rename(pendingFile, r.credFile); err != nil {
		return err
	}
	r.credExists = true
	return nil
}

// agentConn is the agent's own connection init --remote reads with.
type agentConn interface {
	app.Querier
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
func loginAsAgent(ctx context.Context, sh shellHost, dsn string) (agentConn, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	conn, err := connect(ctx, sh, dsn)
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
	v, err := app.GuardAgentVersion(r.c.ctx, conn)
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
	r.recorded, err = app.GuardSetupRecorded(r.c.ctx, conn, id)
	return err
}

// reusable is the pending setup init prints again: unexpired and not yet
// run.
func (r *remoteInit) reusable() *config.Setup {
	if r.entry == nil || r.entry.Setup == nil || r.recorded || r.password == "" || r.entry.Setup.CertificateChanged != r.certChanged {
		return nil
	}
	if r.entry.Setup.ConnectOnly() || connectOnlyCode(r.entry.Setup.Code) {
		// A connect-only code with a credential file is never handed out
		// again on this path: the engine stopped between writing the
		// credential and clearing awaitingAddress, or the person confirmed
		// a database that does not record the setup (SETUP_NOT_FOUND). The
		// credential's own code replaces it.
		return nil
	}
	s := r.entry.Setup
	expires, err := s.Expires()
	if err != nil || !r.c.now().Before(expires) {
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
// A role that does not log in while an INSTALL setup is pending: INSTALL
// again with the password this machine holds, so any of its INSTALL codes
// matches the credential. A role that does not log in otherwise: the
// database refuses the credential (CREDENTIAL_REJECTED), so an AGENT code
// with a new password (RI-17), with no flag. A role that logs in while a
// connect-only setup the person confirmed is not recorded there
// (SETUP_NOT_FOUND: it ran in another database of the same server): an
// AGENT code with a new password for this one. Otherwise AGENT for an
// agent the config does not have yet; else UPGRADE when its guard is older
// than this build's; else an AGENT code with no change. Every AGENT code
// names no tables: the role keeps its grants (payload).
func (r *remoteInit) decide() (plan, error) {
	latest := app.GuardLatestVersion()
	if r.certChanged {
		return r.certificatePlan()
	}
	pendingInstall := r.entry != nil && r.entry.Setup != nil && r.entry.Setup.Kind == string(setupcode.KindInstall)
	if !r.loggedIn {
		switch {
		case r.password != "" && pendingInstall:
			return plan{kind: setupcode.KindInstall, password: r.password, rotate: true}, nil
		case r.password != "":
			return r.withNewPassword(plan{kind: setupcode.KindAgent})
		}
		return r.withNewPassword(plan{kind: setupcode.KindInstall})
	}
	if r.installed > latest {
		return plan{}, fmt.Errorf("the database's guard (version %d) is newer than this basalt (version %d): update basalt on this machine first", r.installed, latest)
	}
	p := plan{from: r.installed}
	switch {
	case r.confirmedNotFound():
		p.kind = setupcode.KindAgent
		return r.withNewPassword(p)
	case r.entry == nil:
		p.kind = setupcode.KindAgent
	case r.installed < latest:
		p.kind = setupcode.KindUpgrade
	default:
		p.kind = setupcode.KindAgent
	}
	return p, nil
}

// confirmedNotFound reports whether the pending setup is a connect-only
// code whose database the person confirmed and that the database the agent
// logs in to does not record (the engine's SETUP_NOT_FOUND).
func (r *remoteInit) confirmedNotFound() bool {
	s := r.entry
	return s != nil && s.Setup != nil && !s.Setup.ConnectOnly() && connectOnlyCode(s.Setup.Code) && !r.recorded
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
		Format: setupcode.Format, SetupID: id, Kind: p.kind, Prefix: r.f.prefix,
		Guard: setupcode.Guard{From: p.from, To: app.GuardLatestVersion()}, Build: buildVersion(), ExpiresAt: expires,
	}
	if !r.connectOnly {
		target := r.target
		out.Target, out.Engine = &target, r.engineKey()
		if p.kind != setupcode.KindInstall {
			// The engine's pin for the host, a hint for the connect page.
			out.TrustPin = r.pinnedSHA()
		}
	}
	if r.certChanged && out.Engine == nil {
		return setupcode.Payload{}, errNoEngineForTrust
	}
	if p.kind == setupcode.KindUpgrade {
		return out, nil
	}
	// An INSTALL code asks for every table in public, which the person
	// ticks on the connect page. An AGENT code names no tables: the role
	// keeps the grants it holds (CONTRACT.md, The setup code, Kinds), and
	// a role that is gone runs as an INSTALL, with ticks.
	a := &setupcode.Agent{Name: r.f.agent, StatementTimeoutMs: r.f.timeout.Milliseconds()}
	if p.kind == setupcode.KindInstall {
		a.AllTables = &setupcode.AllTables{Schemas: []string{"public"}}
	}
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

// checkBuildVersion refuses, before anything is written, a build whose
// version a setup code cannot carry (a source build without tags: "dev").
func checkBuildVersion(version string) error {
	if setupcode.ValidBuild(version) {
		return nil
	}
	return fmt.Errorf("this build of basalt has no release version (it reports %q), so it cannot make a setup code; install a release build", version)
}

// run makes (or reuses) the code, writes the credential and the config,
// and returns the result.
func (r *remoteInit) run() (RemoteInitResult, error) {
	if r.connectOnly {
		return r.runConnectOnly()
	}
	if s := r.reusable(); s != nil {
		if err := r.writeConfig(s); err != nil {
			return RemoteInitResult{}, err
		}
		return r.result(*s, true)
	}
	p, err := r.decide()
	if err != nil {
		return RemoteInitResult{}, err
	}
	payload, err := r.payload(p)
	if err != nil {
		return RemoteInitResult{}, err
	}
	code, err := encodeSetup(payload)
	if err != nil {
		return RemoteInitResult{}, err
	}
	if err := r.writeCredential(p); err != nil {
		return RemoteInitResult{}, err
	}
	s := newSetup(payload, code)
	s.CertificateChanged = r.certChanged
	if err := r.writeConfig(&s); err != nil {
		return RemoteInitResult{}, err
	}
	// A .secret a connect-only code left belongs to a code engine.json no
	// longer records: its password is dropped.
	if err := r.removeSecret(); err != nil {
		return RemoteInitResult{}, err
	}
	return r.result(s, false)
}

// newSetup is the pending setup engine.json records for a new code.
func newSetup(p setupcode.Payload, code string) config.Setup {
	return config.Setup{
		SetupID: p.SetupID, Kind: string(p.Kind), GuardVersion: p.Guard.To,
		ExpiresAt: p.ExpiresAt, Code: code, Fingerprint: p.Fingerprint(), AwaitingAddress: p.ConnectOnly(),
	}
}

// connectOnlyAllowed is nil when this run may make a connect-only code: the
// engine it writes is agent-operated with the Vault on (init --remote
// always writes the portal's pages). Otherwise the message names what the
// connect page needs.
func (r *remoteInit) connectOnlyAllowed() error {
	if r.settings.OperatedBy != mcpcontract.OperatedByAgent {
		return errors.New("this engine is person-operated, and basalt init --remote sets up only an agent-operated engine: " +
			"the person runs basalt init on this machine instead")
	}
	if r.settings.VaultFor(r.prev, r.existed).Vault != config.VaultOn {
		return errors.New("this engine has the Vault off, and the connect page that basalt init --remote hands the person needs it on")
	}
	return nil
}

// connectOnlyCode reports whether code is a connect-only setup code (it
// has no target). A code that cannot be read is not.
func connectOnlyCode(code string) bool {
	p, err := setupcode.Decode(code)
	return err == nil && p.ConnectOnly()
}

// pendingConnectOnly is the agent's pending connect-only setup, nil when
// none: waiting for its address, or refused by the person.
func (r *remoteInit) pendingConnectOnly() *config.Setup {
	if r.entry == nil || r.entry.Setup == nil || !r.entry.Setup.ConnectOnly() {
		return nil
	}
	return r.entry.Setup
}

// settle settles what the run depends on: the role's names, the operator
// and the vault it writes. --remote makes a new engine agent-operated;
// afterwards the config says who operates it (CONTRACT.md, Who operates
// the engine), so a person-operated engine is never made agent-operated
// behind the person's back: the connect path then refuses.
func (r *remoteInit) settle() error {
	if r.existed && r.prev.OperatedBy != mcpcontract.OperatedByAgent {
		r.f.operatedBy = OperatedByPerson
	}
	if err := r.setPrefix(r.f.prefix); err != nil {
		return err
	}
	vc, err := chooseVault("", r.f.operatedBy, links.Portal, remoteVaultWhy)
	if err != nil {
		return err
	}
	r.f.vault = vc
	r.settings = vc.settings(r.settings)
	r.settings.OperatedBy = r.f.operatedBy.enum()
	return nil
}

// setPrefix sets the role prefix of the agent's names and role.
func (r *remoteInit) setPrefix(prefix string) error {
	r.f.prefix = prefix
	r.names = guardmodel.Names{Prefix: prefix}
	role, err := r.names.Agent(r.f.agent)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	r.role = role
	return nil
}

// credentialPrefix is the role prefix of the credential this machine holds
// for the agent: its user is <prefix>_agent_<name> (with .<ref> through
// Supabase's pooler). The credential names the role, so a code for it names
// that role, never a saved copy; "" when its user is not such a role (the
// fixed default prefix then).
func credentialPrefix(u *url.URL, agent, supabaseRef string) string {
	if u == nil || u.User == nil {
		return ""
	}
	user := u.User.Username()
	if supabaseRef != "" {
		user = strings.TrimSuffix(user, "."+supabaseRef)
	}
	prefix, ok := strings.CutSuffix(user, "_agent_"+agent)
	if !ok || (guardmodel.Names{Prefix: prefix}).Validate() != nil {
		return ""
	}
	return prefix
}

// secretPath is agents/<agent>.secret, next to the credential file.
func (r *remoteInit) secretPath() string {
	return config.SecretPath(r.credFile, r.f.agent)
}

// hasSecret reports whether the agent's .secret exists.
func (r *remoteInit) hasSecret() (bool, error) {
	_, err := r.files.stat(r.secretPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("%s is not usable: %w", r.secretPath(), err)
	}
	return true, nil
}

// removeSecret removes the agent's .secret, when there is one.
func (r *remoteInit) removeSecret() error {
	err := r.files.remove(r.secretPath())
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove %s: %w", r.secretPath(), err)
}

// runConnectOnly makes (or reuses) a connect-only code: no target, the
// engine's key required, the password in .secret (CONTRACT.md,
// Connect-only setup codes). While a code waits and has not expired, the
// same request prints it again and any other is refused, so .secret is
// never replaced before its code expires. After it expired (even inside
// the 30-minute grace, abandoning a confirmed run still in flight), after
// the person refused its database, after the engine refused the address
// the connect page handed over, or when .secret is gone, the pending setup
// is forgotten and the code is a recovery code: AGENT with a new password.
func (r *remoteInit) runConnectOnly() (RemoteInitResult, error) {
	pending := r.pendingConnectOnly()
	if pending != nil && !pending.Refused && !pending.AddressInvalid {
		reuse, err := r.reuseConnectOnly(pending)
		if err != nil || reuse {
			if err != nil {
				return RemoteInitResult{}, err
			}
			if err := r.writeConfig(pending); err != nil {
				return RemoteInitResult{}, err
			}
			return r.result(*pending, true)
		}
	}
	kind := setupcode.KindInstall
	if pending != nil {
		kind = setupcode.KindAgent
	}
	p, err := r.withNewPassword(plan{kind: kind})
	if err != nil {
		return RemoteInitResult{}, err
	}
	payload, err := r.connectOnlyPayload(p)
	if err != nil {
		return RemoteInitResult{}, err
	}
	code, err := encodeSetup(payload)
	if err != nil {
		return RemoteInitResult{}, err
	}
	// The old password is dropped only now, after the engine's key and the
	// code: a refusal before this point leaves everything as it was.
	if err := r.removeSecret(); err != nil {
		return RemoteInitResult{}, err
	}
	if err := r.files.write(r.secretPath(), []byte(p.password+"\n")); err != nil {
		return RemoteInitResult{}, err
	}
	s := newSetup(payload, code)
	if err := r.writeConfig(&s); err != nil {
		return RemoteInitResult{}, err
	}
	return r.result(s, false)
}

// reuseConnectOnly decides about a connect-only code still waiting: true
// to print it again (unexpired, .secret there), false when it expired or
// its password is gone (a recovery code then).
func (r *remoteInit) reuseConnectOnly(pending *config.Setup) (bool, error) {
	expires, err := pending.Expires()
	if err != nil || !r.c.now().Before(expires) {
		return false, nil //nolint:nilerr // an expired or malformed pending code is replaced
	}
	return r.hasSecret()
}

// connectOnlyPayload is a connect-only code's content: no target, and the
// engine's key, without which the engine could not collect the address.
func (r *remoteInit) connectOnlyPayload(p plan) (setupcode.Payload, error) {
	key, err := r.loadEngineKey()
	if err != nil {
		return setupcode.Payload{}, fmt.Errorf("a setup code for the connect page needs the engine's key, and basalt cannot read or make it as this user (%w). "+
			"Run basalt init --remote as the engine's OS user (the owner of the engine's state directory)", err)
	}
	out, err := r.payload(p)
	if err != nil {
		return setupcode.Payload{}, err
	}
	out.Target, out.Engine = nil, key
	return out, nil
}

// encodeSetup encodes a code, naming what is wrong with this run's flags.
func encodeSetup(p setupcode.Payload) (string, error) {
	code, err := setupcode.Encode(p)
	switch {
	case errors.Is(err, setupcode.ErrCodeTooLong):
		return "", fmt.Errorf("the setup code would be longer than %d characters: name fewer tables", setupcode.MaxCodeLen)
	case err != nil:
		return "", fmt.Errorf("%w: %s", errUsage, setupcode.InvalidDetail(err))
	}
	return code, nil
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
	dsn, err := app.GuardAgentConnString(r.base.String(), r.role, p.password)
	if err != nil {
		return err
	}
	dsn, applied := hardenedCredential(r.c.ctx, r.c.probe, dsn)
	fmt.Fprint(r.c.stderr, applied.line())
	path := r.credFile
	if r.credExists {
		path += pendingSuffix
	}
	return r.files.write(path, []byte(dsn+"\n"))
}

// writeConfig upserts the agent and prints the vault value it wrote.
func (r *remoteInit) writeConfig(s *config.Setup) error {
	a := config.Agent{Name: r.f.agent, OSUser: r.osUser, Store: config.PostgresStore(r.credFile), Setup: s}
	var v config.VaultWritten
	var err error
	if r.configDir != nil {
		// As root, through the directory opened in paths: a config
		// directory swapped for a symlink since then redirects nothing.
		v, err = r.configDir.upsert(filepath.Base(r.f.configPath), r.settings, a)
	} else {
		v, err = config.UpsertAgentVault(r.f.configPath, r.settings, a)
	}
	if err != nil {
		return err
	}
	fmt.Fprint(r.c.stderr, r.serviceNote)
	fmt.Fprint(r.c.stderr, remoteVaultLine(v))
	r.connectBudget = 0
	if r.f.operatedBy == OperatedByAgent && v.Vault == config.VaultOn {
		r.connectBudget = r.linkBudget
		if r.connectBudget <= 0 {
			r.connectBudget = links.DefaultBudget
		}
	}
	return nil
}

// remoteVaultLine is what init --remote prints on stderr once it wrote w.
// It takes no flag that changes the vault.
func remoteVaultLine(w config.VaultWritten) string {
	if w.Kept {
		return fmt.Sprintf("basalt: vault: %s (kept from engine.json)\n", modeOf(w.Vault))
	}
	return fmt.Sprintf("basalt: vault: %s\n", modeOf(w.Vault))
}

// result is the remote-init result: the code, and what the person does
// with it.
func (r *remoteInit) result(s config.Setup, reused bool) (RemoteInitResult, error) {
	res := RemoteInitResult{
		Agent: r.f.agent, SetupID: s.SetupID, Kind: s.Kind, Code: s.Code, Fingerprint: s.Fingerprint,
		Reused: reused, ExpiresAt: s.ExpiresAt, PersonMessage: setupPersonMessage(r.f.agent, s.Fingerprint),
	}
	if s.AwaitingAddress {
		res = r.connectOnlyResult(res, s)
	} else {
		res = r.withSetupGuidance(res, s)
	}
	return r.withMCP(res), nil
}

// withSetupGuidance is the person message and connect link of a code that
// is not connect-only.
func (r *remoteInit) withSetupGuidance(res RemoteInitResult, s config.Setup) RemoteInitResult {
	// An agent-operated engine with the Vault on hands the connect link
	// when the whole link fits the budget (no network call: the link only
	// holds the code); else the text says where to paste the code.
	url := agent.ConnectLink(s.Code, r.connectBudget)
	if url != "" {
		res.ConnectURL = url
		res.PersonMessage, _ = agent.ConnectMessage("Finish setting up Basalt for "+r.f.agent+".", url, s.Fingerprint)
	}
	res.pasteAtPortal = url == ""
	return res
}

// withMCP adds the basalt mcp command the agent registers, and the OS user
// the text output names.
func (r *remoteInit) withMCP(res RemoteInitResult) RemoteInitResult {
	res.osUser = r.osUser
	res.MCPCommand = mcpArgs(r.f.agent, mcpBinary(r.c.host))
	fmt.Fprint(r.c.stderr, temporaryBinaryWarning(res.MCPCommand[0], os.TempDir()))
	return res
}

// connectOnlyResult is the result of a connect-only code: the connect link
// and the fingerprint, no laptop command. A link over the budget is left
// out: the text says to paste the code at the connect page.
func (r *remoteInit) connectOnlyResult(res RemoteInitResult, s config.Setup) RemoteInitResult {
	res.ConnectOnly = true
	lead := "Connect your database to " + r.f.agent + "."
	if open := agent.ConnectLink(s.Code, r.connectBudget); open != "" {
		res.ConnectURL = open
		res.PersonMessage, _ = agent.ConnectOnlyMessage(lead, open, s.Fingerprint)
		return res
	}
	res.pasteAtPortal = true
	page := strings.TrimPrefix(links.Portal+links.ConnectPath, "https://")
	res.PersonMessage = lead + " Open " + page + ", paste the setup code the agent shows you, check that it shows the setup fingerprint " + s.Fingerprint +
		", and follow the page. The page asks for your database's connection string: paste it there only. The agent never needs it, so never paste it into this chat."
	return res
}

// setupPersonMessage is what the agent shows the person verbatim, within
// agent.MaxPersonMessageLength for the longest agent name: it names the
// agent once.
func setupPersonMessage(name, fingerprint string) string {
	return fmt.Sprintf("Finish setting up Basalt for %s: open %s, paste the setup code the agent shows you, "+
		"check that it shows the setup fingerprint %s, and follow the page. "+
		"The page asks for your database's connection string: paste it there only, never into this chat.",
		name, strings.TrimPrefix(links.Portal+links.ConnectPath, "https://"), fingerprint)
}

// printRemoteResult prints the result: the connect link or the code in a
// block of its own, its fingerprint and what the person does.
func printRemoteResult(c *cliIO, res RemoteInitResult) error {
	if res.Reused {
		fmt.Fprintln(c.stderr, "basalt: a setup code is pending for this agent; here it is again")
	}
	expires, err := time.Parse(time.RFC3339, res.ExpiresAt)
	if err != nil {
		return err
	}
	if res.ConnectOnly {
		if err := printConnectOnly(c, res, expires); err != nil {
			return err
		}
		return printRemoteMCP(c, res)
	}
	_, err = fmt.Fprintf(c.stdout, "Setup code for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, expires.UTC().Format("2006-01-02 15:04 UTC"), res.Code, res.Fingerprint, res.PersonMessage)
	if err == nil && res.pasteAtPortal {
		// The link is over the budget: no link is printed, the code is
		// pasted at the connect page instead.
		_, err = fmt.Fprintf(c.stdout, "\nTo use Basalt Vault, a hosted service, paste the setup code at %s.\n", strings.TrimPrefix(links.Portal+links.ConnectPath, "https://"))
	}
	if err != nil {
		return err
	}
	return printRemoteMCP(c, res)
}

// printRemoteMCP prints the basalt mcp command the agent registers.
func printRemoteMCP(c *cliIO, res RemoteInitResult) error {
	_, err := fmt.Fprintf(c.stdout, "then add this MCP server to the agent's client, running as OS user %s:\n  %s\n",
		res.osUser, shellJoin(res.MCPCommand))
	return err
}

// stateDirMode is the engine's state directory's mode when init makes it,
// as the engine does: only its OS user.
const stateDirMode = 0o700

// engineKey is the engine's signing key for the code (M4.1, CO-18), made
// as the engine makes it on its first start when the key file is missing.
// Run as root, init cannot make a file the engine's OS user owns, and an
// unreadable or refused file is never replaced: then the code carries no
// engine key, and init says why on stderr.
func (r *remoteInit) engineKey() *setupcode.Engine {
	key, err := r.loadEngineKey()
	if err != nil {
		fmt.Fprintf(r.c.stderr, "basalt: the code carries no engine key: %v\n", err)
		return nil
	}
	return key
}

// loadEngineKey is engineKey's key, or why there is none.
func (r *remoteInit) loadEngineKey() (*setupcode.Engine, error) {
	if r.c.host.Euid() == 0 {
		// As root, through the state directory opened without following a
		// link the engine's user controls; a new key file is that user's.
		spki, err := rootEngineKey(r.stateDir, r.c.goos, r.configDir, r.c.now)
		if err != nil {
			return nil, keyRefused(err)
		}
		return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(spki)}, nil
	}
	if err := os.MkdirAll(r.stateDir, stateDirMode); err != nil {
		return nil, err
	}
	keys, err := app.LoadOrCreateEngineKeys(filepath.Join(r.stateDir, channel.KeyFileName), r.c.now)
	if err != nil {
		return nil, keyRefused(err)
	}
	return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())}, nil
}

func keyRefused(err error) error {
	return fmt.Errorf("the engine's key file is refused (%w); the agent's status tool shows KEY_ERROR", err)
}

// printConnectOnly prints a connect-only code's result: the connect link
// and the fingerprint, never a laptop command, or, over the link budget,
// the code to paste at the connect page.
func printConnectOnly(c *cliIO, res RemoteInitResult, expires time.Time) error {
	until := expires.UTC().Format("2006-01-02 15:04 UTC")
	if res.ConnectURL == "" {
		_, err := fmt.Fprintf(c.stdout, "Setup code for %s (%s), for the connect page only, valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
			res.Agent, res.Kind, until, res.Code, res.Fingerprint, res.PersonMessage)
		return err
	}
	_, err := fmt.Fprintf(c.stdout, "Connect link for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, until, res.ConnectURL, res.Fingerprint, res.PersonMessage)
	return err
}
