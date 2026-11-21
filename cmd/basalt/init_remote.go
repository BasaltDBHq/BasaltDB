package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
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
	flagAllTables   = "all-tables"
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

// remoteVaultWhy says why the vault is off by default for init --remote.
const remoteVaultWhy = "default for --operated-by=person; --vault=on to turn it on"

// remoteFlags are basalt init --remote's flags after parsing.
type remoteFlags struct {
	agent, write, read, prefix, configPath, databaseURL string
	timeout                                             time.Duration
	operatedBy                                          OperatedBy
	newCode, json, configGiven                          bool
	// allTables is --all-tables: every table in public, in place of
	// --write and --read. forget is --forget, one-shot, never saved.
	allTables, forget bool
	// given are the flags set on the command line.
	given map[string]bool
	spec  guard.AgentSpec
	// vaultFlag is --vault as given ("" when not); vault is what init
	// asks the config's vault to be (chooseVault).
	vaultFlag VaultMode
	vault     vaultChoice
	// directAddr is --direct-addr as given ("" when not).
	directAddr string
}

// RemoteInitResult is what basalt init --remote --json prints
// (api/mcp/setup/remote-init-result.schema.json).
type RemoteInitResult struct {
	Agent       string `json:"agent"`
	SetupID     string `json:"setupId"`
	Kind        string `json:"kind"`
	Code        string `json:"code"`
	Fingerprint string `json:"fingerprint"`
	Reused      bool   `json:"reused,omitempty"`
	ExpiresAt   string `json:"expiresAt"`
	// ConnectOnly is a connect-only code: only the connect page runs it.
	ConnectOnly   bool   `json:"connectOnly,omitempty"`
	PersonMessage string `json:"personMessage"`
	// ConnectURL is the connect link, set when the engine is agent-operated
	// with the Vault on and the whole link fits the link budget
	// (CONTRACT.md, Connect, The connect link). Links are PersonMessage's
	// URLs, set exactly when it holds one.
	ConnectURL string     `json:"connectUrl,omitempty"`
	Links      []mcp.Link `json:"links,omitempty"`
	// MCPCommand is the basalt mcp command the agent registers, as argv.
	MCPCommand []string         `json:"mcpCommand"`
	NextSteps  []agent.NextStep `json:"nextSteps"`
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
	if c.getenv(envAdminURL) != "" {
		// Never used here, but whoever can read this environment holds
		// the admin password (CONTRACT.md, Agents and the admin credential).
		fmt.Fprintln(c.stderr, "basalt: warning: "+remoteAdminEnvSet)
	}
	if err := checkBuildVersion(buildVersion()); err != nil {
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
	fs.BoolVar(&f.allTables, flagAllTables, false, "give the agent every table in schema public the admin role owns, in place of --write and --read")
	fs.BoolVar(&f.forget, "forget", false, "drop the agent's pending setup from the connect page and make a new code for it")
	fs.StringVar(&f.configPath, "config", config.DefaultPath(c.goos), "engine config file")
	fs.BoolVar(&f.json, "json", false, "print the result as JSON (remote-init-result.schema.json)")
	fs.Var(&f.vaultFlag, flagVault, "on or off: whether the engine reaches the portal's pages through the Vault (default on with --operated-by=agent, else off)")
	fs.StringVar(&f.directAddr, flagDirectAddr, "", directAddrUsage)
	if err := parse(fs, args); err != nil {
		return f, err
	}
	var directGiven bool
	f.given = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) {
		f.given[fl.Name] = true
		switch fl.Name {
		case "config":
			f.configGiven = true
		case flagDirectAddr:
			directGiven = true
		}
	})
	if directGiven {
		if err := checkDirectAddr(f.directAddr); err != nil {
			return f, err
		}
	}
	if f.agent == "" {
		return f, fmt.Errorf("%w: --agent is required", errUsage)
	}
	if f.allTables && (f.write != "" || f.read != "") {
		return f, fmt.Errorf("%w: --all-tables is in place of --write and --read: give one or the other", errUsage)
	}
	if f.forget && f.databaseURL != "" {
		return f, fmt.Errorf("%w: --forget drops a setup from the connect page; give --database-url without it", errUsage)
	}
	if !config.ValidAgentName(f.agent) {
		return f, fmt.Errorf("%w: agent name %q is not valid for the engine", errUsage, f.agent)
	}
	if _, err := (guard.Names{Prefix: f.prefix}).Agent(f.agent); err != nil {
		return f, fmt.Errorf("%w: %w", errUsage, err)
	}
	f.spec = guard.AgentSpec{Name: f.agent, Write: splitList(f.write), Read: splitList(f.read), StatementTimeout: f.timeout}
	vc, err := chooseVault(f.vaultFlag, f.operatedBy, links.Portal, remoteVaultWhy)
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
	if f.allTables {
		args = append(args, "--"+flagAllTables+"=true")
	}
	addIf("prefix", f.prefix, guard.DefaultPrefix)
	addIf("statement-timeout", f.timeout.String(), guard.DefaultStatementTimeout.String())
	addIf("os-user", osUser, "")
	addIf("operated-by", string(f.operatedBy), string(OperatedByPerson))
	addIf(flagDirectAddr, f.directAddr, "")
	return args
}

// requestFlags are the saved flags whose change asks for a new AGENT code.
var requestFlags = []string{"write", "read", flagAllTables, "prefix", "statement-timeout"}

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
	// connectOnly: no --database-url and no credential file, so this run
	// makes a connect-only code (CONTRACT.md, Connect-only setup codes).
	connectOnly bool
}

func newRemoteInit(c *cliIO, f remoteFlags) (*remoteInit, error) {
	r := &remoteInit{c: c, f: f, names: guard.Names{Prefix: f.prefix}}
	r.role, _ = r.names.Agent(f.agent) // checked by parseInitRemote
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
// settings of a new config. Without --config and not as root, the config
// lives in the user's own config directory, as init's foreground setup.
// With --config and not as root, the sockets live next to that config.
func (r *remoteInit) paths() error {
	dir := filepath.Dir(r.f.configPath)
	r.settings = r.f.vault.settings(config.Settings{SocketDir: config.DefaultSocketDir(r.c.goos), PagesURL: links.Portal, OperatedBy: r.f.operatedBy.enum(), DirectAddr: r.f.directAddr})
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
		if r.f.configGiven && r.c.host.Euid() != 0 {
			// Not root, the system socket directory is not writable: keep
			// the sockets next to the config the person chose.
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
		for i := range cfg.Agents {
			if cfg.Agents[i].Name == r.f.agent {
				r.entry = &cfg.Agents[i]
			}
		}
	}
	if err := r.restoreForForget(); err != nil {
		return err
	}
	if err := config.CheckSocketPath(config.SocketPath(r.settings.SocketDir, r.f.agent)); err != nil {
		return fmt.Errorf("%w; pass --config in a shorter directory", err)
	}
	asRoot := r.c.host.Euid() == 0
	if asRoot {
		// The user who ran sudo runs basalt status, log, approve and
		// revert on this machine: the person socket of a service engine
		// admits it (CONTRACT.md, Recording the person). Never root.
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
		// makes it: the engine runs as that user and serves the person
		// socket, so the config is a service one. Only with a person to
		// admit (SUDO_UID): without one, a service config's person socket
		// would admit nobody.
		// writeConfig says so once engine.json is written, never on a run
		// that refuses before writing it.
		if trusted > 0 && len(r.settings.PersonUIDs) > 0 && uint32(trusted) != r.settings.PersonUIDs[0] {
			r.settings.Mode = config.ModeService
			r.serviceNote = fmt.Sprintf("basalt: %s belongs to uid %d, not root or you (uid %d): this config is a service one (mode %s). "+
				"The engine runs as uid %d and admits you on its person socket; restart its service after this run\n",
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

// connection settles the database: --database-url, else the .pending
// credential's (a setup for another database may be waiting), else the
// credential file's. It logs in as the agent with the credentials for that
// database, .pending first.
func (r *remoteInit) connection() error {
	cred, err := readCredentialIfAny(r.files, r.credFile)
	if err != nil {
		return err
	}
	if r.f.forget && (cred != nil || r.pendingConnectOnly() == nil) {
		return fmt.Errorf("there is no pending setup from the connect page to forget for %s", r.f.agent)
	}
	pending, err := readCredentialIfAny(r.files, r.credFile+pendingSuffix)
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
		// No address and no credential: a code for the connect page, which
		// collects the address (CONTRACT.md, Connect-only setup codes).
		if err := r.connectOnlyAllowed(); err != nil {
			return err
		}
		r.connectOnly = true
		return nil
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
	if r.entry.Setup.ConnectOnly() {
		// A connect-only code with a credential file: the engine stopped
		// between writing the credential and clearing awaitingAddress. It is
		// never handed out again on this path: the credential's own code
		// replaces it.
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
		Format: setupcode.Format, SetupID: id, Kind: p.kind, Prefix: r.f.prefix,
		Guard: setupcode.Guard{From: p.from, To: guard.LatestVersion()}, Build: buildVersion(), ExpiresAt: expires,
	}
	if !r.connectOnly {
		target := r.target
		out.Target, out.Engine = &target, r.engineKey()
	}
	if p.kind == setupcode.KindUpgrade {
		return out, nil
	}
	a := &setupcode.Agent{Name: r.f.agent, Write: r.f.spec.Write, Read: r.f.spec.Read, StatementTimeoutMs: r.f.timeout.Milliseconds()}
	if r.f.allTables {
		a.Write, a.Read = nil, nil
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
	saved := r.f.savedArgs(r.osUser)
	if r.connectOnly {
		return r.runConnectOnly(saved)
	}
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
	code, err := encodeSetup(payload)
	if err != nil {
		return RemoteInitResult{}, err
	}
	if err := r.writeCredential(p); err != nil {
		return RemoteInitResult{}, err
	}
	s := newSetup(payload, code)
	if err := r.writeConfig(saved, &s); err != nil {
		return RemoteInitResult{}, err
	}
	// With --database-url the agent's first run goes on with that address:
	// the password of a connect-only code that was waiting is dropped
	// (engine.json no longer records that code).
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
// always writes the portal's pages). Otherwise --database-url is required,
// and the message names what the connect path needs.
func (r *remoteInit) connectOnlyAllowed() error {
	if r.settings.OperatedBy == mcpcontract.OperatedByAgent && r.settings.VaultFor(r.prev, r.existed).Vault == config.VaultOn {
		return nil
	}
	return fmt.Errorf("%w: --database-url is required on the agent's first run (the connection string without its password). "+
		"Without it, basalt init --remote makes a code for the connect page, which needs an agent-operated engine (--operated-by=agent) "+
		"with the Vault on and the portal's pages, and basalt init --remote run as the engine's OS user", errUsage)
}

// pendingConnectOnly is the agent's pending connect-only setup, nil when
// none: waiting for its address, or refused by the person.
func (r *remoteInit) pendingConnectOnly() *config.Setup {
	if r.entry == nil || r.entry.Setup == nil || !r.entry.Setup.ConnectOnly() {
		return nil
	}
	return r.entry.Setup
}

// forgetRestores are the saved flags --forget makes its recovery code
// with, unless the run gives them: the same tables, role and timeout, and
// the engine's operator (the connect path needs an agent-operated engine).
var forgetRestores = []string{"prefix", "statement-timeout", "operated-by"}

// tableFlags name the agent's tables; given one, none is restored.
var tableFlags = []string{"write", "read", flagAllTables}

// restoreForForget gives a --forget run the request the agent's saved flags
// ask for, for every flag it does not give, and settles what depends on
// them (the role's names, the operator and the vault it writes).
func (r *remoteInit) restoreForForget() error {
	if !r.f.forget || r.entry == nil {
		return nil
	}
	saved := r.entry.InitArgs
	if !slices.ContainsFunc(tableFlags, func(n string) bool { return r.f.given[n] }) {
		r.f.write, r.f.read = savedValue(saved, "write"), savedValue(saved, "read")
		r.f.allTables = savedValue(saved, flagAllTables) == "true"
	}
	for _, name := range forgetRestores {
		v := savedValue(saved, name)
		if r.f.given[name] || v == "" {
			continue
		}
		if err := r.restoreFlag(name, v); err != nil {
			return fmt.Errorf("the saved flag --%s=%s: %w", name, v, err)
		}
	}
	r.f.spec = guard.AgentSpec{Name: r.f.agent, Write: splitList(r.f.write), Read: splitList(r.f.read), StatementTimeout: r.f.timeout}
	r.names = guard.Names{Prefix: r.f.prefix}
	role, err := r.names.Agent(r.f.agent)
	if err != nil {
		return err
	}
	r.role = role
	vc, err := chooseVault(r.f.vaultFlag, r.f.operatedBy, links.Portal, remoteVaultWhy)
	if err != nil {
		return err
	}
	r.f.vault = vc
	r.settings = vc.settings(r.settings)
	r.settings.OperatedBy = r.f.operatedBy.enum()
	return nil
}

// restoreFlag sets the saved value v of flag name.
func (r *remoteInit) restoreFlag(name, v string) error {
	switch name {
	case "prefix":
		r.f.prefix = v
	case "statement-timeout":
		d, err := time.ParseDuration(v)
		if err != nil {
			return err
		}
		r.f.timeout = d
	case "operated-by":
		return r.f.operatedBy.Set(v)
	}
	return nil
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
// never replaced while its code may already have run. After it expired,
// after the person refused its database, after --forget, or when .secret
// is gone, the code is a recovery code: AGENT with a new password.
func (r *remoteInit) runConnectOnly(saved []string) (RemoteInitResult, error) {
	pending := r.pendingConnectOnly()
	if pending != nil && !r.f.forget && !pending.Refused {
		reuse, err := r.reuseConnectOnly(pending, saved)
		if err != nil || reuse {
			if err != nil {
				return RemoteInitResult{}, err
			}
			if err := r.writeConfig(saved, pending); err != nil {
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
	// --forget drops the old password only now, after the engine's key and
	// the code: a refusal before this point leaves everything as it was.
	if err := r.removeSecret(); err != nil {
		return RemoteInitResult{}, err
	}
	if err := r.files.write(r.secretPath(), []byte(p.password+"\n")); err != nil {
		return RemoteInitResult{}, err
	}
	s := newSetup(payload, code)
	if err := r.writeConfig(saved, &s); err != nil {
		return RemoteInitResult{}, err
	}
	return r.result(s, false)
}

// reuseConnectOnly decides about a connect-only code still waiting: true
// to print it again (same request, unexpired, .secret there), an error for
// a change while it may still run, false when it expired or its password
// is gone (a recovery code then).
func (r *remoteInit) reuseConnectOnly(pending *config.Setup, saved []string) (bool, error) {
	expires, err := pending.Expires()
	if err != nil || !r.c.now().Before(expires) {
		return false, nil //nolint:nilerr // an expired or malformed pending code is replaced
	}
	if r.f.newCode || !sameRequest(r.entry.InitArgs, saved) {
		return false, fmt.Errorf("finish the pending setup on the connect page first, or wait until it expires at %s", expires.UTC().Format("2006-01-02 15:04 UTC"))
	}
	return r.hasSecret()
}

// connectOnlyPayload is a connect-only code's content: no target, and the
// engine's key, without which the engine could not collect the address.
func (r *remoteInit) connectOnlyPayload(p plan) (setupcode.Payload, error) {
	key, err := r.loadEngineKey()
	if err != nil {
		return setupcode.Payload{}, fmt.Errorf("a setup code for the connect page needs the engine's key, and basalt cannot read or make it as this user (%w). "+
			"Run basalt init --remote as the engine's OS user (the owner of the engine's state directory), or give --database-url <the database, without password>", err)
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
	dsn, err := guard.AgentConnString(r.base.String(), r.role, p.password)
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
func (r *remoteInit) writeConfig(saved []string, s *config.Setup) error {
	a := config.Agent{Name: r.f.agent, OSUser: r.osUser, Store: config.PostgresStore(r.credFile), InitArgs: saved, Setup: s}
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
	fmt.Fprint(r.c.stderr, r.f.vault.line(v))
	r.connectBudget = 0
	if r.f.operatedBy == OperatedByAgent && v.Vault == config.VaultOn {
		r.connectBudget = r.linkBudget
		if r.connectBudget <= 0 {
			r.connectBudget = links.DefaultBudget
		}
	}
	return nil
}

// result is the remote-init result: the code, what the person does with
// it, and the steps (P RUN_COMMAND, P TELL_AGENT, A END_TURN, A CALL_TOOL
// status, as the catalog's SETUP_NOT_RUN).
func (r *remoteInit) result(s config.Setup, reused bool) (RemoteInitResult, error) {
	res := RemoteInitResult{
		Agent: r.f.agent, SetupID: s.SetupID, Kind: s.Kind, Code: s.Code, Fingerprint: s.Fingerprint,
		Reused: reused, ExpiresAt: s.ExpiresAt, PersonMessage: setupPersonMessage(r.f.agent, s.Fingerprint),
	}
	var err error
	if s.AwaitingAddress {
		res, err = r.connectOnlyResult(res, s)
	} else {
		res, err = r.withSetupGuidance(res, s)
	}
	if err != nil {
		return RemoteInitResult{}, err
	}
	return r.withMCP(res), nil
}

// withSetupGuidance is the person message, connect link and steps of a
// code that is not connect-only.
func (r *remoteInit) withSetupGuidance(res RemoteInitResult, s config.Setup) (RemoteInitResult, error) {
	// An agent-operated engine with the Vault on hands the connect link
	// first when the whole link fits the budget (no network call: the link
	// only holds the code); else the text says where to paste the code.
	url := agent.ConnectLink(s.Code, r.connectBudget)
	if url != "" {
		res.ConnectURL = url
		res.PersonMessage, res.Links = agent.ConnectMessage("Finish setting up Basalt for "+r.f.agent+".", url, s.Fingerprint)
	}
	res.pasteAtPortal = r.connectBudget > 0 && url == ""
	steps, err := setupSteps(s.Code, url)
	if err != nil {
		return RemoteInitResult{}, err
	}
	res.NextSteps = steps
	return res, nil
}

// withMCP adds the basalt mcp command the agent registers, and the OS user
// the text output names.
func (r *remoteInit) withMCP(res RemoteInitResult) RemoteInitResult {
	res.osUser = r.osUser
	res.MCPCommand = remoteMCPArgs(r.f.agent, r.f.configPath, r.settings.SocketDir, r.c.goos, r.c.host)
	fmt.Fprint(r.c.stderr, temporaryBinaryWarning(res.MCPCommand[0], os.TempDir()))
	return res
}

// connectOnlyResult is the result of a connect-only code: the connect link
// and the fingerprint, no laptop command; the steps P OPEN_LINK, A
// END_TURN, A CALL_TOOL status. A link over the budget is left out: the
// text says to paste the code at the connect page, and the step opens it.
func (r *remoteInit) connectOnlyResult(res RemoteInitResult, s config.Setup) (RemoteInitResult, error) {
	res.ConnectOnly = true
	lead := "Connect your database to " + r.f.agent + "."
	open := agent.ConnectLink(s.Code, r.connectBudget)
	if open != "" {
		res.ConnectURL = open
		res.PersonMessage, res.Links = agent.ConnectOnlyMessage(lead, open, s.Fingerprint)
	} else {
		res.pasteAtPortal = true
		open = links.Portal + links.ConnectPath
		res.PersonMessage = lead + " Open " + strings.TrimPrefix(open, "https://") + ", paste the setup code the agent shows you, check that it shows the setup fingerprint " + s.Fingerprint +
			", and follow the page. The page asks for your database's connection string: paste it there only. The agent never needs it, so never paste it into this chat."
	}
	steps, err := agent.NewSteps().
		OpenLink(open, "", agent.ConnectOnlyStepText).
		EndTurn("End your turn: the person runs the setup on the connect page. The page waits until this engine has picked up the database's address.").
		CallTool(toolStatus, map[string]any{}, "Call status to see whether the setup finished, or what the engine needs next.").
		Build()
	if err != nil {
		return RemoteInitResult{}, err
	}
	res.NextSteps = steps
	return res, nil
}

// setupCommand is what the person runs on their own computer.
func setupCommand(code string) string { return "basalt init --setup-code " + code }

// setupSteps are the steps of the result: with a connect link (url) the
// link comes first and the command second, as the catalog's connectLink
// variant of SETUP_NOT_RUN.
func setupSteps(code, url string) ([]agent.NextStep, error) {
	b := agent.NewSteps()
	if url != "" {
		b.OpenLink(url, "", agent.ConnectStepText)
	}
	return b.
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
	keys, err := channel.LoadOrCreateKeys(filepath.Join(r.stateDir, channel.KeyFileName), r.c.now)
	if err != nil {
		return nil, keyRefused(err)
	}
	return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())}, nil
}

func keyRefused(err error) error {
	return fmt.Errorf("the engine's key file is refused (%w); basalt status shows KEY_ERROR", err)
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
