package setupcli

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

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
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
)

// IsRemote reports whether args ask for basalt init --remote.
func IsRemote(args []string) bool {
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

// RunRemote is basalt init --remote: it makes a setup code for an
// agent-operated engine and prints it. h is what it reaches outside the CLI.
func RunRemote(c *cli.IO, h Host, args []string) int {
	res, err := InitRemote(c, h, args)
	if err != nil {
		return c.Fail(err)
	}
	if err := PrintRemoteResult(c, res); err != nil {
		return c.Fail(err)
	}
	return cli.ExitOK
}

// InitRemote runs basalt init --remote and returns what it prints.
func InitRemote(c *cli.IO, h Host, args []string) (setup.RemoteInitResult, error) {
	f, err := parseInitRemote(c, args)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	if err := setup.CheckBuildVersion(setup.BuildVersion()); err != nil {
		return setup.RemoteInitResult{}, err
	}
	r, err := newRemoteInit(c, h, f)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	res, err := r.run()
	r.unlock()
	return res, err
}

// parseInitRemote reads basalt init --remote's flags: --remote and
// --agent only (CONTRACT.md, CLI). The role's prefix and its statement
// timeout are fixed values.
func parseInitRemote(c *cli.IO, args []string) (setup.RemoteFlags, error) {
	f := setup.RemoteFlags{Prefix: cmp.Or(c.RolePrefix, guardmodel.DefaultPrefix), Timeout: guardmodel.DefaultRoleStatementTimeout, OperatedBy: setup.OperatedByAgent}
	var remote bool
	fs := c.Flags("init --remote")
	fs.BoolVar(&remote, flagRemote, false, "set up an agent on a bot's machine: prints the connect link the person opens")
	fs.StringVar(&f.Agent, "agent", "", "the agent's name (lowercase letters, digits, _); needed only when the engine serves more than one agent")
	if err := cli.Parse(fs, args); err != nil {
		return f, fmt.Errorf("%w (basalt init --remote takes only --agent; the connect page asks for the rest)", err)
	}
	f.ConfigPath = cmp.Or(c.Paths.Config, c.SystemConfig())
	return f, nil
}

// remoteAgentName is the agent a run without --agent sets up: the one
// agent the config has, else the default name. With more than one, --agent
// is required.
func remoteAgentName(agents []config.Agent) (string, error) {
	switch len(agents) {
	case 0:
		return setupcode.DemoAgent, nil
	case 1:
		return agents[0].Name, nil
	}
	return "", fmt.Errorf("%w: this engine serves more than one agent: give --agent NAME", cli.ErrUsage)
}

// remoteInit is one run of basalt init --remote: the paths, the existing
// config and credential, and what logging in as the agent found.
type remoteInit struct {
	c *cli.IO
	// setup is what the run reaches outside the CLI: the guard, the engine
	// keys and the trust profiles.
	setup    Host
	f        setup.RemoteFlags
	names    guardmodel.Names
	role     string
	settings config.Settings
	entry    *config.Agent
	credFile string
	// files reads and writes credFile, its .pending and its .lock: by
	// path, or as root through agents/ opened without following a link.
	files setup.CredFiles
	// configDir is, as root, the config directory opened without following
	// a link anyone but root controls: engine.json is locked, read and
	// written relative to it (nil not as root: by path).
	configDir setup.RootConfigDir
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
	// then moved over the credential file once the pending setup is
	// recorded). installed is the guard version it sees, recorded whether
	// the pending setup is recorded.
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

// Host is what basalt init --remote reaches outside the CLI: the guard's
// versions, records and agent connection string, the engine's keys, the
// trust profiles next to the config, the database's server errors, and the
// credential files and config directory, which root opens without following
// a link anyone but root or the file's owner controls.
type Host interface {
	setup.DBErrors
	// TrustProfileFor is the profile in the trust.d next to the config at
	// configPath that names host, or nil.
	TrustProfileFor(configPath, host string) *trustprofile.Profile
	// ConnTarget is the host and port a connection string names, and whether
	// its TLS check uses the system's roots (TLS on, no root certificate
	// given); the error is the driver's own.
	ConnTarget(dsn string) (setup.ConnTarget, error)
	// GuardAgentConnString is adminURL with the agent's role and password.
	GuardAgentConnString(adminURL, role, password string) (string, error)
	// GuardAgentVersion is the guard version q's database has, 0 when none.
	GuardAgentVersion(ctx context.Context, q cli.Querier) (int, error)
	// GuardLatestVersion is the guard version this binary installs.
	GuardLatestVersion() int
	// GuardSetupRecorded reports whether the setup with id is recorded.
	GuardSetupRecorded(ctx context.Context, q cli.Querier, id uuid.UUID) (bool, error)
	// LoadOrCreateEngineKeys reads the engine's keys at path, making them
	// when there are none.
	LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error)
	// PathCredFiles reaches the credential files by path: init --remote not
	// as root, in the user's own directories.
	PathCredFiles() setup.CredFiles
	// OpenRootCredFiles opens dir, the agents directory, as root, making it
	// (and the config directory) when missing. Every directory on the way
	// must be owned by root or trusted, and no link is followed. Reads
	// through it check the string another user wrote there.
	OpenRootCredFiles(dir string, trusted int) (setup.CredFiles, error)
	// RootTrustedOwner is the owner root trusts on the way to the config
	// directory dir: dir's, or, when it does not exist yet, that of the
	// nearest directory above it that does.
	RootTrustedOwner(dir string) (int, error)
	// OpenRootConfigDir opens dir, the config directory, as root, making it
	// when missing; engine.json is then locked, read and written relative
	// to it, checked as the hardened read checks it.
	OpenRootConfigDir(dir string, trusted int) (setup.RootConfigDir, error)
	// RootEngineKey is the engine's public key for a root init --remote:
	// the key file in stateDir read or, when there is none, created relative
	// to the state directory opened without following a link anyone but
	// root controls, owned by the config directory's owner.
	RootEngineKey(stateDir, goos string, cfg setup.RootConfigDir, now func() time.Time) ([]byte, error)
}

func newRemoteInit(c *cli.IO, h Host, f setup.RemoteFlags) (*remoteInit, error) {
	r := &remoteInit{c: c, setup: h, f: f}
	if err := r.paths(); err != nil {
		return nil, err
	}
	unlock, err := r.files.Lock(r.credFile + config.LockSuffix)
	if err != nil {
		r.files.Close()
		return nil, err
	}
	r.unlock = func() {
		unlock()
		r.files.Close()
		if r.configDir != nil {
			r.configDir.Close()
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
	dir := filepath.Dir(r.f.ConfigPath)
	r.settings = config.Settings{SocketDir: config.DefaultSocketDir(r.c.Goos), PagesURL: links.Portal}
	if r.c.Host.Euid() != 0 && r.c.Paths.Config == "" {
		found, err := r.c.FindConfig(r.f.Agent)
		if err != nil {
			return err
		}
		base, err := r.c.Host.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, config.UserDirName)
		// With two configs and the agent in the user's own, this init goes
		// on in that one: it writes no second config.
		if found != config.UserPath(base) {
			if err := r.c.RefuseSecondConfig(); err != nil {
				return err
			}
		}
		r.f.ConfigPath = filepath.Join(dir, "engine.json")
		r.settings.SocketDir = filepath.Join(dir, "run")
	}
	if r.f.ConfigPath != r.c.SystemConfig() {
		if r.c.Paths.Config != "" && r.c.Host.Euid() != 0 {
			// Not root, the system socket directory is not writable: keep
			// the sockets next to a config in another place.
			r.settings.SocketDir = filepath.Join(dir, "run")
		}
		r.settings.StateDir = filepath.Join(dir, setup.StateDirName)
	}
	r.stateDir = config.Config{StateDir: r.settings.StateDir}.StateDirFor(r.c.Goos)
	// As root, the hardened read (cli.LoadEngineConfig): the config must be a
	// plain file owned by root or its directory's owner, not writable by
	// group or others and reached without links, before any field is read.
	cfg, err := cli.LoadEngineConfig(r.c, r.f.ConfigPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		r.prev, r.existed = cfg, true
		r.stateDir = cfg.StateDirFor(r.c.Goos)
		r.settings.SocketDir = cfg.SocketDir
		r.linkBudget = cfg.LinkBudgetOrDefault()
	}
	if r.f.Agent == "" {
		name, err := remoteAgentName(r.prev.Agents)
		if err != nil {
			return err
		}
		r.f.Agent = name
	}
	if !config.ValidAgentName(r.f.Agent) {
		return fmt.Errorf("%w: agent name %q is not valid for the engine (lowercase letters, digits and _)", cli.ErrUsage, r.f.Agent)
	}
	for i := range r.prev.Agents {
		if r.prev.Agents[i].Name == r.f.Agent {
			r.entry = &r.prev.Agents[i]
		}
	}
	if err := r.settle(); err != nil {
		return err
	}
	if err := config.CheckSocketPath(config.SocketPath(r.settings.SocketDir, r.f.Agent)); err != nil {
		return fmt.Errorf("%w; use a shorter agent name", err)
	}
	asRoot := r.c.Host.Euid() == 0
	if asRoot {
		// The user who ran sudo is the person on this machine
		// (CONTRACT.md, Recording the person). Never root.
		person, err := InvokingUID(r.c)
		if err == nil && person != 0 {
			r.settings.PersonUIDs = []uint32{person}
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		dir = abs
	}
	r.credFile = filepath.Join(dir, "agents", r.f.Agent+".url")
	r.osUser = ""
	if r.entry != nil {
		if asRoot {
			// As root the computed path is used, never the config's
			// string: agents/sub/../bot.url passes the check but would
			// resolve through agents/sub.
			if _, err := config.RootCredentialPath(r.f.ConfigPath, r.f.Agent, r.entry.Store.CredentialFile); err != nil {
				return fmt.Errorf("%w; as root, basalt init --remote uses only that path. Fix the agent's store.credentialFile in the config", err)
			}
		} else {
			r.credFile = r.entry.Store.CredentialFile
		}
		r.osUser = r.entry.OSUser
	}
	if r.osUser == "" {
		u, err := cli.InvokingUser()
		if err != nil {
			return err
		}
		r.osUser = u
	}
	r.files = r.setup.PathCredFiles()
	if asRoot {
		trusted, err := r.setup.RootTrustedOwner(dir)
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
		files, err := r.setup.OpenRootCredFiles(filepath.Dir(r.credFile), trusted)
		if err != nil {
			return err
		}
		r.files = files
		if r.configDir, err = r.setup.OpenRootConfigDir(dir, trusted); err != nil {
			files.Close()
			return err
		}
	}
	return nil
}

// connection settles the database: the .pending credential's (a setup for
// another password may be waiting), else the credential file's, else none:
// a connect-only code, whose engine collects the address. It logs in as the
// agent with the credentials for that database, .pending first.
func (r *remoteInit) connection() error {
	cred, err := setup.ReadCredentialIfAny(r.files, r.credFile)
	if err != nil {
		return err
	}
	pending, err := setup.ReadCredentialIfAny(r.files, r.credFile+config.PendingSuffix)
	if err != nil {
		return err
	}
	switch {
	case pending != nil:
		r.base, r.target = pending.URL, pending.Target
	case cred != nil:
		r.base, r.target = cred.URL, cred.Target
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
	if prefix := setup.CredentialPrefix(r.base, r.f.Agent, r.target.SupabaseRef); prefix != "" && prefix != r.f.Prefix {
		if err := r.setPrefix(prefix); err != nil {
			return err
		}
	}
	// A credential for another database, or another role, is not this
	// one's: the engine uses a .pending only for its own database and role.
	if pending != nil && !r.sameLogin(pending) {
		pending = nil
	}
	if cred != nil && !r.sameLogin(cred) {
		cred = nil
	}
	// The password this machine holds for the database: the newest one.
	for _, c := range []*setup.Credential{cred, pending} {
		if c != nil {
			r.password = c.Password()
		}
	}
	// Before any login sends a startup message: say that a chain no
	// authority here verifies is trusted on the connect page. Nothing is
	// pinned here.
	r.noteUnknownAuthority()
	return r.login(pending, cred)
}

// sameLogin reports whether c names the database and the role of the base
// credential (r.base, r.target).
func (r *remoteInit) sameLogin(c *setup.Credential) bool {
	return c.Target == r.target && setup.URLUser(c.URL) == setup.URLUser(r.base)
}

// login logs in as the agent: with the .pending credential first (a
// setup the person may have run), which then replaces the credential
// file once the pending setup is recorded, as the engine promotes it, else
// with the credential file. A refused login is not an error: the role
// cannot log in. An unreachable database is, and changes nothing.
func (r *remoteInit) login(pending, cred *setup.Credential) error {
	if pending != nil {
		conn, err := r.c.AgentLogin(r.c.Ctx, pending.DSN)
		switch {
		case err == nil:
			defer conn.Close(r.c.Ctx)
			r.password = pending.Password()
			if err := r.inspect(conn); err != nil {
				return err
			}
			if !r.recorded {
				return nil // .pending stays until its setup is recorded
			}
			return r.promote(pending)
		case r.rootChanged(pending.DSN, err):
			r.certChanged = true
			return nil
		case !errors.Is(err, handoff.ErrLoginRefused):
			return err
		}
	}
	if cred == nil {
		return nil
	}
	conn, err := r.c.AgentLogin(r.c.Ctx, cred.DSN)
	switch {
	case errors.Is(err, handoff.ErrLoginRefused):
		return nil // the role cannot log in
	case r.rootChanged(cred.DSN, err):
		// Not a refused credential: the pinned host presents another
		// certificate. The connect page asks the person.
		r.certChanged = true
		return nil
	case err != nil:
		return err
	}
	r.password = cred.Password()
	defer conn.Close(r.c.Ctx)
	return r.inspect(conn)
}

// promote moves the .pending credential, which logs in, over the
// credential file, once the .pending path still names the file read, a
// regular file with one link.
func (r *remoteInit) promote(pending *setup.Credential) error {
	pendingFile := r.credFile + config.PendingSuffix
	now, err := r.files.Stat(pendingFile)
	if err != nil {
		return err
	}
	// The engine's check (config.SameCredentialFile): the same file, still
	// a regular file with one link.
	if !os.SameFile(now, pending.File) || config.CheckPlainFile(now) != nil {
		return fmt.Errorf("%s changed while basalt init ran; nothing changed, run it again", pendingFile)
	}
	if err := r.files.Rename(pendingFile, r.credFile); err != nil {
		return err
	}
	r.credExists = true
	return nil
}

// inspect reads, as the agent, the guard version and whether the pending
// setup is recorded.
func (r *remoteInit) inspect(conn cli.AgentConn) error {
	r.loggedIn = true
	v, err := r.setup.GuardAgentVersion(r.c.Ctx, conn)
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
	r.recorded, err = r.setup.GuardSetupRecorded(r.c.Ctx, conn, id)
	return err
}

// reusable is the pending setup init prints again: unexpired and not yet
// run.
func (r *remoteInit) reusable() *config.Setup {
	if r.entry == nil || r.entry.Setup == nil || r.recorded || r.password == "" || r.entry.Setup.CertificateChanged != r.certChanged {
		return nil
	}
	if r.entry.Setup.ConnectOnly() || setup.ConnectOnlyCode(r.entry.Setup.Code) {
		// A connect-only code with a credential file is never handed out
		// again on this path: the engine stopped between writing the
		// credential and clearing awaitingAddress, or the person confirmed
		// a database that does not record the setup (SETUP_NOT_FOUND). The
		// credential's own code replaces it.
		return nil
	}
	s := r.entry.Setup
	expires, err := s.Expires()
	if err != nil || !r.c.Now().Before(expires) {
		return nil
	}
	return s
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
func (r *remoteInit) decide() (setup.Plan, error) {
	latest := r.setup.GuardLatestVersion()
	if r.certChanged {
		return r.certificatePlan()
	}
	pendingInstall := r.entry != nil && r.entry.Setup != nil && r.entry.Setup.Kind == string(setupcode.KindInstall)
	if !r.loggedIn {
		switch {
		case r.password != "" && pendingInstall:
			return setup.Plan{Kind: setupcode.KindInstall, Password: r.password, Rotate: true}, nil
		case r.password != "":
			return r.withNewPassword(setup.Plan{Kind: setupcode.KindAgent})
		}
		return r.withNewPassword(setup.Plan{Kind: setupcode.KindInstall})
	}
	if r.installed > latest {
		return setup.Plan{}, fmt.Errorf("the database's guard (version %d) is newer than this basalt (version %d): update basalt on this machine first", r.installed, latest)
	}
	p := setup.Plan{From: r.installed}
	switch {
	case r.confirmedNotFound():
		p.Kind = setupcode.KindAgent
		return r.withNewPassword(p)
	case r.entry == nil:
		p.Kind = setupcode.KindAgent
	case r.installed < latest:
		p.Kind = setupcode.KindUpgrade
	default:
		p.Kind = setupcode.KindAgent
	}
	return p, nil
}

// confirmedNotFound reports whether the pending setup is a connect-only
// code whose database the person confirmed and that the database the agent
// logs in to does not record (the engine's SETUP_NOT_FOUND).
func (r *remoteInit) confirmedNotFound() bool {
	s := r.entry
	return s != nil && s.Setup != nil && !s.Setup.ConnectOnly() && setup.ConnectOnlyCode(s.Setup.Code) && !r.recorded
}

func (r *remoteInit) withNewPassword(p setup.Plan) (setup.Plan, error) {
	pw, err := setupcode.NewPassword()
	if err != nil {
		return setup.Plan{}, err
	}
	p.Password, p.Rotate, p.NewPassword = pw, true, true
	return p, nil
}

// payload builds the setup code's content.
func (r *remoteInit) payload(p setup.Plan) (setupcode.Payload, error) {
	id, expires, err := setupcode.NewSetupID(r.c.Now(), r.c.Rand)
	if err != nil {
		return setupcode.Payload{}, err
	}
	out := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: p.Kind, Prefix: r.f.Prefix,
		Guard: setupcode.Guard{From: p.From, To: r.setup.GuardLatestVersion()}, Build: setup.BuildVersion(), ExpiresAt: expires,
	}
	if !r.connectOnly {
		target := r.target
		out.Target, out.Engine = &target, r.engineKey()
		if p.Kind != setupcode.KindInstall {
			// The engine's pin for the host, a hint for the connect page.
			out.TrustPin = r.pinnedSHA()
		}
	}
	if r.certChanged && out.Engine == nil {
		return setupcode.Payload{}, setup.ErrNoEngineForTrust
	}
	if p.Kind == setupcode.KindUpgrade {
		return out, nil
	}
	// An INSTALL code asks for every table in public, which the person
	// ticks on the connect page. An AGENT code names no tables: the role
	// keeps the grants it holds (CONTRACT.md, The setup code, Kinds), and
	// a role that is gone runs as an INSTALL, with ticks.
	a := &setupcode.Agent{Name: r.f.Agent, StatementTimeoutMs: r.f.Timeout.Milliseconds()}
	if p.Kind == setupcode.KindInstall {
		a.AllTables = &setupcode.AllTables{Schemas: []string{"public"}}
	}
	if p.Rotate {
		if a.Verifier, err = setupcode.NewVerifier(p.Password); err != nil {
			return setupcode.Payload{}, err
		}
	}
	out.Agent = a
	return out, nil
}

// run makes (or reuses) the code, writes the credential and the config,
// and returns the result.
func (r *remoteInit) run() (setup.RemoteInitResult, error) {
	if r.connectOnly {
		return r.runConnectOnly()
	}
	if s := r.reusable(); s != nil {
		if err := r.writeConfig(s); err != nil {
			return setup.RemoteInitResult{}, err
		}
		return r.result(*s, true)
	}
	p, err := r.decide()
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	payload, err := r.payload(p)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	code, err := encodeSetup(payload)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	if err := r.writeCredential(p); err != nil {
		return setup.RemoteInitResult{}, err
	}
	s := setup.NewSetup(payload, code)
	s.CertificateChanged = r.certChanged
	if err := r.writeConfig(&s); err != nil {
		return setup.RemoteInitResult{}, err
	}
	// A .secret a connect-only code left belongs to a code engine.json no
	// longer records: its password is dropped.
	if err := r.removeSecret(); err != nil {
		return setup.RemoteInitResult{}, err
	}
	return r.result(s, false)
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
		r.f.OperatedBy = setup.OperatedByPerson
	}
	if err := r.setPrefix(r.f.Prefix); err != nil {
		return err
	}
	vc, err := ChooseVault("", r.f.OperatedBy, links.Portal, setup.RemoteVaultWhy)
	if err != nil {
		return err
	}
	r.f.Vault = vc
	r.settings = vc.Settings(r.settings)
	r.settings.OperatedBy = r.f.OperatedBy.Enum()
	return nil
}

// setPrefix sets the role prefix of the agent's names and role.
func (r *remoteInit) setPrefix(prefix string) error {
	r.f.Prefix = prefix
	r.names = guardmodel.Names{Prefix: prefix}
	role, err := r.names.Agent(r.f.Agent)
	if err != nil {
		return fmt.Errorf("%w: %w", cli.ErrUsage, err)
	}
	r.role = role
	return nil
}

// secretPath is agents/<agent>.secret, next to the credential file.
func (r *remoteInit) secretPath() string {
	return config.SecretPath(r.credFile, r.f.Agent)
}

// hasSecret reports whether the agent's .secret exists.
func (r *remoteInit) hasSecret() (bool, error) {
	_, err := r.files.Stat(r.secretPath())
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
	err := r.files.Remove(r.secretPath())
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
func (r *remoteInit) runConnectOnly() (setup.RemoteInitResult, error) {
	pending := r.pendingConnectOnly()
	if pending != nil && !pending.Refused && !pending.AddressInvalid {
		reuse, err := r.reuseConnectOnly(pending)
		if err != nil || reuse {
			if err != nil {
				return setup.RemoteInitResult{}, err
			}
			if err := r.writeConfig(pending); err != nil {
				return setup.RemoteInitResult{}, err
			}
			return r.result(*pending, true)
		}
	}
	kind := setupcode.KindInstall
	if pending != nil {
		kind = setupcode.KindAgent
	}
	p, err := r.withNewPassword(setup.Plan{Kind: kind})
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	payload, err := r.connectOnlyPayload(p)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	code, err := encodeSetup(payload)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	// The old password is dropped only now, after the engine's key and the
	// code: a refusal before this point leaves everything as it was.
	if err := r.removeSecret(); err != nil {
		return setup.RemoteInitResult{}, err
	}
	if err := r.files.Write(r.secretPath(), []byte(p.Password+"\n")); err != nil {
		return setup.RemoteInitResult{}, err
	}
	s := setup.NewSetup(payload, code)
	if err := r.writeConfig(&s); err != nil {
		return setup.RemoteInitResult{}, err
	}
	return r.result(s, false)
}

// reuseConnectOnly decides about a connect-only code still waiting: true
// to print it again (unexpired, .secret there), false when it expired or
// its password is gone (a recovery code then).
func (r *remoteInit) reuseConnectOnly(pending *config.Setup) (bool, error) {
	expires, err := pending.Expires()
	if err != nil || !r.c.Now().Before(expires) {
		return false, nil //nolint:nilerr // an expired or malformed pending code is replaced
	}
	return r.hasSecret()
}

// connectOnlyPayload is a connect-only code's content: no target, and the
// engine's key, without which the engine could not collect the address.
func (r *remoteInit) connectOnlyPayload(p setup.Plan) (setupcode.Payload, error) {
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
		return "", fmt.Errorf("%w: %s", cli.ErrUsage, setupcode.InvalidDetail(err))
	}
	return code, nil
}

// writeCredential writes a new password's connection string. It never
// replaces a credential file that exists: a login refused now may be a
// transient error, and the old password may still be the one that works,
// so the new one waits in .pending until a login proves it and the pending
// setup is recorded (the engine, or the next run of init, then moves it
// over). Only the first credential goes straight to the credential file.
// Both 0600, atomic, never through a symlink (config.WriteFile). A password
// this machine already holds is not written again.
//
// One state is left as is: with the credential file deleted by hand, a
// .pending that logs in for a setup not recorded, and a new password
// (confirmedNotFound), the new password goes to the credential file while
// the working one stays in .pending. init never deletes the credential
// file itself, so only a hand edit reaches this state.
func (r *remoteInit) writeCredential(p setup.Plan) error {
	if !p.NewPassword {
		return nil
	}
	dsn, err := r.setup.GuardAgentConnString(r.base.String(), r.role, p.Password)
	if err != nil {
		return err
	}
	dsn, applied := setup.HardenedCredential(r.c.Ctx, r.c.Probe, r.setup, dsn)
	fmt.Fprint(r.c.Stderr, applied.Line())
	path := r.credFile
	if r.credExists {
		path += config.PendingSuffix
	}
	return r.files.Write(path, []byte(dsn+"\n"))
}

// writeConfig upserts the agent and prints the vault value it wrote.
func (r *remoteInit) writeConfig(s *config.Setup) error {
	a := config.Agent{Name: r.f.Agent, OSUser: r.osUser, Store: config.PostgresStore(r.credFile), Setup: s}
	var v config.VaultWritten
	var err error
	if r.configDir != nil {
		// As root, through the directory opened in paths: a config
		// directory swapped for a symlink since then redirects nothing.
		v, err = r.configDir.Upsert(filepath.Base(r.f.ConfigPath), r.settings, a)
	} else {
		v, err = config.UpsertAgentVault(r.f.ConfigPath, r.settings, a)
	}
	if err != nil {
		return err
	}
	fmt.Fprint(r.c.Stderr, r.serviceNote)
	fmt.Fprint(r.c.Stderr, remoteVaultLine(v))
	r.connectBudget = 0
	if r.f.OperatedBy == setup.OperatedByAgent && v.Vault == config.VaultOn {
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
		return fmt.Sprintf("basalt: vault: %s (kept from engine.json)\n", setup.ModeOf(w.Vault))
	}
	return fmt.Sprintf("basalt: vault: %s\n", setup.ModeOf(w.Vault))
}

// result is the remote-init result: the code, and what the person does
// with it.
func (r *remoteInit) result(s config.Setup, reused bool) (setup.RemoteInitResult, error) {
	res := setup.RemoteInitResult{
		Agent: r.f.Agent, SetupID: s.SetupID, Kind: s.Kind, Code: s.Code, Fingerprint: s.Fingerprint,
		Reused: reused, ExpiresAt: s.ExpiresAt, PersonMessage: setupPersonMessage(r.f.Agent, s.Fingerprint),
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
func (r *remoteInit) withSetupGuidance(res setup.RemoteInitResult, s config.Setup) setup.RemoteInitResult {
	// An agent-operated engine with the Vault on hands the connect link
	// when the whole link fits the budget (no network call: the link only
	// holds the code); else the text says where to paste the code.
	url := guidance.ConnectLink(s.Code, r.connectBudget)
	if url != "" {
		res.ConnectURL = url
		res.PersonMessage, _ = guidance.ConnectMessage("Finish setting up Basalt for "+r.f.Agent+".", url, s.Fingerprint)
	}
	res.PasteAtPortal = url == ""
	return res
}

// withMCP adds the basalt mcp command the agent registers, and the OS user
// the text output names.
func (r *remoteInit) withMCP(res setup.RemoteInitResult) setup.RemoteInitResult {
	res.OSUser = r.osUser
	res.MCPCommand = setup.MCPArgs(r.f.Agent, setup.MCPBinary(r.c.Host))
	fmt.Fprint(r.c.Stderr, setup.TemporaryBinaryWarning(res.MCPCommand[0], os.TempDir()))
	return res
}

// connectOnlyResult is the result of a connect-only code: the connect link
// and the fingerprint, no laptop command. A link over the budget is left
// out: the text says to paste the code at the connect page.
func (r *remoteInit) connectOnlyResult(res setup.RemoteInitResult, s config.Setup) setup.RemoteInitResult {
	res.ConnectOnly = true
	lead := "Connect your database to " + r.f.Agent + "."
	if open := guidance.ConnectLink(s.Code, r.connectBudget); open != "" {
		res.ConnectURL = open
		res.PersonMessage, _ = guidance.ConnectOnlyMessage(lead, open, s.Fingerprint)
		return res
	}
	res.PasteAtPortal = true
	page := strings.TrimPrefix(links.Portal+links.ConnectPath, "https://")
	res.PersonMessage = lead + " Open " + page + ", paste the setup code the agent shows you, check that it shows the setup fingerprint " + s.Fingerprint +
		", and follow the page. The page asks for your database's connection string: paste it there only. The agent never needs it, so never paste it into this chat."
	return res
}

// setupPersonMessage is what the agent shows the person verbatim, within
// guidance.MaxPersonMessageLength for the longest agent name: it names the
// agent once.
func setupPersonMessage(name, fingerprint string) string {
	return fmt.Sprintf("Finish setting up Basalt for %s: open %s, paste the setup code the agent shows you, "+
		"check that it shows the setup fingerprint %s, and follow the page. "+
		"The page asks for your database's connection string: paste it there only, never into this chat.",
		name, strings.TrimPrefix(links.Portal+links.ConnectPath, "https://"), fingerprint)
}

// PrintRemoteResult prints the result: the connect link or the code in a
// block of its own, its fingerprint and what the person does.
func PrintRemoteResult(c *cli.IO, res setup.RemoteInitResult) error {
	if res.Reused {
		fmt.Fprintln(c.Stderr, "basalt: a setup code is pending for this agent; here it is again")
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
	_, err = fmt.Fprintf(c.Stdout, "Setup code for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, expires.UTC().Format("2006-01-02 15:04 UTC"), res.Code, res.Fingerprint, res.PersonMessage)
	if err == nil && res.PasteAtPortal {
		// The link is over the budget: no link is printed, the code is
		// pasted at the connect page instead.
		_, err = fmt.Fprintf(c.Stdout, "\nTo use Basalt Vault, a hosted service, paste the setup code at %s.\n", strings.TrimPrefix(links.Portal+links.ConnectPath, "https://"))
	}
	if err != nil {
		return err
	}
	return printRemoteMCP(c, res)
}

// printRemoteMCP prints the basalt mcp command the agent registers.
func printRemoteMCP(c *cli.IO, res setup.RemoteInitResult) error {
	_, err := fmt.Fprintf(c.Stdout, "then add this MCP server to the agent's client, running as OS user %s:\n  %s\n",
		res.OSUser, guidance.ShellJoin(res.MCPCommand))
	return err
}

// engineKey is the engine's signing key for the code (M4.1, CO-18), made
// as the engine makes it on its first start when the key file is missing.
// Run as root, init cannot make a file the engine's OS user owns, and an
// unreadable or refused file is never replaced: then the code carries no
// engine key, and init says why on stderr.
func (r *remoteInit) engineKey() *setupcode.Engine {
	key, err := r.loadEngineKey()
	if err != nil {
		fmt.Fprintf(r.c.Stderr, "basalt: the code carries no engine key: %v\n", err)
		return nil
	}
	return key
}

// loadEngineKey is engineKey's key, or why there is none.
func (r *remoteInit) loadEngineKey() (*setupcode.Engine, error) {
	if r.c.Host.Euid() == 0 {
		// As root, through the state directory opened without following a
		// link the engine's user controls; a new key file is that user's.
		spki, err := r.setup.RootEngineKey(r.stateDir, r.c.Goos, r.configDir, r.c.Now)
		if err != nil {
			return nil, setup.KeyRefused(err)
		}
		return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(spki)}, nil
	}
	if err := os.MkdirAll(r.stateDir, engine.StateDirMode); err != nil {
		return nil, err
	}
	keys, err := r.setup.LoadOrCreateEngineKeys(filepath.Join(r.stateDir, channel.KeyFileName), r.c.Now)
	if err != nil {
		return nil, setup.KeyRefused(err)
	}
	return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())}, nil
}

// printConnectOnly prints a connect-only code's result: the connect link
// and the fingerprint, never a laptop command, or, over the link budget,
// the code to paste at the connect page.
func printConnectOnly(c *cli.IO, res setup.RemoteInitResult, expires time.Time) error {
	until := expires.UTC().Format("2006-01-02 15:04 UTC")
	if res.ConnectURL == "" {
		_, err := fmt.Fprintf(c.Stdout, "Setup code for %s (%s), for the connect page only, valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
			res.Agent, res.Kind, until, res.Code, res.Fingerprint, res.PersonMessage)
		return err
	}
	_, err := fmt.Fprintf(c.Stdout, "Connect link for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, until, res.ConnectURL, res.Fingerprint, res.PersonMessage)
	return err
}
