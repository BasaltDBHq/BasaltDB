package setup

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/trustpin"
	"github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
	"github.com/basaltdbhq/basaltdb/internal/lib/certroots"
)

// The run of basalt init --remote (CONTRACT.md, basalt init --remote): it
// finds the config, the agent's credential files and what the agent's
// login sees, decides the code (RemoteRun), and writes the credential, the
// .secret and the config. The CLI (setupcli) parses its flags and prints
// the result; it fills RemoteEnv.

// InitRemote runs basalt init --remote with the flags f and returns what it
// prints. Usage errors wrap ErrUsage.
func InitRemote(ctx context.Context, env RemoteEnv, h RemoteHost, f RemoteFlags) (RemoteInitResult, error) {
	r, err := newRemoteInit(ctx, env, h, f)
	if err != nil {
		return RemoteInitResult{}, err
	}
	res, err := r.run()
	r.unlock()
	return res, err
}

// The database certificate on persona 2 (CONTRACT.md, Pinning from the
// connect page): basalt init --remote never pins. The person trusts a
// certificate on the connect page, and the bot's engine pins it only after
// its own reading of the chain matches. These helpers stand alone, on
// pkg/trustpin and trustdir, so init --remote needs nothing of the removed
// basalt trust commands.

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
	return "", fmt.Errorf("%w: this engine serves more than one agent: give --agent NAME", ErrUsage)
}

// remoteInit is one run of basalt init --remote: the paths, the existing
// config and credential, and what logging in as the agent found.
type remoteInit struct {
	ctx context.Context
	// env is what the run reaches through the CLI: the process, its
	// configs, the agent's login, the clock and stderr.
	env RemoteEnv
	// host is what the run reaches outside the CLI: the guard, the engine
	// keys and the trust profiles.
	host     RemoteHost
	f        RemoteFlags
	names    guardmodel.Names
	role     string
	settings config.Settings
	entry    *config.Agent
	credFile string
	// files reads and writes credFile, its .pending and its .lock: by
	// path, or as root through agents/ opened without following a link.
	files CredFiles
	// configDir is, as root, the config directory opened without following
	// a link anyone but root controls: engine.json is locked, read and
	// written relative to it (nil not as root: by path).
	configDir RootConfigDir
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

func newRemoteInit(ctx context.Context, env RemoteEnv, h RemoteHost, f RemoteFlags) (*remoteInit, error) {
	r := &remoteInit{ctx: ctx, env: env, host: h, f: f}
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
	r.settings = config.Settings{SocketDir: config.DefaultSocketDir(r.env.Goos()), PagesURL: links.Portal}
	if r.env.Euid() != 0 && r.env.ConfigFlag() == "" {
		found, err := r.env.FindConfig(r.f.Agent)
		if err != nil {
			return err
		}
		base, err := r.env.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, config.UserDirName)
		// With two configs and the agent in the user's own, this init goes
		// on in that one: it writes no second config.
		if found != config.UserPath(base) {
			if err := r.env.RefuseSecondConfig(); err != nil {
				return err
			}
		}
		r.f.ConfigPath = filepath.Join(dir, "engine.json")
		r.settings.SocketDir = filepath.Join(dir, "run")
	}
	if r.f.ConfigPath != r.env.SystemConfig() {
		if r.env.ConfigFlag() != "" && r.env.Euid() != 0 {
			// Not root, the system socket directory is not writable: keep
			// the sockets next to a config in another place.
			r.settings.SocketDir = filepath.Join(dir, "run")
		}
		r.settings.StateDir = filepath.Join(dir, StateDirName)
	}
	r.stateDir = config.Config{StateDir: r.settings.StateDir}.StateDirFor(r.env.Goos())
	// As root, the hardened read (RemoteEnv.LoadEngineConfig): the config must be a
	// plain file owned by root or its directory's owner, not writable by
	// group or others and reached without links, before any field is read.
	cfg, err := r.env.LoadEngineConfig(r.f.ConfigPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		r.prev, r.existed = cfg, true
		r.stateDir = cfg.StateDirFor(r.env.Goos())
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
		return fmt.Errorf("%w: agent name %q is not valid for the engine (lowercase letters, digits and _)", ErrUsage, r.f.Agent)
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
	asRoot := r.env.Euid() == 0
	if asRoot {
		// The user who ran sudo is the person on this machine
		// (CONTRACT.md, Recording the person). Never root.
		person, err := r.env.InvokingUID()
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
		u, err := r.env.InvokingUser()
		if err != nil {
			return err
		}
		r.osUser = u
	}
	r.files = r.host.PathCredFiles()
	if asRoot {
		trusted, err := r.host.RootTrustedOwner(dir)
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
		files, err := r.host.OpenRootCredFiles(filepath.Dir(r.credFile), trusted)
		if err != nil {
			return err
		}
		r.files = files
		if r.configDir, err = r.host.OpenRootConfigDir(dir, trusted); err != nil {
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
	cred, err := ReadCredentialIfAny(r.files, r.credFile)
	if err != nil {
		return err
	}
	pending, err := ReadCredentialIfAny(r.files, r.credFile+config.PendingSuffix)
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
		if err := ConnectOnlyAllowed(r.settings, r.prev, r.existed); err != nil {
			return err
		}
		r.connectOnly = true
		return nil
	}
	r.credExists = cred != nil
	if prefix := CredentialPrefix(r.base, r.f.Agent, r.target.SupabaseRef); prefix != "" && prefix != r.f.Prefix {
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
	for _, c := range []*Credential{cred, pending} {
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
func (r *remoteInit) sameLogin(c *Credential) bool {
	return c.Target == r.target && URLUser(c.URL) == URLUser(r.base)
}

// login logs in as the agent: with the .pending credential first (a
// setup the person may have run), which then replaces the credential
// file once the pending setup is recorded, as the engine promotes it, else
// with the credential file. A refused login is not an error: the role
// cannot log in. An unreachable database is, and changes nothing.
func (r *remoteInit) login(pending, cred *Credential) error {
	if pending != nil {
		conn, err := r.env.AgentLogin(r.ctx, pending.DSN)
		switch {
		case err == nil:
			defer conn.Close(r.ctx)
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
		case !r.env.LoginRefused(err):
			return err
		}
	}
	if cred == nil {
		return nil
	}
	conn, err := r.env.AgentLogin(r.ctx, cred.DSN)
	switch {
	case r.env.LoginRefused(err):
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
	defer conn.Close(r.ctx)
	return r.inspect(conn)
}

// promote moves the .pending credential, which logs in, over the
// credential file, once the .pending path still names the file read, a
// regular file with one link.
func (r *remoteInit) promote(pending *Credential) error {
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
func (r *remoteInit) inspect(conn RemoteAgentConn) error {
	r.loggedIn = true
	v, err := r.host.GuardAgentVersion(r.ctx, conn)
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
	r.recorded, err = r.host.GuardSetupRecorded(r.ctx, conn, id)
	return err
}

// facts is what this run found, as the setup service's decisions read it
// (RemoteRun).
func (r *remoteInit) facts() RemoteRun {
	return RemoteRun{
		Agent: r.f.Agent, Prefix: r.f.Prefix, Timeout: r.f.Timeout, Entry: r.entry, Password: r.password,
		LoggedIn: r.loggedIn, Recorded: r.recorded, Installed: r.installed, Latest: r.host.GuardLatestVersion(),
		CertChanged: r.certChanged, ConnectOnly: r.connectOnly, Target: r.target,
	}
}

// payload builds the setup code's content (RemoteRun.Payload), with
// the engine's key and its pin for the host read here.
func (r *remoteInit) payload(p Plan) (setupcode.Payload, error) {
	return r.facts().Payload(p, r.env.Now(), r.env.Rand(), r.engineKey, r.pinnedSHA)
}

// run makes (or reuses) the code, writes the credential and the config,
// and returns the result.
func (r *remoteInit) run() (RemoteInitResult, error) {
	if r.connectOnly {
		return r.runConnectOnly()
	}
	if s := r.facts().Reusable(r.env.Now()); s != nil {
		if err := r.writeConfig(s); err != nil {
			return RemoteInitResult{}, err
		}
		return r.result(*s, true)
	}
	p, err := r.facts().Decide()
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
	s := NewSetup(payload, code)
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

// settle settles what the run depends on: the role's names, the operator
// and the vault it writes. --remote makes a new engine agent-operated;
// afterwards the config says who operates it (CONTRACT.md, Who operates
// the engine), so a person-operated engine is never made agent-operated
// behind the person's back: the connect path then refuses.
func (r *remoteInit) settle() error {
	if r.existed && r.prev.OperatedBy != mcpcontract.OperatedByAgent {
		r.f.OperatedBy = OperatedByPerson
	}
	if err := r.setPrefix(r.f.Prefix); err != nil {
		return err
	}
	vc, err := ChooseVault("", r.f.OperatedBy, links.Portal, RemoteVaultWhy)
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
		return fmt.Errorf("%w: %w", ErrUsage, err)
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
func (r *remoteInit) runConnectOnly() (RemoteInitResult, error) {
	pending := r.facts().PendingConnectOnly()
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
	p, err := r.facts().ConnectOnlyPlan()
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
	if err := r.files.Write(r.secretPath(), []byte(p.Password+"\n")); err != nil {
		return RemoteInitResult{}, err
	}
	s := NewSetup(payload, code)
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
	if err != nil || !r.env.Now().Before(expires) {
		return false, nil //nolint:nilerr // an expired or malformed pending code is replaced
	}
	return r.hasSecret()
}

// connectOnlyPayload is a connect-only code's content: no target, and the
// engine's key, without which the engine could not collect the address.
func (r *remoteInit) connectOnlyPayload(p Plan) (setupcode.Payload, error) {
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
		return "", fmt.Errorf("%w: %s", ErrUsage, setupcode.InvalidDetail(err))
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
func (r *remoteInit) writeCredential(p Plan) error {
	if !p.NewPassword {
		return nil
	}
	dsn, err := r.host.GuardAgentConnString(r.base.String(), r.role, p.Password)
	if err != nil {
		return err
	}
	dsn, applied := HardenedCredential(r.ctx, r.env.Probe, r.host, dsn)
	fmt.Fprint(r.env.Stderr(), applied.Line())
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
		v, err = r.host.UpsertAgentVault(r.f.ConfigPath, r.settings, a)
	}
	if err != nil {
		return err
	}
	fmt.Fprint(r.env.Stderr(), r.serviceNote)
	fmt.Fprint(r.env.Stderr(), remoteVaultLine(v))
	r.connectBudget = 0
	if r.f.OperatedBy == OperatedByAgent && v.Vault == config.VaultOn {
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
		return fmt.Sprintf("basalt: vault: %s (kept from engine.json)\n", ModeOf(w.Vault))
	}
	return fmt.Sprintf("basalt: vault: %s\n", ModeOf(w.Vault))
}

// result is the remote-init result: the code, and what the person does
// with it (RemoteRun.RemoteResult), with the basalt mcp command.
func (r *remoteInit) result(s config.Setup, reused bool) (RemoteInitResult, error) {
	return r.withMCP(r.facts().RemoteResult(s, reused, r.connectBudget)), nil
}

// withMCP adds the basalt mcp command the agent registers, and the OS user
// the text output names.
func (r *remoteInit) withMCP(res RemoteInitResult) RemoteInitResult {
	res.OSUser = r.osUser
	res.MCPCommand = MCPArgs(r.f.Agent, r.env.MCPBinary())
	fmt.Fprint(r.env.Stderr(), TemporaryBinaryWarning(res.MCPCommand[0], os.TempDir()))
	return res
}

// engineKey is the engine's signing key for the code (M4.1, CO-18), made
// as the engine makes it on its first start when the key file is missing.
// Run as root, init cannot make a file the engine's OS user owns, and an
// unreadable or refused file is never replaced: then the code carries no
// engine key, and init says why on stderr.
func (r *remoteInit) engineKey() *setupcode.Engine {
	key, err := r.loadEngineKey()
	if err != nil {
		fmt.Fprintf(r.env.Stderr(), "basalt: the code carries no engine key: %v\n", err)
		return nil
	}
	return key
}

// loadEngineKey is engineKey's key, or why there is none.
func (r *remoteInit) loadEngineKey() (*setupcode.Engine, error) {
	if r.env.Euid() == 0 {
		// As root, through the state directory opened without following a
		// link the engine's user controls; a new key file is that user's.
		spki, err := r.host.RootEngineKey(r.stateDir, r.env.Goos(), r.configDir, r.env.Now)
		if err != nil {
			return nil, KeyRefused(err)
		}
		return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(spki)}, nil
	}
	if err := r.env.MkdirStateDir(r.stateDir); err != nil {
		return nil, err
	}
	keys, err := r.host.LoadOrCreateEngineKeys(filepath.Join(r.stateDir, channel.KeyFileName), r.env.Now)
	if err != nil {
		return nil, KeyRefused(err)
	}
	return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())}, nil
}

// noteUnknownAuthority says, before any login, that the credential's host
// presents a chain no authority here verifies and that no profile covers:
// the person trusts it on the connect page. Nothing is pinned. A chain that
// cannot be read, or that verifies, says nothing.
func (r *remoteInit) noteUnknownAuthority() {
	if r.base == nil || r.env.FetchChain() == nil {
		return
	}
	target, err := r.host.ConnTarget(r.base.String())
	if err != nil || target.Host == "" || !target.SystemRoots {
		return
	}
	host := trustprofile.NormalizeHost(target.Host)
	if r.host.TrustProfileFor(r.f.ConfigPath, host) != nil {
		return // a profile, a pin included, decides; a changed pin shows at the login
	}
	chain, err := r.env.FetchChain()(r.ctx, host, target.Port)
	if err != nil {
		return
	}
	if seen := trustpin.Check(chain, host, r.env.Now(), certroots.Store{}); seen.Pinnable() {
		fmt.Fprintf(r.env.Stderr(), "basalt: %s presents a certificate authority no authority on this machine verifies: %s\n",
			r.env.TerminalText(host), ConnectPageTrust)
	}
}

// pinOf is the engine's pin for host in the config's trust.d: its
// pin-<host> profile, or nil, read through h.
func pinOf(h RemoteHost, configPath, host string) *trustprofile.Profile {
	p := h.TrustProfileFor(configPath, host)
	if p == nil || !p.Exact() || p.Name != trustprofile.PinName(host) {
		return nil
	}
	return p
}

// pinnedSHA is the SHA-256 (DER, lowercase hex) of the certificate the
// engine has pinned for the target's host: the code's trustPin, "" when it
// has no pin.
func (r *remoteInit) pinnedSHA() string {
	p := pinOf(r.host, r.f.ConfigPath, trustprofile.NormalizeHost(r.target.Host))
	if p == nil || len(p.Certificates()) == 0 {
		return ""
	}
	return trustprofile.DERSHA256(p.Certificates()[0])
}

// rootChanged reports whether err, a login of dsn, failed on the
// certificate of a host pinned in the config's trust.d whose chain top now
// (read with the TLS handshake alone) is not the pinned one:
// TRUST_ROOT_CHANGED. Never accepted here: the connect page asks the
// person, and the engine checks its own reading.
func (r *remoteInit) rootChanged(dsn string, err error) bool {
	if r.env.FetchChain() == nil || !trustprofile.CertificateNotVerified(err) {
		return false
	}
	target, perr := r.host.ConnTarget(dsn)
	if perr != nil || target.Host == "" {
		return false
	}
	host := trustprofile.NormalizeHost(target.Host)
	p := pinOf(r.host, r.f.ConfigPath, host)
	if p == nil {
		return false
	}
	chain, ferr := r.env.FetchChain()(r.ctx, host, target.Port)
	if ferr != nil || len(chain) == 0 {
		return false
	}
	return !pinned(p.Certificates(), chain[len(chain)-1])
}

// pinned reports whether top is one of the pinned certificates.
func pinned(certs []*x509.Certificate, top *x509.Certificate) bool {
	for _, c := range certs {
		if c.Equal(top) {
			return true
		}
	}
	return false
}
