package setup

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

const (
	// PendingSuffix names the new password's file while an AGENT code that
	// rotates it waits: the old password keeps working until the person runs
	// the code (RI-5).
	PendingSuffix = ".pending"
	// LockSuffix names the lock file that keeps two runs of init --remote
	// for one agent apart.
	LockSuffix = ".lock"
)

// RemoteVaultWhy says why the vault is off by default for an engine
// another init made person-operated.
const RemoteVaultWhy = "default for a person-operated engine"

// RemoteFlags are what basalt init --remote asks for: --agent, and the
// fixed values the removed flags used to change. The agent's tables are
// never among them: an INSTALL code lets the person tick them on the
// connect page, and an AGENT code keeps the role's grants (the database's
// grants are the only record of them).
type RemoteFlags struct {
	Agent, Prefix, ConfigPath string
	Timeout                   time.Duration
	OperatedBy                OperatedBy
	// Vault is what init asks the config's vault to be (setupcli.ChooseVault).
	Vault VaultChoice
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
	// PasteAtPortal: the engine would hand the connect link but the whole
	// link does not fit the budget, so the text output says to paste the
	// code at the connect page instead.
	PasteAtPortal bool
	// OSUser is the OS user the MCP command runs as, for the text output.
	OSUser string
}

// CredFiles reads and writes the agent's credential file, its .pending and
// its .lock for init --remote, each named by its full path.
type CredFiles interface {
	Lock(path string) (func(), error)
	// Read reads a credential file this process wrote (with the checks of
	// credfiles' readOwnCredential); an error wrapping fs.ErrNotExist when
	// there is none.
	Read(path string) (string, os.FileInfo, error)
	// Stat is the file at path, not following a link.
	Stat(path string) (os.FileInfo, error)
	Write(path string, data []byte) error
	Rename(from, to string) error
	// Remove removes the file at path, not following a link.
	Remove(path string) error
	Close()
}

// Credential is a credential file as read: its connection string, the
// database it names, and the file it was read from (to check, before
// moving it, that the path still names that file).
type Credential struct {
	DSN    string
	URL    *url.URL
	Target setupcode.Target
	File   os.FileInfo
}

// Password is the credential's password.
func (c *Credential) Password() string {
	pw, _ := c.URL.User.Password()
	return pw
}

// URLUser is u's user name, "" when it names none.
func URLUser(u *url.URL) string {
	if u == nil || u.User == nil {
		return ""
	}
	return u.User.Username()
}

// ReadCredentialIfAny reads a credential file with the no-follow checks,
// or nil when there is none.
func ReadCredentialIfAny(files CredFiles, path string) (*Credential, error) {
	dsn, fi, err := files.Read(path)
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
	return &Credential{DSN: dsn, URL: u, Target: t, File: fi}, nil
}

// Plan is the code init makes: its kind, the password whose verifier it
// carries (rotate), whether that password is new (and so written: see
// writeCredential), and the guard versions.
type Plan struct {
	Kind                setupcode.Kind
	Password            string
	Rotate, NewPassword bool
	From                int
}

// BuildVersion is this build's version in the code's form (no leading v,
// no build metadata).
func BuildVersion() string {
	v := strings.TrimPrefix(buildinfo.Version, "v")
	v, _, _ = strings.Cut(v, "+")
	return v
}

// CheckBuildVersion refuses, before anything is written, a build whose
// version a setup code cannot carry (a source build without tags: "dev").
func CheckBuildVersion(version string) error {
	if setupcode.ValidBuild(version) {
		return nil
	}
	return fmt.Errorf("this build of basalt has no release version (it reports %q), so it cannot make a setup code; install a release build", version)
}

// NewSetup is the pending setup engine.json records for a new code.
func NewSetup(p setupcode.Payload, code string) config.Setup {
	return config.Setup{
		SetupID: p.SetupID, Kind: string(p.Kind), GuardVersion: p.Guard.To,
		ExpiresAt: p.ExpiresAt, Code: code, Fingerprint: p.Fingerprint(), AwaitingAddress: p.ConnectOnly(),
	}
}

// ConnectOnlyCode reports whether code is a connect-only setup code (it
// has no target). A code that cannot be read is not.
func ConnectOnlyCode(code string) bool {
	p, err := setupcode.Decode(code)
	return err == nil && p.ConnectOnly()
}

// CredentialPrefix is the role prefix of the credential this machine holds
// for the agent: its user is <prefix>_agent_<name> (with .<ref> through
// Supabase's pooler). The credential names the role, so a code for it names
// that role, never a saved copy; "" when its user is not such a role (the
// fixed default prefix then).
func CredentialPrefix(u *url.URL, agent, supabaseRef string) string {
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

func KeyRefused(err error) error {
	return fmt.Errorf("the engine's key file is refused (%w); the agent's status tool shows KEY_ERROR", err)
}

// ErrNoEngineForTrust: the engine collects the certificate the person
// trusted with its key, so a code without one could never finish.
var ErrNoEngineForTrust = errors.New("the database's certificate changed, and the setup code that replaces the engine's pin " +
	"needs the engine's key, which cannot be read here: run basalt init --remote as the engine's OS user")

// StateDirName is the engine's state directory next to a per-user config.
const StateDirName = "state"

// RootConfigDir is the config directory init --remote opened as root: the
// consumer is the setup CLI, whose host opens it, and the type is here so
// the host's implementation need not import that controller.
type RootConfigDir interface {
	// Upsert is config.UpsertAgentVault on the config file name, relative to
	// the opened directory.
	Upsert(name string, s config.Settings, a config.Agent) (config.VaultWritten, error)
	// Close closes the directory.
	Close()
}

// ConnTarget is where a connection string connects.
type ConnTarget struct {
	Host string
	Port int
	// SystemRoots: TLS is on and the roots are the system's.
	SystemRoots bool
}
