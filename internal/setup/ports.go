package setup

import (
	"context"
	"crypto/x509"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	coretrust "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The setup service's ports: what its use cases ask of the database, the
// computer and the engine's files, each filled by an adapter under
// internal/setup/out, internal/platform or internal/app.

// Querier is the admin connection or transaction a plan or an apply runs on.
// It is an alias of the interface itself, so an adapter that cannot import
// this package still implements SetuprunBackend.
type Querier = interface {
	Exec(ctx context.Context, sql string, args ...any) (Result, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// Conn is a connection a setup's adapter opened to the person's database:
// the query port the backend's calls run on, its transactions and its
// close. The setup runs no SQL on it itself.
type Conn interface {
	Port() Querier
	Begin(ctx context.Context) (Tx, error)
	Close(ctx context.Context) error
}

// Tx is a transaction on a Conn, or a savepoint in one (Begin). Rolling
// back a transaction that already ended is not an error.
type Tx interface {
	Port() Querier
	Begin(ctx context.Context) (Tx, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// SetuprunBackend is what a setup reads and writes in the database: the guard's SQL
// functions and the sample schema. An outbound adapter implements it; the
// program that runs a setup (internal/app, or pkg/setup for a program that
// calls it directly) builds one and passes it to NewSetuprun and the functions here.
type SetuprunBackend interface {
	LatestVersion() int
	Migrations() []guardmodel.Migration
	StatusAt(installed int, migs []guardmodel.Migration) guardmodel.Status

	InstalledPrefix(ctx context.Context, q Querier) (string, error)
	InstalledVersion(ctx context.Context, q Querier) (int, error)
	CheckUsable(ctx context.Context, q Querier) error
	// UnusableInstall reports whether err is CheckUsable's refusal of an
	// older install.
	UnusableInstall(err error) bool
	// ReadOldInstall reads whether the guard is below the update floor,
	// which an install replaces: ok false for no guard and for one at or
	// above the floor. It reads schema_version only.
	ReadOldInstall(ctx context.Context, q Querier) (old guardmodel.OldInstall, ok bool, err error)
	RemoveOldInstallDoc() string

	SetupsFor(ctx context.Context, q Querier, id uuid.UUID, role string) ([]setupcode.RecordedSetup, error)
	RecordSetupStatement(n guardmodel.Names, s guardmodel.Setup) (guardmodel.Statement, error)
	// SetupRefusal is the refusal code record_setup raised in err.
	SetupRefusal(err error) (string, bool)

	AgentRoleExists(ctx context.Context, q Querier, n guardmodel.Names, agent string) (bool, error)
	AgentRoles(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error)
	RoleStatementTimeout(ctx context.Context, q Querier, role string) (guardmodel.RoleTimeouts, error)
	GrantedTables(ctx context.Context, q Querier, role string) ([]string, error)
	AllTablesIn(ctx context.Context, q Querier, schema string) (guardmodel.SchemaTables, error)
	AgentBlindTables(ctx context.Context, q Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]guardmodel.BlindTable, error)
	RLSBlindTables(ctx context.Context, q Querier, role string, tables []string) ([]string, error)
	// MissingTables is the tables of a plan's refusal for tables that do not exist.
	MissingTables(err error) ([]string, bool)
	// GuardDetail is the Detail and Hint of the database error in err;
	// false when err carries no database error.
	GuardDetail(err error) (detail, hint string, ok bool)
	// UndefinedTable reports whether err is the database's undefined_table:
	// a guard older than the table, or none.
	UndefinedTable(err error) bool

	PlanInit(ctx context.Context, q Querier, opts guardmodel.InitOptions) (guardmodel.Script, error)
	PlanUninstall(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error)
	UncoveredTables(ctx context.Context, q Querier) ([]guardmodel.Uncovered, error)

	Engines(ctx context.Context, q Querier, admin bool) ([]guardmodel.RecordedEngine, error)
	RecordEngineStatement(publicKey []byte, guardVersion int) guardmodel.Statement

	// HasPasskeyFor reports whether an active passkey of this database
	// belongs to origin.
	HasPasskeyFor(ctx context.Context, q Querier, origin string) (bool, error)
	// CurrentDatabase is current_database() on q.
	CurrentDatabase(ctx context.Context, q Querier) (string, error)
	// MetaOwner is the role that owns basalt_meta, "" when it does not exist.
	MetaOwner(ctx context.Context, q Querier) (string, error)
	// Run executes one statement on q.
	Run(ctx context.Context, q Querier, sql string) error
	// ApplyScript runs the script's statements in tx, the install's
	// transaction, in order.
	ApplyScript(ctx context.Context, tx Querier, s guardmodel.Script) error

	DemoSchema() string
	DemoPlanDrop(ctx context.Context, q Querier) ([]string, error)
	// DemoApplyDrop runs drops inside tx, the removal's transaction, in a
	// savepoint of their own.
	DemoApplyDrop(ctx context.Context, tx Querier, drops []string) (kept bool, err error)
}

// ContractBackend is the database side of the setup contract: the shared
// run's backend, the setup's transaction on the admin connection, and the
// label, trust pin and passkey calls it makes.
type ContractBackend interface {
	SetuprunBackend
	// BeginTx begins a transaction on the connection q runs on; CommitTx
	// and RollbackTx end it (a rollback after a commit is a no-op).
	BeginTx(ctx context.Context, q Querier) (Querier, error)
	CommitTx(ctx context.Context, tx Querier) error
	RollbackTx(ctx context.Context, tx Querier) error
	// BeginFunc runs fn in a transaction on the connection q runs on:
	// committed when fn returns nil, rolled back when it returns an error.
	BeginFunc(ctx context.Context, q Querier, fn func(tx Querier) error) error
	// CommitAnswered reports whether a failed commit's outcome is known:
	// answered with an error, turned into a rollback, or never sent.
	CommitAnswered(err error) bool
	// ConnectedAs is the database and role q reached, as the server says
	// them: current_database() and session_user.
	ConnectedAs(ctx context.Context, q Querier) (database, user string, err error)
	// ReadLabels and ReadReadableLabels run on a connection's port;
	// ReadableTables and WriteLabels on a transaction's.
	ReadLabels(ctx context.Context, conn Querier, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error)
	ReadReadableLabels(ctx context.Context, conn Querier, n guardmodel.Names) ([]guardmodel.ColumnLabel, error)
	ReadableTables(ctx context.Context, tx Querier, n guardmodel.Names) ([]string, error)
	WriteLabels(ctx context.Context, tx Querier, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)
	RecordTrustPin(ctx context.Context, q Querier, host string, port int, sha256 string) error
	// PasskeysInstalled reports whether the database has the guard's
	// passkeys table.
	PasskeysInstalled(ctx context.Context, q Querier) (bool, error)
	ActivePasskeys(ctx context.Context, q Querier) ([]guardmodel.RegisteredPasskey, error)
	RegisterPasskey(ctx context.Context, q Querier, cred passkey.Credential, label string) error
	RevokePasskey(ctx context.Context, q Querier, credentialID []byte, force bool) (int, error)
}

// LocalBackend is what the local setup needs from its adapters, beyond what
// SetuprunBackend gives the shared run: the connections and their
// trust, the credential files, and the guard's reads and writes of one
// install. The engine wires it (internal/app). Every call that reads or
// writes the database runs on the query port it is given (Conn.Port,
// Tx.Port). ReadCredential is not a plain read: it refuses a connection
// string that makes the driver read a file (passfile, sslrootcert).
type LocalBackend interface {
	SetuprunBackend
	// The engine's own files, and the PII classifier.
	EngineFiles
	Classifier
	// OSUsers looks the computer's OS users up (setup/out/osusers).
	OSUsers() Users
	// FetchChain reads the chain host:port presents with the TLS handshake
	// alone.
	FetchChain(ctx context.Context, host string, port int) ([]*x509.Certificate, error)
	// PinRoots are the system's and the public roots the pin check reads
	// (certroots.Store outside tests).
	PinRoots() coretrust.Roots
	// Connections and their trust.
	Connect(ctx context.Context, dsn string) (Conn, error)
	// ConnectPinned opens dsn trusting only p's certificate for its host.
	ConnectPinned(ctx context.Context, dsn string, p *trustprofile.Profile) (Conn, error)
	Trust() *trustprofile.Set
	// ParseTarget is what dsn names, as the driver parses it.
	ParseTarget(dsn string) (Target, error)
	// ExplainTrust is what verifies the certificate of dsn's first host with
	// set's profiles.
	ExplainTrust(dsn string, set *trustprofile.Set) (trustprofile.Applied, error)
	// ConnHost is the host and port conn reached.
	ConnHost(conn Conn) (host string, port int)
	// ConnCertificate is conn's certificate for the confirm step: kind is
	// what the dial verified it with, provider the built-in profile's name
	// with certProvider. It returns the kind shown and the issuer.
	ConnCertificate(conn Conn, kind, provider string) (shown, issuer string)
	// ReadCredential reads the agent's connection string at path and
	// refuses one that makes the driver read a file
	// (ErrForeignCredential), so a root engine never connects
	// with what another user wrote.
	ReadCredential(path string) (string, error)
	ConnectionKeys() []string
	ConnectionKey(key string) bool
	CertificateNotVerified(err error) bool
	// PinFile and PinFileNew write the engine's trust profile for host.
	PinFile(configPath, host string, cert *x509.Certificate, caOnly bool) (*trustprofile.Profile, []string, error)
	PinFileNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error)

	// The database's errors.
	// DatabaseError is the message and detail of the database error in
	// err; false when err carries none.
	DatabaseError(err error) (message, detail string, ok bool)
	// CommitAnswered reports whether a failed commit's outcome is known:
	// answered with an error, turned into a rollback, or never sent.
	CommitAnswered(err error) bool

	// The session and the catalog.
	CurrentUser(ctx context.Context, q Querier) (string, error)
	SessionUser(ctx context.Context, q Querier) (string, error)
	CurrentUserAndDatabase(ctx context.Context, q Querier) (user, database string, err error)
	// IsMember reports whether role is a member of group.
	IsMember(ctx context.Context, q Querier, role, group string) (bool, error)
	// ListTables reads at most limit tables of schemas, in schema and table
	// order.
	ListTables(ctx context.Context, q Querier, schemas []string, limit int) ([]CatalogTable, error)
	// ListColumns reads at most limit ordinary columns of tables, in the
	// tables' order and then the columns'.
	ListColumns(ctx context.Context, q Querier, tables []string, limit int) ([]piistore.Column, error)

	// The guard's install.
	AgentStatus(ctx context.Context, q Querier, migs []guardmodel.Migration) (guardmodel.Status, error)
	RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (guardmodel.Script, error)
	NewPassword() string
	AgentConnString(adminURL, role, password string) (string, error)

	// Trust pins recorded in the database.
	RecordTrustPin(ctx context.Context, q Querier, host string, port int, sha256 string) error
	RecordedTrustPin(ctx context.Context, q Querier, host string, port int) (string, bool, error)
	// RecordedTrustPinTx runs on a transaction's port.
	RecordedTrustPinTx(ctx context.Context, tx Querier, n guardmodel.Names, host string, port int) (string, bool, error)

	// Column labels. ReadLabels runs on a connection's port; the others on
	// a transaction's.
	PIIUnclassified(ctx context.Context, q Querier) ([]guardmodel.UnclassifiedColumn, error)
	ReadLabels(ctx context.Context, conn Querier, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error)
	WriteLabels(ctx context.Context, tx Querier, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)
	AgentUnlabeled(ctx context.Context, tx Querier, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error)
	WriteAgentLabels(ctx context.Context, tx Querier, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)

	// The classifier's reads, on a connection's port.
	// PIIColumns fills the listed columns (by namespace, resource, name and
	// data type) with their Kind, Key and Generated from the store's
	// catalog. It always returns len(listed) columns with a Kind; a failed
	// catalog read leaves Key and Generated unset and a domain's base type
	// unread (so a domain over text gets its own type's kind and goes
	// unsampled), and is the error.
	PIIColumns(ctx context.Context, conn Querier, listed []piistore.Column) ([]piistore.Column, error)
	// PIISampler reads a column's sample on conn: each read in a read-only
	// transaction under timeout, each value cut to maxChars characters.
	PIISampler(conn Querier, timeout time.Duration, maxChars int) func(ctx context.Context, col piistore.Column) (piistore.Sample, error)

	// Passkeys.
	ActivePasskeys(ctx context.Context, q Querier) ([]guardmodel.RegisteredPasskey, error)
	RegisterPasskey(ctx context.Context, q Querier, cred passkey.Credential, label string) error
	RevokePasskey(ctx context.Context, q Querier, credentialID []byte, force bool) (int, error)
	// ListPasskeys lists the active passkeys the connection's role may read.
	ListPasskeys(ctx context.Context, q Querier) ([]ActivePasskey, error)

	// The sample schema.
	DemoTables() []string
	// SeedDemo runs on a transaction's port.
	SeedDemo(ctx context.Context, tx Querier) (guardmodel.DemoPlan, error)
	DemoCounts(ctx context.Context, q Querier) (leads, notes int, err error)
}

// EngineFiles are the engine's own files a local setup reads and writes,
// by path, as the engine's own user: engine.json and the agents'
// credential files. An outbound adapter implements it (setup/out/enginefiles).
// Every call is the config or os call it is named after, unchanged; a
// caller refuses an engine that runs as root before it reads the config.
type EngineFiles interface {
	// Lstat is os.Lstat's error for path: nil when it exists.
	Lstat(path string) error
	LoadConfig(path string) (config.Config, error)
	// ReadCredentialFile reads an agent's connection string
	// (config.ReadCredential), with no check of what the driver would read.
	ReadCredentialFile(path string) (string, error)
	ReadFile(path string) ([]byte, error)
	// WriteFile writes data at path as config.WriteFile does.
	WriteFile(path string, data []byte) error
	Remove(path string) error
	UpsertAgentVault(path string, s config.Settings, a config.Agent) (config.VaultWritten, error)
	RemoveAgents(path string, names []string) (removedFile bool, err error)
}

// Classifier suggests a class for each column from its sample, in the
// columns' order, keeping no value: the PII classifier's run with its
// default options. internal/app fills it.
type Classifier interface {
	SuggestColumns(ctx context.Context, cols []piistore.Column, sample SampleFunc) ([]ColumnSuggestion, error)
}

// Users looks OS users up.
type Users interface {
	Lookup(name string) (*user.User, error)
	LookupID(uid string) (*user.User, error)
	GroupIDs(u *user.User) ([]string, error)
	// Self is this engine's own uid.
	Self() int
}

// DBErrors reads what SQLStateOf cannot: the message of a database
// error, whose type the setup domain cannot name.
type DBErrors interface {
	// ServerMessage is the message of the error the database server sent,
	// when err is (or wraps) one; false otherwise.
	ServerMessage(err error) (string, bool)
}

// Machine is what the printed basalt mcp command reads of the computer.
type Machine interface {
	// Executable is the absolute, link-resolved path of the running binary.
	Executable() (string, error)
}

// RemoteHost is what basalt init --remote reaches outside the CLI: the guard's
// versions, records and agent connection string, the engine's keys, the
// trust profiles next to the config, the database's server errors, and the
// credential files and config directory, which root opens without following
// a link anyone but root or the file's owner controls.
type RemoteHost interface {
	DBErrors
	// TrustProfileFor is the profile in the trust.d next to the config at
	// configPath that names host, or nil.
	TrustProfileFor(configPath, host string) *trustprofile.Profile
	// PinRoots are the system's and the public roots the check of an
	// unknown authority reads (certroots.Store outside tests).
	PinRoots() coretrust.Roots
	// ConnTarget is the host and port a connection string names, and whether
	// its TLS check uses the system's roots (TLS on, no root certificate
	// given); the error is the driver's own.
	ConnTarget(dsn string) (ConnTarget, error)
	// GuardAgentConnString is adminURL with the agent's role and password.
	GuardAgentConnString(adminURL, role, password string) (string, error)
	// GuardAgentVersion is the guard version q's database has, 0 when none;
	// q is the agent's login, whose Pgx method gives the driver's connection.
	GuardAgentVersion(ctx context.Context, q Querier) (int, error)
	// GuardLatestVersion is the guard version this binary installs.
	GuardLatestVersion() int
	// GuardSetupRecorded reports whether the setup with id is recorded.
	GuardSetupRecorded(ctx context.Context, q Querier, id uuid.UUID) (bool, error)
	// UpsertAgentVault writes the agent and the vault into the config at
	// path, by path (config.UpsertAgentVault): init --remote not as root.
	UpsertAgentVault(path string, s config.Settings, a config.Agent) (config.VaultWritten, error)
	// LoadOrCreateEngineKeys reads the engine's keys at path, making them
	// when there are none.
	LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error)
	// PathCredFiles reaches the credential files by path: init --remote not
	// as root, in the user's own directories.
	PathCredFiles() CredFiles
	// OpenRootCredFiles opens dir, the agents directory, as root, making it
	// (and the config directory) when missing. Every directory on the way
	// must be owned by root or trusted, and no link is followed. Reads
	// through it check the string another user wrote there.
	OpenRootCredFiles(dir string, trusted int) (CredFiles, error)
	// RootTrustedOwner is the owner root trusts on the way to the config
	// directory dir: dir's, or, when it does not exist yet, that of the
	// nearest directory above it that does.
	RootTrustedOwner(dir string) (int, error)
	// OpenRootConfigDir opens dir, the config directory, as root, making it
	// when missing; engine.json is then locked, read and written relative
	// to it, checked as the hardened read checks it.
	OpenRootConfigDir(dir string, trusted int) (RootConfigDir, error)
	// RootEngineKey is the engine's public key for a root init --remote:
	// the key file in stateDir read or, when there is none, created relative
	// to the state directory opened without following a link anyone but
	// root controls, owned by the config directory's owner.
	RootEngineKey(stateDir, goos string, cfg RootConfigDir, now func() time.Time) ([]byte, error)
}

// RemoteEnv is what basalt init --remote reaches through the CLI that runs
// it (setupcli fills it from its IO): the process and its configs, the
// agent's login, the clock, the network probes and stderr.
type RemoteEnv interface {
	// Euid is the process's effective uid.
	Euid() int
	// ConfigFlag is the config path the command line gave, "" for none.
	ConfigFlag() string
	// SystemConfig is the system-wide config path.
	SystemConfig() string
	// FindConfig is the config that serves agent (the CLI's search).
	FindConfig(agent string) (string, error)
	// UserConfigDir is the user's config directory.
	UserConfigDir() (string, error)
	// RefuseSecondConfig refuses a second config next to the one found.
	RefuseSecondConfig() error
	// LoadEngineConfig is the hardened read of the config at path: as
	// root, a plain file owned by root or its directory's owner, not
	// writable by group or others and reached without links.
	LoadEngineConfig(path string) (config.Config, error)
	// InvokingUID is the uid of the person who ran the command (sudo's).
	InvokingUID() (uint32, error)
	// InvokingUser is the OS user who ran the command.
	InvokingUser() (string, error)
	// AgentLogin logs in with the agent's credential dsn; LoginRefused
	// reports whether its error is the database refusing the login.
	AgentLogin(ctx context.Context, dsn string) (RemoteAgentConn, error)
	LoginRefused(err error) bool
	Now() time.Time
	Rand() io.Reader
	Goos() string
	// Probe tries a login to dsn for its TLS check (HardenedCredential).
	Probe(ctx context.Context, dsn string) error
	// FetchChain reads the chain host:port presents with the TLS handshake
	// alone; nil when the CLI reads none.
	FetchChain() func(ctx context.Context, host string, port int) ([]*x509.Certificate, error)
	// TerminalText is s safe to print on a terminal.
	TerminalText(s string) string
	// MCPBinary is the basalt binary the agent's MCP command runs.
	MCPBinary() string
	// MkdirStateDir makes the engine's state directory, with its mode.
	MkdirStateDir(path string) error
	// Stderr takes the run's notes.
	Stderr() io.Writer
}

// RemoteAgentConn is the agent's own connection init --remote reads with.
type RemoteAgentConn interface {
	Querier
	Close(ctx context.Context) error
}

// CredFiles reads and writes the agent's credential file, its .pending and
// its .lock for init --remote, each named by its full path. It is an alias
// of the interface itself, so the adapter (setup/out/credfiles) returns it
// with no import of this package.
type CredFiles = interface {
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

// RootConfigDir is the config directory init --remote opened as root. It is
// an alias of the interface itself, so the adapter (setup/out/credfiles)
// returns it with no import of this package.
type RootConfigDir = interface {
	// Upsert is config.UpsertAgentVault on the config file name, relative to
	// the opened directory.
	Upsert(name string, s config.Settings, a config.Agent) (config.VaultWritten, error)
	// Close closes the directory.
	Close()
}

// ServiceHost is what basalt service install reaches outside the setup
// service. Every method is the adapter call it is named after.
type ServiceHost interface {
	// OSDefaultUser is the engine's default OS user on goos.
	OSDefaultUser(goos string) string
	// OSLookupUID is the uid of the OS user name, or -1 when there is no
	// such user.
	OSLookupUID(name string) int
	// LoadConfigNoFollow reads the engine config at path, refusing a link
	// at it (config.LoadNoFollow).
	LoadConfigNoFollow(path string) (config.Config, error)
	// LoadEngineConfigAsSelf is the hardened read of the engine config as
	// this process's user (cli.LoadEngineConfigAs).
	LoadEngineConfigAsSelf(path string) (config.Config, error)
	// LockConfigAs takes the config lock, its file given to uid
	// (config.LockConfigAs).
	LockConfigAs(path string, uid int) (config.HeldLock, error)
	// ReadKeptCredential reads a credential file the engine's user keeps
	// (credfiles.ReadKeptCredential).
	ReadKeptCredential(path, engineUser string) (string, error)
	// UpsertedVault is the config at configPath, opened as root reads the
	// engine user's file, with s and a upserted (config.UpsertedVault).
	UpsertedVault(configPath, engineUser string, s config.Settings, a config.Agent) ([]byte, config.VaultWritten, error)
	// CredentialMissing reports whether no file is at path, not following
	// a link.
	CredentialMissing(path string) bool
	// CheckAgentOSUser refuses an agent OS user that is the engine's own or
	// shares a group with it.
	CheckAgentOSUser(osUser, engineUser string) error
	// WithPluginUnits is spec with cfg's plugin units, a line on warn for
	// each entry left as it is.
	WithPluginUnits(spec servicespec.Spec, cfg config.Config, warn io.Writer) servicespec.Spec
	// InstallUnits plans and applies the service install of spec (printing
	// the steps only for dryRun), the steps' output on out and errw.
	InstallUnits(ctx context.Context, spec servicespec.Spec, dryRun bool, out, errw io.Writer) error
}
