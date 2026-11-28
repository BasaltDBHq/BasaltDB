// The local setup page's jobs (CONTRACT.md, The local setup page): the
// INSTALL job of an engine with no config, run with the admin connection
// string the person types on the page, and the UPDATE, REMOVE and fix jobs
// of an engine with one. The string is used for one request and never
// written, logged or returned; every answer and refusal is built from fixed
// words and values read from the catalog.

package setup

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	coretrust "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The jobs of the setup page (CONTRACT.md, The local setup page, Jobs):
// INSTALL on an engine with no config, UPDATE and REMOVE on an engine that
// has one (agentjobs.go).
const (
	JobInstall = "INSTALL"
	JobUpdate  = "UPDATE"
	JobRemove  = "REMOVE"
	// JobChange is a link only: basalt init's link for an engine that is
	// already set up. The page offers UPDATE and REMOVE and sends the one
	// the person picks; no request carries CHANGE.
	JobChange = "CHANGE"
)

// Fixed values the engine chooses itself for a first install.
const (
	statementTimeout = 30 * time.Second
	// callLimit bounds one check or run; the transaction rolls back.
	callLimit = 60 * time.Second
)

// Request is the body of the check and run routes.
type Request struct {
	Job         string `json:"job"`
	Agent       string `json:"agent"`
	OSUser      string `json:"osUser"`
	Demo        bool   `json:"demo"`
	DatabaseURL string `json:"databaseUrl"`
	// Schemas and Tables are for an install of a real database (Demo
	// false). Tables nil on a check asks for the listing.
	Schemas []string    `json:"schemas,omitempty"`
	Tables  []TablePick `json:"tables,omitempty"`
	// ColumnClasses and RestPublic are the labels the person set
	// (CONTRACT.md, The install of a real database).
	ColumnClasses []ColumnClass `json:"columnClasses,omitempty"`
	RestPublic    bool          `json:"restPublic,omitempty"`
	// TrustRoot is the SHA-256 of the certificate authority the person
	// trusted for the database's host.
	TrustRoot string `json:"trustRoot,omitempty"`
	// ConfirmName is the database name the person typed to confirm an
	// INSTALL that replaces a guard below the update floor; only its run
	// carries it.
	ConfirmName string `json:"confirmName,omitempty"`
	// Pinned is the engine's pin a TRUST check showed for a ledger that
	// names another, which its run records: a pin that changed since is
	// TRUST_ROOT_MISMATCH.
	Pinned string `json:"pinned,omitempty"`
	// CredentialID is the passkey a PASSKEY_REMOVE removes, base64url.
	CredentialID string     `json:"credentialId,omitempty"`
	Answers      []Answer   `json:"answers,omitempty"`
	Challenge    *Challenge `json:"challenge,omitempty"`
	Passkey      *Passkey   `json:"passkey,omitempty"`
	// Since is basalt init's probe only (a check with no job, with Agent):
	// when it opened the CHANGE link. It is answered GUARD_UPDATED once an
	// UPDATE for the agent finished after it.
	Since *time.Time `json:"since,omitempty"`
}

// Answer answers one row-level security question.
type Answer struct {
	Table  string `json:"table"`
	Choice string `json:"choice"`
}

// Question is a row-level security question for one table.
type Question struct {
	Kind    string   `json:"kind"`
	Table   string   `json:"table"`
	Text    string   `json:"text"`
	Choices []string `json:"choices"`
}

// Passkey is the browser's registration response with an optional label.
type Passkey struct {
	passkey.RegistrationResponse
	Label string `json:"label,omitempty"`
}

// CheckAnswer is the check route's answer.
type CheckAnswer struct {
	Database      string     `json:"database"`
	Lines         []string   `json:"lines"`
	SQL           string     `json:"sql"`
	Questions     []Question `json:"questions"`
	Notes         []string   `json:"notes"`
	PasskeyNeeded bool       `json:"passkeyNeeded"`
	// Challenge is the passkey challenge of an INSTALL; an UPDATE and a
	// REMOVE register no passkey and have none.
	Challenge *Challenge `json:"challenge,omitempty"`
	// Tables, Excluded and TablesMore are the listing call's answer for
	// an install of a real database.
	Tables     []ListedTable   `json:"tables,omitempty"`
	Excluded   []ExcludedTable `json:"excluded,omitempty"`
	TablesMore bool            `json:"tablesMore,omitempty"`
	// Columns are the columns of the picked tables with their class now
	// and a suggestion; ColumnsMore says there are more than listed.
	Columns     []ColumnInfo `json:"columns,omitempty"`
	ColumnsMore bool         `json:"columnsMore,omitempty"`
	// Pinned and Recorded are a TRUST check's for a ledger that names
	// another pin: the engine's SHA-256 and the ledger's.
	Pinned   string `json:"pinned,omitempty"`
	Recorded string `json:"recorded,omitempty"`
	// Host, Port, SessionUser and Certificate are the confirm step's, on
	// an install's check: the admin connection's host and port, the role
	// it logged in as and what verified its certificate.
	Host        string              `json:"host,omitempty"`
	Port        int                 `json:"port,omitempty"`
	SessionUser string              `json:"sessionUser,omitempty"`
	Certificate *ConfirmCertificate `json:"certificate,omitempty"`
	// Replace is an INSTALL's on a database whose guard is below the
	// update floor: the run removes it and installs, with the typed
	// database name (CONTRACT.md, The local setup page, An older install).
	Replace *Replace `json:"replace,omitempty"`
}

// RegisteredPasskey is one passkey the run registered.
type RegisteredPasskey struct {
	CredentialID passkey.Bytes `json:"credentialId"`
	Label        string        `json:"label"`
	CheckCode    string        `json:"checkCode"`
}

// RunAnswer is the run route's answer.
type RunAnswer struct {
	Agent string `json:"agent"`
	// Lines are what the install did, in fixed words (the sample data's
	// counts).
	Lines      []string            `json:"lines"`
	Warnings   []string            `json:"warnings"`
	Passkeys   []RegisteredPasskey `json:"passkeys"`
	MCPCommand string              `json:"mcpCommand"`
	// EngineRemoved: a REMOVE removed this engine's last agent and deleted
	// engine.json.
	EngineRemoved bool `json:"engineRemoved"`
	// EngineRemoving: the engine then created the removal job's marker, so
	// the job stops it and removes it from this computer; the page ticks
	// that step once the engine stops answering.
	EngineRemoving bool `json:"engineRemoving"`
	// Remaining is a PASSKEY_REMOVE's: the active passkeys of this page's
	// origin left.
	Remaining *int `json:"remaining,omitempty"`
}

// LocalOptions are what the engine gives the setup.
type LocalOptions struct {
	// LocalBackend is the database, the connection and the trust files the
	// setup works on. Required.
	Backend LocalBackend
	// ConfigPath is the engine.json the run writes; its folder is the
	// engine's own.
	ConfigPath string
	// Origin is the page origin (http://localhost:8787): the passkey's
	// origin, with RP ID localhost.
	Origin string
	// Now is the clock (time.Now outside tests).
	Now func() time.Time
	// Dial opens the admin connection (LocalBackend.Connect outside tests).
	Dial func(ctx context.Context, dsn string) (Conn, error)
	// Users looks OS users up (the OS outside tests).
	Users Users
	// Prefix is the roles' prefix: guardmodel.DefaultPrefix outside tests,
	// whose databases share one server's roles.
	Prefix string
	// Configured is the setup of an engine that runs with its config: it
	// runs UPDATE and REMOVE for the agents in it and never an INSTALL
	// (the engine loads engine.json only at its start).
	Configured bool
	// DialPinned opens the admin connection trusting only the pin's
	// certificate for its host (LocalBackend.ConnectPinned outside tests).
	DialPinned func(ctx context.Context, dsn string, pin *trustprofile.Profile) (Conn, error)
	// Profiles are the trust profiles in force (LocalBackend.Trust outside tests).
	Profiles func() *trustprofile.Set
	// Probe reads the chain a host presents (LocalBackend.FetchChain outside tests).
	Probe func(ctx context.Context, host string, port int) ([]*x509.Certificate, error)
	// PinRoots are the roots the pin check reads (LocalBackend.PinRoots
	// outside tests).
	PinRoots coretrust.Roots
	// SampleColumn reads a column's sample for the check's suggestions
	// (the classifier's sampler outside tests).
	SampleColumn func(ctx context.Context, conn Conn, col piistore.Column) (piistore.Sample, error)
	// Euid is this process's effective user id (os.Geteuid outside tests).
	Euid func() int
	// CredentialChanged tells the running engine an agent's new password,
	// after a REPAIR wrote it (a no-op when nothing listens).
	CredentialChanged func(agent, password string)
	// Reload has the running engine serve its config again, after a fix
	// rewrote an agent's connection string (a no-op when nothing listens).
	Reload func()
	// Reinstalled tells the running engine that an INSTALL on it, removed,
	// wrote engine.json again, so it serves that config (a no-op when
	// nothing listens).
	Reinstalled func()
	// StateDir holds the engine's key file, channel.json, whose signing key
	// an install records: the state directory the engine will run with
	// (config.DefaultStateDir, as the engine.json the install writes names
	// none).
	StateDir string
}

// LocalService runs the setup jobs. One runs at a time.
type LocalService struct {
	opts LocalOptions
	be   LocalBackend
	key  []byte
	rp   passkey.Relying
	busy sync.Mutex
	// mark is the person's "No, this isn't mine" (Not your database).
	mark resetMark
	// updated is when each agent's last UPDATE finished, for basalt init's
	// probe.
	updated updateMarks
}

// New returns the setup of an engine with no config.
func NewLocal(o LocalOptions) (*LocalService, error) {
	if o.ConfigPath == "" || o.Origin == "" {
		return nil, errors.New("setup: config path and origin required")
	}
	if o.Backend == nil {
		return nil, errors.New("setup: backend required")
	}
	rp, err := LocalRelying(o.Origin)
	if err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Dial == nil {
		o.Dial = o.Backend.Connect
	}
	if o.Users == nil {
		o.Users = o.Backend.OSUsers()
	}
	if o.Prefix == "" {
		o.Prefix = guardmodel.DefaultPrefix
	}
	if o.DialPinned == nil {
		o.DialPinned = o.Backend.ConnectPinned
	}
	if o.Profiles == nil {
		o.Profiles = o.Backend.Trust
	}
	if o.Probe == nil {
		o.Probe = o.Backend.FetchChain
	}
	if o.PinRoots == nil {
		o.PinRoots = o.Backend.PinRoots()
	}
	if o.Euid == nil {
		o.Euid = os.Geteuid
	}
	if o.CredentialChanged == nil {
		o.CredentialChanged = func(string, string) {}
	}
	if o.Reload == nil {
		o.Reload = func() {}
	}
	if o.Reinstalled == nil {
		o.Reinstalled = func() {}
	}
	if o.StateDir == "" {
		o.StateDir = config.DefaultStateDir(runtime.GOOS)
	}
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	return &LocalService{opts: o, be: o.Backend, key: key, rp: rp}, nil
}

// job is a validated request's job: the agent's role and its spec.
type job struct {
	req  Request
	role string
	uid  uint32
	// host is the admin string's host and port, lowercase: the challenge
	// is bound to it.
	host string
	// schemas and picks are for a real install; picks nil is the listing.
	schemas []string
	picks   []TablePick
}

// validate checks everything that needs no database, in order.
func (s *LocalService) validate(req Request) (job, error) {
	if err := s.be.Lstat(s.opts.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		return job{}, refuse(CodeJobUnavailable, "This engine is already set up. An install never changes an engine that has a config; ask the agent for the setup link of the change you want.")
	}
	if isAgentJob(req.Job) {
		return job{}, refuse(CodeJobUnavailable, "This engine has no config yet, so it has no agent to update, remove or fix. Ask the agent for a new link.")
	}
	if req.Job != JobInstall {
		return job{}, refuse(CodeInvalidArgument, "This setup link names a job this engine does not run.")
	}
	role, err := (guardmodel.Names{Prefix: s.opts.Prefix}).Agent(req.Agent)
	if err != nil {
		return job{}, refuse(CodeInvalidArgument, "This setup link names an agent whose name cannot be used. Ask the agent for a new link.")
	}
	uid, err := checkOSUser(s.opts.Users, req.OSUser)
	if err != nil {
		return job{}, err
	}
	j := job{req: req, role: role, uid: uid}
	if len(req.ConfirmName) > maxDatabaseName {
		return job{}, refuse(CodeAnswersInvalid, ReplaceWrongName)
	}
	if req.CredentialID != "" {
		return job{}, refuse(CodeAnswersInvalid, "An install removes no passkey.")
	}
	if req.Demo && req.hasRealFields() {
		return job{}, refuse(CodeAnswersInvalid, "The sample database takes no schema, table or label to set.")
	}
	if !req.Demo {
		if j.schemas, err = checkSchemas(req.Schemas); err != nil {
			return job{}, err
		}
		if req.Tables != nil {
			if len(req.Tables) == 0 {
				return job{}, refuse(CodeNoTables, "There is no table to give the agent. Pick at least one table; nothing changed.")
			}
			if j.picks, err = checkPicks(req.Tables, j.schemas); err != nil {
				return job{}, err
			}
		}
		if err = checkClasses(req, j.picks); err != nil {
			return job{}, err
		}
	}
	if j.host, err = s.checkAdminURL(req.DatabaseURL, role); err != nil {
		return job{}, err
	}
	return j, nil
}

// adminURLParams is the refusal of a parameter outside the allowlist. It
// never names the parameter or its value.
func (s *LocalService) adminURLParams() string {
	return "The admin connection string can take only these parameters: " +
		strings.Join(s.be.ConnectionKeys(), ", ") + ". Remove the others (a file such as passfile, sslkey, sslcert or sslrootcert is never read from it) and paste it again."
}

// checkAdminURL accepts a postgres:// or postgresql:// URL with a user and
// a password that an agent's connection string can be built from. The
// refusal never names any part of it.
func (s *LocalService) checkAdminURL(raw, role string) (string, error) {
	bad := refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
	if !strings.HasPrefix(raw, "postgres://") && !strings.HasPrefix(raw, "postgresql://") {
		return "", bad
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.User.Username() == "" || u.Host == "" {
		return "", bad
	}
	if pw, ok := u.User.Password(); !ok || pw == "" {
		return "", bad
	}
	// The host, port and database come from the URL itself, and the
	// parameters only from pgdial's allowlist: one that names another
	// host or database would make the connection and the target checks
	// disagree, and one that names a file (passfile, sslkey, sslcert,
	// sslrootcert, service) would have the engine read it as its own
	// user. The pinned login sets its roots itself, never from the string.
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", bad
	}
	for key := range query {
		if !s.be.ConnectionKey(key) {
			return "", refuse(CodeConnectionStringRefused, s.adminURLParams())
		}
	}
	if _, err := s.be.AgentConnString(raw, role, ""); err != nil {
		return "", bad
	}
	return strings.ToLower(u.Host), nil
}

// sameTarget: two connection strings, as the driver parses them (query
// parameters included), name the same host and port (the host compared in
// lowercase) and the same database.
func (s *LocalService) sameTarget(a, b string) bool {
	ca, err := s.be.ParseTarget(a)
	if err != nil {
		return false
	}
	cb, err := s.be.ParseTarget(b)
	if err != nil {
		return false
	}
	return ca.Host != "" && strings.EqualFold(ca.Host, cb.Host) && ca.Port == cb.Port &&
		ca.Database != "" && ca.Database == cb.Database
}

// connect opens the admin connection; a failure is a fixed refusal.
func (s *LocalService) connect(ctx context.Context, admin string) (Conn, error) {
	conn, err := s.opts.Dial(ctx, admin)
	if err != nil {
		return nil, s.connectError(ctx, err)
	}
	return conn, nil
}

// open opens the admin connection of j: a real install may pin the
// database's certificate (connectAdmin).
func (s *LocalService) open(ctx context.Context, req Request) (Conn, *pin, error) {
	if req.Demo {
		conn, err := s.connect(ctx, req.DatabaseURL)
		return conn, nil, err
	}
	return s.connectAdmin(ctx, req)
}

// planned is what plan found and built.
type planned struct {
	seeded guardmodel.DemoPlan
	script guardmodel.Script
	keep   bool
	// rekey: the role exists, an agent of this guard's group, with no
	// password this engine holds (an earlier setup this engine forgot):
	// the install sets a new one, as the Update check's REPAIR does.
	rekey     bool
	write     []string
	read      []string
	questions []Question
	// answers are the answers the script was planned with.
	answers []Answer
	list    listing
	// labeled is how many columns the run's labels write.
	labeled int
	// replaced is the guard below the update floor the plan removed first
	// (replaceOld), with the statements it ran; nil when there was none.
	replaced *guardmodel.OldInstall
	removed  []string
}

// plan reads the database for j in tx: refusals, then the removal of a
// guard below the update floor (replaceOld), then the sample data or
// the tables, and the install script. run is the run's plan, which checks
// the typed database name. keep is a role that exists and is
// this engine's own (finishing an install whose engine.json was never
// written): its password stays. answers nil (a check) shows the SQL as if
// every row-level security question were answered ALL_ROWS, the page's
// answer; a run passes the person's. The caller rolls tx back (check) or
// commits (run).
func (s *LocalService) plan(ctx context.Context, tx Tx, j job, password, database string, answers []Answer, run bool) (planned, error) {
	prefix := s.opts.Prefix
	names := guardmodel.Names{Prefix: prefix}
	installed, err := s.be.InstalledPrefix(ctx, tx.Port())
	if err != nil {
		return planned{}, s.setupFailed("read the guard prefix", err)
	}
	if installed != "" && installed != prefix {
		return planned{}, refuse(CodePrefixMismatch, "This database's Basalt uses the prefix "+installed+", not "+prefix+".")
	}
	var p planned
	if p.replaced, p.removed, err = s.replaceOld(ctx, tx, j, database, installed == prefix, run); err != nil {
		return planned{}, err
	}
	if p.replaced != nil {
		installed = "" // removed: the install below starts from no guard
	}
	if err := s.usable(ctx, tx); err != nil {
		return planned{}, err
	}
	exists, err := s.be.AgentRoleExists(ctx, tx.Port(), names, j.req.Agent)
	if err != nil {
		return planned{}, s.setupFailed("read the agent role", err)
	}
	if exists {
		switch {
		case s.ownRole(ctx, j, database):
			p.keep, password = true, ""
		case installed == prefix:
			// A role of this guard's agents group whose password this
			// engine no longer holds (its setup was reset): the admin string
			// typed on the page allows a new one, as it allows REPAIR. The
			// install's adopt checks still refuse anything but a plain agent
			// role.
			member, err := s.be.IsMember(ctx, tx.Port(), j.role, names.Agents())
			if err != nil {
				return planned{}, s.setupFailed("read the agent role membership", err)
			}
			if !member {
				return planned{}, refuse(CodeRoleExists, fmt.Sprintf("The database already has the role %s. An install never takes over a role outside BasaltDB's agents.", j.role))
			}
			p.rekey = true
		default:
			return planned{}, refuse(CodeRoleExists, fmt.Sprintf("The database already has the role %s. An install never takes over an existing role.", j.role))
		}
	}
	// A role that exists may hold grants from an earlier run that never
	// finished: the run revokes those on tables not picked now (Exact), in
	// the same transaction, so the role ends with exactly this run's tables.
	spec := guardmodel.AgentSpec{
		Name: j.req.Agent, Password: password, CreateOnly: !p.keep && !p.rekey, Exact: p.keep || p.rekey,
		StatementTimeout: statementTimeout,
	}
	opts := guardmodel.InitOptions{Names: names}
	if j.req.Demo {
		if p.seeded, err = s.be.SeedDemo(ctx, tx.Port()); err != nil {
			return planned{}, s.setupFailed("seed the sample data", err)
		}
		spec.Write = s.be.DemoTables()
		if p.seeded.Ours {
			// Sample tables left by an earlier demo may have row-level
			// security on (a Remove drops the agents' policies, and a
			// provider's table editor can turn it on): the agent gets its
			// policy on them, as the page's ALL_ROWS answer gives it, with no
			// question. A basalt_demo the demo did not make is left alone.
			if opts.AgentPolicies, err = s.be.AgentBlindTables(ctx, tx.Port(), names, spec); err != nil {
				return planned{}, s.setupFailed("read the tables without row-level security", err)
			}
		}
	} else {
		if p.list, err = s.readListing(ctx, tx.Port(), j.schemas); err != nil {
			return planned{}, s.setupFailed("read the tables", err)
		}
		if j.picks == nil {
			return p, nil // the listing call
		}
		if p.write, p.read, err = p.list.access(j.picks); err != nil {
			return planned{}, err
		}
		spec.Write, spec.Read = p.write, p.read
		blind, err := s.be.AgentBlindTables(ctx, tx.Port(), names, spec)
		if err != nil {
			return planned{}, s.setupFailed("read the tables without row-level security", err)
		}
		p.questions = questions(blind, j.req.Agent)
		if answers == nil {
			answers = allRows(blind)
		}
		if opts.AgentPolicies, err = policies(blind, answers); err != nil {
			return planned{}, err
		}
		p.answers = answers
	}
	opts.Agent = spec
	if p.script, err = s.be.PlanInit(ctx, tx.Port(), opts); err != nil {
		return planned{}, s.setupFailed("plan the install", err)
	}
	p.script.Statements = append(p.script.Statements, s.recordEngine()...)
	return p, nil
}

// recordEngine is record_engine for this engine's signing key, in the
// install transaction as a setup code's install records it (CONTRACT.md,
// Engine records): the key is read from <StateDir>/channel.json, the file
// the engine loads at its start, and made there when there is none. A key
// file that is refused records nothing and the install goes on: the engine
// then runs with its key refused, and status says KEY_ERROR with its fix.
func (s *LocalService) recordEngine() []guardmodel.Statement {
	keys, err := s.be.LoadOrCreateStateKeys(s.opts.StateDir, s.opts.Now)
	if err != nil {
		return nil
	}
	return []guardmodel.Statement{s.be.RecordEngineStatement(keys.PublicKeySPKI(), s.be.LatestVersion())}
}

// ownRole: the agent's role exists and this engine holds its password. The
// credential an earlier run wrote, in this engine's own folder, logs in as
// that role on the database the admin string reached. Only then does an
// install finish with that role (its engine.json write had failed);
// anything else is another role of the same name, never taken over.
func (s *LocalService) ownRole(ctx context.Context, j job, database string) bool {
	// ReadCredential accepts only a string that makes the driver read no
	// file: the folder is the engine's own, but a credential is never
	// trusted to be well-formed.
	dsn, err := s.be.ReadCredential(s.files(j.req.Agent).credential)
	if err != nil {
		return false
	}
	// The kept credential must be for the server and database this run's
	// admin string names, before it is tried at all: a role of the same
	// name on another server is never taken over.
	if !s.sameTarget(dsn, j.req.DatabaseURL) {
		return false
	}
	conn, err := s.opts.Dial(ctx, dsn)
	if err != nil {
		return false
	}
	defer conn.Close(context.WithoutCancel(ctx))
	user, db, err := s.be.CurrentUserAndDatabase(ctx, conn.Port())
	if err != nil {
		return false
	}
	return user == j.role && db == database
}

// replaceOld removes, in tx, a guard of this engine's prefix (ours) below
// the update floor, before anything else is planned, and returns it with
// the statements it ran; nil when there is none. A run must carry the
// database's name as the person typed it (ANSWERS_INVALID otherwise,
// before anything is dropped), and carries none when nothing is replaced.
// A check removes it too, in its transaction that it rolls back.
func (s *LocalService) replaceOld(ctx context.Context, tx Tx, j job, database string, ours, run bool) (*guardmodel.OldInstall, []string, error) {
	var old *guardmodel.OldInstall
	if ours {
		var err error
		if old, err = ReadReplace(ctx, s.be, tx.Port()); err != nil {
			return nil, nil, s.setupFailed("read the installed guard", err)
		}
	}
	switch {
	case old == nil && run && j.req.ConfirmName != "":
		return nil, nil, refuse(CodeAnswersInvalid, ReplaceNotNeeded)
	case old == nil:
		return nil, nil, nil
	case run && j.req.ConfirmName != database:
		return nil, nil, refuse(CodeAnswersInvalid, ReplaceWrongName)
	}
	drops, err := RemoveOld(ctx, s.be, tx.Port(), guardmodel.Names{Prefix: s.opts.Prefix})
	if err != nil {
		return nil, nil, s.setupFailed("remove the old install", err)
	}
	return old, drops, nil
}

// replacing reports, in tx, whether the install replaces a guard below the
// update floor: the challenge is bound to it.
func (s *LocalService) replacing(ctx context.Context, tx Tx) (bool, error) {
	installed, err := s.be.InstalledPrefix(ctx, tx.Port())
	if err != nil {
		return false, s.setupFailed("read the guard prefix", err)
	}
	if installed != s.opts.Prefix {
		return false, nil
	}
	old, err := ReadReplace(ctx, s.be, tx.Port())
	if err != nil {
		return false, s.setupFailed("read the installed guard", err)
	}
	return old != nil, nil
}

// usable refuses GUARD_UNUSABLE for a basalt_meta this build cannot
// install over or update, before anything is planned or changed.
func (s *LocalService) usable(ctx context.Context, tx Tx) error {
	err := s.be.CheckUsable(ctx, tx.Port())
	switch {
	case s.be.UnusableInstall(err):
		return refuse(CodeGuardUnusable, "This database has an older BasaltDB install that this version cannot use. Remove it first, then set up again: "+s.be.RemoveOldInstallDoc()+" says how. Nothing changed.")
	case err != nil:
		return s.setupFailed("read the installed guard", err)
	}
	return nil
}

// setupFailed is SETUP_FAILED for err at step: the person's message names
// the Postgres error code and the step when the database refused it, and
// Cause carries the redacted message for the engine's log.
func (s *LocalService) setupFailed(step string, err error) *RefusalError {
	return failed(step, err, s.be.DatabaseError)
}

// failed is SETUP_FAILED for err at step, its cause read with describe
// (causeOf).
func failed(step string, err error, describe describeError) *RefusalError {
	c := causeOf(step, err, describe)
	r := refuse(CodeSetupFailed, FailedMessage(c.Step, c.SQLState))
	r.Cause = c
	return r
}

// refused is err as the refusal the page answers with (asRefusal); nil
// stays nil. Every call the page makes returns its error through it, so
// the page's AsRefusal only ever finds a refusal.
func (s *LocalService) refused(err error) error {
	if err == nil {
		return nil
	}
	return s.asRefusal(err)
}

// Check reads what an install would do. It changes nothing.
func (s *LocalService) Check(ctx context.Context, req Request) (CheckAnswer, error) {
	given := req.DatabaseURL
	req.DatabaseURL = s.verifyByDefault(given)
	a, err := s.check(ctx, req)
	return a, scrub(scrub(s.refused(err), given), req.DatabaseURL)
}

// verifyByDefault is the admin string the check and the run use: with
// sslmode=verify-full when it names no sslmode and a built-in trust profile
// covers its host (trustprofile.VerifyFullByDefault), so the admin login,
// the confirm step and the agent's connection string all verify the
// certificate; else as given.
func (s *LocalService) verifyByDefault(dsn string) string {
	return trustprofile.VerifyFullByDefault(dsn, s.opts.Profiles())
}

func (s *LocalService) check(ctx context.Context, req Request) (CheckAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, callLimit)
	defer cancel()
	if s.opts.Configured && !s.installOnRemoved(req) {
		return s.checkAgentJob(ctx, req)
	}
	j, err := s.validate(req)
	if err != nil {
		return CheckAnswer{}, err
	}
	if req.ConfirmName != "" {
		return CheckAnswer{}, refuse(CodeAnswersInvalid, "Only a run is confirmed with the database name.")
	}
	conn, pinned, err := s.open(ctx, req)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, s.setupFailed("begin", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	database, err := s.currentDatabase(ctx, tx)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	facts, err := s.readConfirm(ctx, tx, conn, req.DatabaseURL, pinned)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	// A throwaway password: the shown SQL redacts it, and nothing commits.
	p, err := s.plan(ctx, tx, j, s.be.NewPassword(), database, req.Answers, false)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	var replace *Replace
	if p.replaced != nil {
		replace = ReplaceOf(*p.replaced)
	}
	needed, err := passkeyNeeded(ctx, s.be, tx, s.opts.Origin)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, s.setupFailed("read the passkeys", err))
	}
	if !req.Demo && j.picks == nil {
		out, err := listingAnswer(j, database, p, needed)
		if err != nil {
			return CheckAnswer{}, err
		}
		facts.apply(&out)
		out.Replace = replace
		return out, nil
	}
	ch, err := s.challenge(req, bound{database: database, host: j.host, picks: picksKey(j.picks), answers: answersKey(p.answers), classes: classesKey(req), trustRoot: req.TrustRoot, replace: replace != nil})
	if err != nil {
		return CheckAnswer{}, s.setupFailed("make the passkey challenge", err)
	}
	if !req.Demo {
		out := CheckAnswer{
			Database: database, Lines: append(replacedLines(database, p), realSummary(j, database, p.write, p.read, needed, p.keep)...),
			SQL:       RemovedSQL(p.removed) + p.script.SQL() + labelsSQL(req),
			Questions: p.questions, Notes: append([]string{}, p.script.Warnings...), PasskeyNeeded: needed, Challenge: &ch, Replace: replace,
		}
		facts.apply(&out)
		out.Lines = append(out.Lines, rekeyLines(j, p)...)
		if pinned != nil {
			out.Lines = append(out.Lines, "It trusts the certificate authority SHA-256 "+pinned.sha256+" for "+pinned.host+" only, and the agent connects with sslmode=verify-full.")
		}
		// The tables are read; the transaction ends before the columns are
		// read and sampled on the connection.
		_ = tx.Rollback(context.WithoutCancel(ctx))
		// A replaced install's labels go with it: every column starts
		// unclassified, as the run finds it.
		if out.Columns, out.ColumnsMore, err = s.columns(ctx, conn, j, replace == nil); err != nil {
			return CheckAnswer{}, timeLimit(ctx, s.setupFailed("read the columns", err))
		}
		return out, nil
	}
	out := CheckAnswer{
		Database: database, Lines: append(replacedLines(database, p), s.summary(j, database, p.seeded, needed, p.keep)...),
		SQL:       RemovedSQL(p.removed) + p.seeded.Shown() + p.script.SQL(),
		Questions: []Question{}, Notes: s.notes(p.seeded, p.script), PasskeyNeeded: needed, Challenge: &ch, Replace: replace,
	}
	facts.apply(&out)
	out.Lines = append(out.Lines, rekeyLines(j, p)...)
	return out, nil
}

// replacedLines say that the install first removes the guard below the
// update floor it replaces; none when it replaces nothing.
func replacedLines(database string, p planned) []string {
	if p.replaced == nil {
		return nil
	}
	return []string{fmt.Sprintf("It first removes the old BasaltDB install from the database %s (guard version %d): the guard's row-level security policies, the schema basalt_meta with its ledger, held approvals and passkeys, and its roles. Your tables and rows stay.", database, p.replaced.Version)}
}

// rekeyLines say that the install sets a new password for a role an
// earlier setup left.
func rekeyLines(j job, p planned) []string {
	if !p.rekey {
		return nil
	}
	return []string{fmt.Sprintf("The database already has the agent role %s from an earlier setup whose password this computer no longer holds: this sets a new password for it, as Fix on the Update check does.", j.role)}
}

// listingAnswer is the answer of a check with no picks: the tables the
// person may pick, and nothing that depends on a pick (CONTRACT.md, The
// install of a real database, The listing call).
func listingAnswer(j job, database string, p planned, needed bool) (CheckAnswer, error) {
	if len(p.list.tables) == 0 {
		return CheckAnswer{}, refuse(CodeNoTables, "The database has no table the admin can give the agent in the listed schemas. Create the tables first; nothing changed.")
	}
	return CheckAnswer{
		Database: database, Lines: []string{fmt.Sprintf("This sets up Basalt in the database %s. Pick the tables the agent %s gets.", database, j.req.Agent)},
		Questions: []Question{}, Notes: []string{}, PasskeyNeeded: needed,
		Tables: p.list.tables, Excluded: p.list.excluded, TablesMore: p.list.more,
	}, nil
}

// currentDatabase is the name of the database the connection reached, as
// the server says it: never a name read from the admin string.
func (s *LocalService) currentDatabase(ctx context.Context, tx Tx) (string, error) {
	name, err := s.be.CurrentDatabase(ctx, tx.Port())
	if err != nil {
		return "", s.setupFailed("read the database name", err)
	}
	return name, nil
}

// passkeyNeeded: the database has no active passkey for origin (none at
// all on a fresh database, whose passkeys table does not exist yet).
func passkeyNeeded(ctx context.Context, b LocalBackend, tx Tx, origin string) (bool, error) {
	// A savepoint: on a fresh database the lookup fails and must not abort tx.
	sub, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = sub.Rollback(context.WithoutCancel(ctx)) }()
	has, err := b.HasPasskeyFor(ctx, sub.Port(), origin)
	if code := SQLStateOf(err); code == "42P01" || code == "3F000" {
		return true, nil // basalt_meta or its passkeys table does not exist yet
	}
	return !has, err
}

// summary is the fixed account of the install the person reads.
func (s *LocalService) summary(j job, database string, seeded guardmodel.DemoPlan, passkeyNeeded, keep bool) []string {
	lines := []string{fmt.Sprintf("This sets up Basalt in the database %s.", database)}
	if keep {
		lines = append(lines, fmt.Sprintf("The agent %s (role %s) is already in the database, and this engine holds its password: this finishes its setup, which stopped before the engine wrote its config. Its password stays.", j.req.Agent, j.role))
	} else {
		lines = append(lines, fmt.Sprintf("It creates the agent %s (role %s), which runs as the OS user %s. Its password is made by this engine and kept on this computer only.", j.req.Agent, j.role, j.req.OSUser))
	}
	if !seeded.Exists() {
		lines = append(lines, "It creates the sample schema "+s.be.DemoSchema()+" with its tables leads and lead_notes.")
	}
	lines = append(lines, "The agent can read and write "+strings.Join(s.be.DemoTables(), " and ")+", and nothing else. Every write it makes is recorded, and a large one waits for your passkey.")
	if passkeyNeeded {
		lines = append(lines, "The database has no passkey for this computer yet: you create one now, and it approves the agent's held writes and reverts.")
	}
	return lines
}

// notes are the lines that depend on what the database holds.
func (s *LocalService) notes(seeded guardmodel.DemoPlan, script guardmodel.Script) []string {
	out := []string{}
	if seeded.Exists() {
		out = append(out, "sample schema "+s.be.DemoSchema()+" already exists; its rows are left as they are")
	}
	return append(out, script.Warnings...)
}

// timeLimit is err, or the time-limit refusal when the call ran out of time.
func timeLimit(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return refuse(CodeTimeLimit, "The setup ran out of time; nothing changed.")
	}
	return err
}
