// Package localsetup is the engine's side of the local setup page
// (CONTRACT.md, The local setup page): the INSTALL job of an engine with no
// config, run with the admin connection string the person types on the
// page. The string is used for one request and never written, logged or
// returned; every answer and refusal is built from fixed words and values
// read from the catalog.
package localsetup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/demo"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// JobInstall is the one job this engine runs today.
const JobInstall = "INSTALL"

// Fixed values the engine chooses itself for a first install.
const (
	defaultPrefix    = guard.DefaultPrefix
	statementTimeout = 30 * time.Second
	// callLimit bounds one check or run; the transaction rolls back.
	callLimit = 60 * time.Second
)

// Request is the body of the check and run routes.
type Request struct {
	Job         string     `json:"job"`
	Agent       string     `json:"agent"`
	OSUser      string     `json:"osUser"`
	Demo        bool       `json:"demo"`
	DatabaseURL string     `json:"databaseUrl"`
	Answers     []Answer   `json:"answers,omitempty"`
	Challenge   *Challenge `json:"challenge,omitempty"`
	Passkey     *Passkey   `json:"passkey,omitempty"`
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
	Challenge     Challenge  `json:"challenge"`
}

// RegisteredPasskey is one passkey the run registered.
type RegisteredPasskey struct {
	CredentialID passkey.Bytes `json:"credentialId"`
	Label        string        `json:"label"`
	CheckCode    string        `json:"checkCode"`
}

// RunAnswer is the run route's answer.
type RunAnswer struct {
	Agent      string              `json:"agent"`
	Warnings   []string            `json:"warnings"`
	Passkeys   []RegisteredPasskey `json:"passkeys"`
	MCPCommand string              `json:"mcpCommand"`
}

// Options are what the engine gives the setup.
type Options struct {
	// ConfigPath is the engine.json the run writes; its folder is the
	// engine's own.
	ConfigPath string
	// Origin is the page origin (http://localhost:8787): the passkey's
	// origin, with RP ID localhost.
	Origin string
	// Now is the clock (time.Now outside tests).
	Now func() time.Time
	// Dial opens the admin connection (pgdial.Connect outside tests).
	Dial func(ctx context.Context, dsn string) (*pgx.Conn, error)
	// Users looks OS users up (the OS outside tests).
	Users Users
	// Prefix is the roles' prefix: guard.DefaultPrefix outside tests,
	// whose databases share one server's roles.
	Prefix string
}

// Service runs the setup jobs. One runs at a time.
type Service struct {
	opts Options
	key  []byte
	rp   passkey.Relying
	busy sync.Mutex
}

// New returns the setup of an engine with no config.
func New(o Options) (*Service, error) {
	if o.ConfigPath == "" || o.Origin == "" {
		return nil, errors.New("localsetup: config path and origin required")
	}
	rp, err := passkey.Local(o.Origin)
	if err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Dial == nil {
		o.Dial = pgdial.Connect
	}
	if o.Users == nil {
		o.Users = osUsers{}
	}
	if o.Prefix == "" {
		o.Prefix = defaultPrefix
	}
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	return &Service{opts: o, key: key, rp: rp}, nil
}

// job is a validated request's job: the agent's role and its spec.
type job struct {
	req  Request
	role string
	uid  uint32
}

// validate checks everything that needs no database, in order.
func (s *Service) validate(req Request) (job, error) {
	if _, err := os.Lstat(s.opts.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		return job{}, refuse(CodeJobUnavailable, "This engine is already set up. An install never changes an engine that has a config; ask the agent for the setup link of the change you want.")
	}
	if req.Job != JobInstall {
		return job{}, refuse(CodeInvalidArgument, "This setup link names a job this engine does not run.")
	}
	role, err := (guard.Names{Prefix: s.opts.Prefix}).Agent(req.Agent)
	if err != nil {
		return job{}, refuse(CodeInvalidArgument, "This setup link names an agent whose name cannot be used. Ask the agent for a new link.")
	}
	uid, err := checkOSUser(s.opts.Users, req.OSUser)
	if err != nil {
		return job{}, err
	}
	if !req.Demo {
		return job{}, refuse(CodeNoTables, "Picking tables on this page is not available yet; set up the sample database with basalt init --demo.")
	}
	if err := checkAdminURL(req.DatabaseURL, role); err != nil {
		return job{}, err
	}
	return job{req: req, role: role, uid: uid}, nil
}

// checkAdminURL accepts a postgres:// or postgresql:// URL with a user and
// a password that an agent's connection string can be built from. The
// refusal never names any part of it.
func checkAdminURL(raw, role string) error {
	bad := refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
	if !strings.HasPrefix(raw, "postgres://") && !strings.HasPrefix(raw, "postgresql://") {
		return bad
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.User.Username() == "" || u.Host == "" {
		return bad
	}
	if pw, ok := u.User.Password(); !ok || pw == "" {
		return bad
	}
	if _, err := guard.AgentConnString(raw, role, ""); err != nil {
		return bad
	}
	return nil
}

// connect opens the admin connection; a failure is a fixed refusal.
func (s *Service) connect(ctx context.Context, admin string) (*pgx.Conn, error) {
	conn, err := s.opts.Dial(ctx, admin)
	if err == nil {
		return conn, nil
	}
	var pg *pgconn.PgError
	switch {
	case pgdial.CertificateNotVerified(err):
		return nil, refuse(CodeCertificateNotVerified, "The database's TLS certificate could not be verified for its host name.")
	case errors.As(err, &pg) && strings.HasPrefix(pg.Code, "28"):
		return nil, refuse(CodeLoginFailed, "The database refused the login. Check the admin user and password.")
	case ctx.Err() != nil:
		return nil, refuse(CodeTimeLimit, "The setup ran out of time; nothing changed.")
	}
	return nil, refuse(CodeDatabaseUnreachable, "The database could not be reached. Check the host and port in the admin connection string.")
}

// plan reads the database for j in tx: refusals, then the sample data and
// the install script. The caller rolls tx back (check) or commits (run).
func (s *Service) plan(ctx context.Context, tx pgx.Tx, j job, password string) (demo.Plan, guard.Script, error) {
	prefix := s.opts.Prefix
	names := guard.Names{Prefix: prefix}
	installed, err := guard.InstalledPrefix(ctx, tx)
	if err != nil {
		return demo.Plan{}, guard.Script{}, setupFailed()
	}
	if installed != "" && installed != prefix {
		return demo.Plan{}, guard.Script{}, refuse(CodePrefixMismatch, "This database's Basalt uses the prefix "+installed+", not "+prefix+".")
	}
	exists, err := guard.AgentRoleExists(ctx, tx, names, j.req.Agent)
	if err != nil {
		return demo.Plan{}, guard.Script{}, setupFailed()
	}
	if exists {
		return demo.Plan{}, guard.Script{}, refuse(CodeRoleExists, fmt.Sprintf("The database already has the role %s. An install never takes over an existing role.", j.role))
	}
	seeded, err := demo.Seed(ctx, tx)
	if err != nil {
		return demo.Plan{}, guard.Script{}, setupFailed()
	}
	script, err := guard.PlanInit(ctx, tx, guard.InitOptions{
		Names: names,
		Agent: guard.AgentSpec{Name: j.req.Agent, Password: password, CreateOnly: true, Write: demo.Tables, StatementTimeout: statementTimeout},
	})
	if err != nil {
		return demo.Plan{}, guard.Script{}, setupFailed()
	}
	return seeded, script, nil
}

func setupFailed() *RefusalError {
	return refuse(CodeSetupFailed, "Reading the database or running the setup failed; nothing changed.")
}

// Check reads what an install would do. It changes nothing.
func (s *Service) Check(ctx context.Context, req Request) (CheckAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, callLimit)
	defer cancel()
	j, err := s.validate(req)
	if err != nil {
		return CheckAnswer{}, err
	}
	conn, err := s.connect(ctx, req.DatabaseURL)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	database := conn.Config().Database
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// A throwaway password: the shown SQL redacts it, and nothing commits.
	seeded, script, err := s.plan(ctx, tx, j, guard.NewPassword())
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	needed, err := passkeyNeeded(ctx, tx, s.opts.Origin)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, setupFailed())
	}
	ch, err := s.challenge(req, database)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	return CheckAnswer{
		Database: database, Lines: summary(j, database, seeded, needed), SQL: seeded.Shown() + script.SQL(),
		Questions: []Question{}, Notes: notes(seeded, script), PasskeyNeeded: needed, Challenge: ch,
	}, nil
}

// passkeyNeeded: the database has no active passkey for origin (none at
// all on a fresh database, whose passkeys table does not exist yet).
func passkeyNeeded(ctx context.Context, tx pgx.Tx, origin string) (bool, error) {
	// A savepoint: on a fresh database the lookup fails and must not abort tx.
	sub, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = sub.Rollback(context.WithoutCancel(ctx)) }()
	has, err := setuprun.HasPasskeyFor(ctx, sub, origin)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "42P01" || pg.Code == "3F000") {
		return true, nil // basalt_meta or its passkeys table does not exist yet
	}
	return !has, err
}

// summary is the fixed account of the install the person reads.
func summary(j job, database string, seeded demo.Plan, passkeyNeeded bool) []string {
	lines := []string{
		fmt.Sprintf("This sets up Basalt in the database %s.", database),
		fmt.Sprintf("It creates the agent %s (role %s), which runs as the OS user %s. Its password is made by this engine and kept on this computer only.", j.req.Agent, j.role, j.req.OSUser),
	}
	if !seeded.Exists() {
		lines = append(lines, "It creates the sample schema "+demo.Schema+" with its tables leads and lead_notes.")
	}
	lines = append(lines, "The agent can read and write "+strings.Join(demo.Tables, " and ")+", and nothing else. Every write it makes is recorded, and a large one waits for your passkey.")
	if passkeyNeeded {
		lines = append(lines, "The database has no passkey for this computer yet: you create one now, and it approves the agent's held writes and reverts.")
	}
	return lines
}

// notes are the lines that depend on what the database holds.
func notes(seeded demo.Plan, script guard.Script) []string {
	out := []string{}
	if seeded.Exists() {
		out = append(out, "The sample schema "+demo.Schema+" already exists; its rows are left as they are.")
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
