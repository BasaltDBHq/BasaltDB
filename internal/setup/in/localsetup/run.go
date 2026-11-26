package localsetup

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// Refusal codes and their statuses (CONTRACT.md, The local setup page,
// Errors): the connect page's reasons, plus INVALID_ARGUMENT and
// JOB_UNAVAILABLE.
const (
	CodeInvalidArgument = "INVALID_ARGUMENT"
	CodeJobUnavailable  = "JOB_UNAVAILABLE"
	// CodeEngineRemoved: a configured engine whose engine.json a REMOVE
	// deleted; basalt init then removes the engine service.
	CodeEngineRemoved           = "ENGINE_REMOVED"
	CodeBusy                    = "BUSY"
	CodeConnectionStringRefused = "CONNECTION_STRING_REFUSED"
	CodeDatabaseUnreachable     = "DATABASE_UNREACHABLE"
	CodeCertificateNotVerified  = "CERTIFICATE_NOT_VERIFIED"
	CodeLoginFailed             = "LOGIN_FAILED"
	CodePrefixMismatch          = "PREFIX_MISMATCH"
	CodeRoleExists              = "ROLE_EXISTS"
	CodeNoTables                = "NO_TABLES"
	CodeAnswersInvalid          = "ANSWERS_INVALID"
	CodePasskeyRequired         = "PASSKEY_REQUIRED"
	CodeChallengeExpired        = "CHALLENGE_EXPIRED"
	CodeChallengeInvalid        = "CHALLENGE_INVALID"
	CodePasskeyInvalid          = "PASSKEY_INVALID"
	CodeSetupFailed             = "SETUP_FAILED"
	// CodeGrantsNotRevoked: the agent role an earlier run left still has a
	// setup grant on a table or sequence not picked now, which this admin
	// cannot revoke (another role made it); nothing changed.
	CodeGrantsNotRevoked = "GRANTS_NOT_REVOKED"
	// CodeGuardUnusable: the database has a basalt_meta this build cannot
	// install over or update (an older install, or a partial one).
	CodeGuardUnusable = setup.SetuprunCodeGuardUnusable
	CodeTimeLimit     = "TIME_LIMIT"
)

// Refusal is a refused setup call: a code and its fixed message. Status,
// when set, is its HTTP status in place of the code's.
type RefusalError struct {
	Code    string
	Message string
	Status  int
	// TrustRoot is set on a CERTIFICATE_NOT_VERIFIED the person can answer
	// by trusting the chain's top for the host.
	TrustRoot *TrustRoot
	// Pinned is the SHA-256 pinned now, on a TRUST check's refusal of a
	// changed certificate.
	Pinned string
	// Cause is why a SETUP_FAILED happened, for the engine's log only.
	Cause *Cause
}

// Cause is a SETUP_FAILED's cause: the step that failed, the Postgres
// SQLSTATE when the database refused it, and the error's message. It holds
// no connection string and no password (redact).
type Cause struct {
	Step     string
	SQLState string
	Message  string
}

// TrustRoot is the chain top a database presents, as the page shows it for
// the person to trust (CONTRACT.md, The install of a real database, The
// database certificate). Subject is text the server supplied.
type TrustRoot struct {
	Subject   string `json:"subject"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expiresAt"`
}

func (r *RefusalError) Error() string { return r.Message }

func refuse(code, message string) *RefusalError { return &RefusalError{Code: code, Message: message} }

// AsRefusal is err as a refusal; anything else is SETUP_FAILED, its text
// only in the redacted Cause. The Service's calls return only refusals
// (Service.refused), so this reads no database error itself.
func AsRefusal(err error) *RefusalError {
	var r *RefusalError
	if errors.As(err, &r) {
		return r
	}
	return failed("setup", err, nil)
}

// asRefusal is AsRefusal with the database error's message in the Cause.
func (s *Service) asRefusal(err error) *RefusalError {
	var r *RefusalError
	if errors.As(err, &r) {
		return r
	}
	return s.setupFailed("setup", err)
}

// Challenge is the passkey challenge check hands the page: the connect
// page's fields, with a MAC made with a key held only in this engine's
// memory over them and the job's fields. It is not single-use; the admin
// string in the same request is what lets a run happen.
type Challenge struct {
	Challenge   passkey.Bytes `json:"challenge"`
	UserID      passkey.Bytes `json:"userId"`
	UserName    string        `json:"userName"`
	DisplayName string        `json:"displayName"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	MAC         passkey.Bytes `json:"mac"`
}

const (
	keyLen          = 32
	challengeLen    = 32
	userIDLen       = 16
	challengeExpiry = 15 * time.Minute
	maxLabel        = 64
	// macDomain separates this MAC from any other the key could make.
	macDomain = "basalt-local-setup-challenge.1\n"
)

func newKey() ([]byte, error) {
	key := make([]byte, keyLen)
	_, err := rand.Read(key)
	return key, err
}

// bound is what a challenge is bound to besides the job: the database the
// server named and the admin string's host.
type bound struct {
	database, host string
	// picks is the picked tables with their access (picksKey), empty for
	// the sample database.
	picks string
	// answers is the row-level security answers, sorted (answersKey).
	answers string
	// classes is the labels the person set (classesKey).
	classes string
	// trustRoot is the certificate authority the person trusted.
	trustRoot string
}

// challenge makes a fresh challenge for req's job on b.
func (s *Service) challenge(req Request, b bound) (Challenge, error) {
	c := Challenge{
		Challenge: make([]byte, challengeLen), UserID: make([]byte, userIDLen),
		UserName: "BasaltDB · " + req.Agent, DisplayName: "BasaltDB · " + b.database,
		ExpiresAt: s.opts.Now().Add(challengeExpiry).UTC().Truncate(time.Second),
	}
	if len(c.DisplayName) > maxLabel {
		c.DisplayName = c.UserName
	}
	if _, err := rand.Read(c.Challenge); err != nil {
		return Challenge{}, err
	}
	if _, err := rand.Read(c.UserID); err != nil {
		return Challenge{}, err
	}
	c.MAC = s.mac(req, b, c)
	return c, nil
}

// mac is the keyed hash over the challenge's fields and the job's, each
// length-prefixed so no two inputs share an encoding.
func (s *Service) mac(req Request, b bound, c Challenge) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(macDomain))
	demoFlag := "0"
	if req.Demo {
		demoFlag = "1"
	}
	for _, part := range [][]byte{
		c.Challenge, c.UserID, []byte(c.UserName), []byte(c.DisplayName), []byte(c.ExpiresAt.UTC().Format(time.RFC3339)),
		[]byte(req.Job), []byte(req.Agent), []byte(req.OSUser), []byte(demoFlag), []byte(b.database), []byte(b.host), []byte(b.picks), []byte(b.answers), []byte(b.classes), []byte(b.trustRoot),
	} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return h.Sum(nil)
}

// verifyPasskey checks the challenge's expiry and the registration, before
// anything connects; checkBinding checks its MAC once the server named the
// database. Only called with a passkey in the request.
func (s *Service) verifyPasskey(req Request) (*passkey.Credential, error) {
	c := req.Challenge
	if c == nil {
		return nil, refuse(CodeChallengeInvalid, "This passkey was made for another setup page. Reload the page and start again.")
	}
	if !s.opts.Now().Before(c.ExpiresAt) {
		return nil, refuse(CodeChallengeExpired, "This page waited more than 15 minutes. Check again, then create the passkey.")
	}
	rr, err := setup.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	if err != nil {
		return nil, refuse(CodeChallengeInvalid, "This passkey was made for another setup page. Reload the page and start again.")
	}
	cred, err := setup.VerifyRegistration(rr, req.Passkey.RegistrationResponse, s.rp)
	if err != nil {
		return nil, refuse(CodePasskeyInvalid, "The passkey could not be checked. Create it again on this page.")
	}
	if len(req.Passkey.Label) > maxLabel {
		return nil, refuse(CodeInvalidArgument, "The passkey's label is too long.")
	}
	if strings.TrimSpace(req.Passkey.Label) == "" {
		// The page asks for no label; register_passkey requires one.
		req.Passkey.Label = defaultPasskeyLabel(os.Hostname)
	}
	return &cred, nil
}

// fallbackPasskeyLabel names a passkey when the computer's name cannot be
// read or holds nothing printable.
const fallbackPasskeyLabel = "Passkey from the setup page"

// defaultPasskeyLabel names a passkey the page sent unnamed after this
// computer: "Passkey on <hostname>", the name without its .local suffix
// and kept to letters, digits, '.', '-' and '_', within maxLabel bytes.
func defaultPasskeyLabel(hostname func() (string, error)) string {
	name, err := hostname()
	if err != nil {
		return fallbackPasskeyLabel
	}
	name = strings.TrimSuffix(name, ".local")
	var b strings.Builder
	for _, r := range name {
		if r < 0x80 && (r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	const prefix = "Passkey on "
	host := b.String()
	if host == "" {
		return fallbackPasskeyLabel
	}
	return prefix + host[:min(len(host), maxLabel-len(prefix))]
}

// checkBinding refuses a challenge made for another job, database or host.
func (s *Service) checkBinding(req Request, b bound) error {
	if req.Challenge == nil || !hmac.Equal(req.Challenge.MAC, s.mac(req, b, *req.Challenge)) {
		return refuse(CodeChallengeInvalid, "This passkey was made for another setup page or database. Reload the page and start again.")
	}
	return nil
}

// Run runs the install once: the guard, the sample data, the agent and the
// passkey in one transaction, then the agent's credential and engine.json,
// written as this engine's own user. One run at a time.
func (s *Service) Run(ctx context.Context, req Request) (RunAnswer, error) {
	given := req.DatabaseURL
	req.DatabaseURL = s.verifyByDefault(given)
	a, err := s.run(ctx, req)
	return a, scrub(scrub(s.refused(err), given), req.DatabaseURL)
}

func (s *Service) run(ctx context.Context, req Request) (RunAnswer, error) {
	if !s.busy.TryLock() {
		return RunAnswer{}, refuse(CodeBusy, "Another setup is running. Wait for it to finish.")
	}
	defer s.busy.Unlock()
	ctx, cancel := context.WithTimeout(ctx, callLimit)
	defer cancel()
	if s.opts.Configured {
		return s.runAgentJob(ctx, req)
	}
	j, err := s.validate(req)
	if err != nil {
		return RunAnswer{}, err
	}
	if req.Demo && len(req.Answers) > 0 {
		return RunAnswer{}, refuse(CodeAnswersInvalid, "This setup asks no question, so it takes no answer.")
	}
	if !req.Demo && j.picks == nil {
		return RunAnswer{}, refuse(CodeNoTables, "There is no table to give the agent. Pick at least one table; nothing changed.")
	}
	if !req.Demo {
		// A real install always carries the check's challenge, so the picks
		// and answers run are the ones check showed.
		if req.Challenge == nil {
			return RunAnswer{}, refuse(CodeChallengeInvalid, "Check the setup on this page first, then run it. Reload the page and start again.")
		}
		if !s.opts.Now().Before(req.Challenge.ExpiresAt) {
			return RunAnswer{}, refuse(CodeChallengeExpired, "This page waited more than 15 minutes. Check again, then run it.")
		}
	}
	var cred *passkey.Credential
	if req.Passkey != nil {
		if cred, err = s.verifyPasskey(req); err != nil {
			return RunAnswer{}, err
		}
	}
	conn, pinned, err := s.open(ctx, req)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	password := s.be.NewPassword()
	dsn, err := s.be.AgentConnString(req.DatabaseURL, j.role, password)
	if err != nil {
		return RunAnswer{}, refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
	}
	if pinned != nil {
		dsn = withVerifyFull(dsn) // the pin applies with verify-full only
	}
	files := s.files(req.Agent)
	var warnings, lines []string
	wrote := false
	err = s.inTx(ctx, conn, func(tx Tx) error {
		database, err := s.currentDatabase(ctx, tx)
		if err != nil {
			return err
		}
		if cred != nil || !req.Demo {
			if err := s.checkBinding(req, bound{database: database, host: j.host, picks: picksKey(j.picks), answers: answersKey(req.Answers), classes: classesKey(req), trustRoot: req.TrustRoot}); err != nil {
				return err
			}
		}
		p, err := s.plan(ctx, tx, j, password, database, answersOf(req))
		if err != nil {
			return err
		}
		script, keep := p.script, p.keep
		needed, err := passkeyNeeded(ctx, s.be, tx, s.opts.Origin)
		if err != nil {
			return s.setupFailed("read the passkeys", err)
		}
		if needed && cred == nil {
			return refuse(CodePasskeyRequired, "The database has no passkey for this computer yet: create one on this page first. Nothing changed.")
		}
		if err := setup.ApplyInitTx(ctx, s.be, tx.Port(), script); err != nil {
			if r := s.grantsNotRevoked(err, j.role); r != nil {
				return r
			}
			return s.setupFailed("install script", err)
		}
		if !req.Demo {
			n, err := s.writeLabels(ctx, tx, guardmodel.Names{Prefix: s.opts.Prefix}, j.picks, req, s.opts.Now())
			if err != nil {
				return err
			}
			p.labeled = n
		}
		if cred != nil {
			if err := s.be.RegisterPasskey(ctx, tx.Port(), *cred, req.Passkey.Label); err != nil {
				return s.setupFailed("register the passkey", err)
			}
		}
		warnings = script.Warnings
		if req.Demo {
			leads, notes, err := s.be.DemoCounts(ctx, tx.Port())
			if err != nil {
				return s.setupFailed("count the sample data", err)
			}
			lines = []string{fmt.Sprintf("demo ready: leads %d, lead_notes %d", leads, notes)}
		} else {
			lines = []string{fmt.Sprintf("agent %s ready: %d tables it can change, %d it can read", req.Agent, len(p.write), len(p.read))}
			if p.labeled > 0 {
				lines = append(lines, fmt.Sprintf("%d columns labeled", p.labeled))
			}
		}
		if pinned != nil {
			// Before the commit, once the SQL succeeded: a pin that stays after
			// a failed commit was approved and checked.
			if err := s.writePin(ctx, pinned, tx); err != nil {
				return err
			}
		}
		if keep {
			return nil // the credential of the role this engine already holds stays
		}
		// The credential goes to disk before the commit: a write that fails
		// rolls the database back with it, so no role is left without it.
		wrote = true
		return files.writeCredential(dsn)
	})
	if err != nil {
		var unknown *unknownOutcomeError
		if errors.As(err, &unknown) {
			// The commit's answer was lost: the role may exist, and this
			// credential is its only password. It stays: a run again finds the
			// role and finishes with it (ownRole), or overwrites it when the
			// role was never made.
			return RunAnswer{}, refuse(CodeSetupFailed, "The database did not confirm the setup. Run it again on this page: it finishes if the setup went through, and starts over if it did not.")
		}
		if wrote {
			files.removeCredential() // its role was rolled back
		}
		return RunAnswer{}, timeLimit(ctx, s.asRefusal(err))
	}
	// The credential is never removed after the commit: a run that finds
	// its role finishes with it (ownRole).
	if err := files.writeConfig(req, j.uid); err != nil {
		r := refuse(CodeSetupFailed, "The database is set up, but this engine could not write its config. Check that the engine's own folder can be written, then run the setup again on this page: it finishes with the agent this engine already holds.")
		r.Status = http.StatusInternalServerError
		return RunAnswer{}, r
	}
	answer := RunAnswer{Agent: req.Agent, Lines: lines, Warnings: append([]string{}, warnings...), Passkeys: []RegisteredPasskey{}, MCPCommand: "basalt mcp --agent " + req.Agent}
	if cred != nil {
		code, _ := cred.CheckCode()
		answer.Passkeys = append(answer.Passkeys, RegisteredPasskey{CredentialID: cred.ID, Label: req.Passkey.Label, CheckCode: code})
	}
	return answer, nil
}

// engineFiles are the agent's credential and engine.json, next to each
// other in the engine's own folder.
type engineFiles struct {
	config, credential string
}

func (s *Service) files(agent string) engineFiles {
	return engineFiles{
		config:     s.opts.ConfigPath,
		credential: filepath.Join(filepath.Dir(s.opts.ConfigPath), "agents", agent+".url"),
	}
}

func (f engineFiles) writeCredential(dsn string) error {
	if err := config.WriteFile(f.credential, []byte(dsn+"\n")); err != nil {
		return refuse(CodeSetupFailed, "This engine could not write the agent's credential; nothing changed.")
	}
	return nil
}

func (f engineFiles) removeCredential() { _ = os.Remove(f.credential) }

// writeConfig adds the agent to a new engine.json: a person-operated
// service engine serving the local pages.
func (f engineFiles) writeConfig(req Request, uid uint32) error {
	_, err := config.UpsertAgentVault(f.config, config.Settings{
		SocketDir: config.DefaultSocketDir(runtime.GOOS), Mode: config.ModeService, PagesURL: links.DefaultLocal,
		OperatedBy: "PERSON", PersonUIDs: []uint32{uid}, VaultDefault: config.VaultOff,
	}, config.Agent{Name: req.Agent, OSUser: req.OSUser, Store: config.PostgresStore(f.credential)})
	return err
}

// Users looks OS users up.
type Users interface {
	Lookup(name string) (*user.User, error)
	LookupID(uid string) (*user.User, error)
	GroupIDs(u *user.User) ([]string, error)
	// Self is this engine's own uid.
	Self() int
}

type osUsers struct{}

func (osUsers) Lookup(name string) (*user.User, error)  { return user.Lookup(name) }
func (osUsers) LookupID(uid string) (*user.User, error) { return user.LookupId(uid) }
func (osUsers) GroupIDs(u *user.User) ([]string, error) { return u.GroupIds() }
func (osUsers) Self() int                               { return os.Getuid() }

// checkOSUser accepts the agent's OS user: one that exists, is not root,
// not this engine's own user and not in its group.
func checkOSUser(users Users, name string) (uint32, error) {
	bad := func(why string) error {
		return refuse(CodeInvalidArgument, fmt.Sprintf("The agent cannot run as the OS user %s: %s. Ask the agent for a new link.", name, why))
	}
	if name == "" {
		return 0, refuse(CodeInvalidArgument, "This setup link names no OS user for the agent. Ask the agent for a new link.")
	}
	if strings.HasPrefix(name, "basalt-plugin-") || strings.HasPrefix(name, "_basalt-plugin-") {
		return 0, bad("Basalt keeps that name for a plugin")
	}
	u, err := users.Lookup(name)
	if err != nil {
		return 0, bad("no such user")
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, bad("its user id cannot be read")
	}
	switch {
	case uid == 0:
		return 0, bad("it is root")
	case int(uid) == users.Self():
		return 0, bad("it is this engine's own user")
	}
	self, err := users.LookupID(strconv.Itoa(users.Self()))
	if err != nil {
		return 0, bad("this engine's own group cannot be read")
	}
	groups, err := users.GroupIDs(u)
	if err != nil {
		return 0, bad("its groups cannot be read")
	}
	if slices.Contains(append(groups, u.Gid), self.Gid) {
		return 0, bad("it is in this engine's group")
	}
	return uint32(uid), nil
}

// answersOf are the run's answers, never nil: plan reads nil as a check,
// which assumes every question answered ALL_ROWS.
func answersOf(req Request) []Answer {
	if req.Answers == nil {
		return []Answer{}
	}
	return req.Answers
}

// unknownOutcomeError is a COMMIT whose answer was lost: whether it took effect is
// not known.
type unknownOutcomeError struct{ err error }

func (u *unknownOutcomeError) Error() string {
	return "the commit's outcome is unknown: " + u.err.Error()
}

func (u *unknownOutcomeError) Unwrap() error { return u.err }

// inTx runs fn in a transaction on conn. It is beginFunc, except that a
// commit that fails without the server's answer is an unknownOutcomeError; one the
// server answered (an error of its own, or a commit that became a rollback)
// is a known failure, and so is fn's.
func (s *Service) inTx(ctx context.Context, conn Conn, fn func(Tx) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return err
	}
	err = tx.Commit(ctx)
	switch {
	case err == nil:
		return nil
	case s.be.CommitAnswered(err):
		return err // answered, rolled back, or never sent
	}
	return &unknownOutcomeError{err: err}
}

// beginFunc runs fn in a transaction on conn, as pgx.BeginFunc does:
// committed when fn returns nil, rolled back when it returns an error,
// which beginFunc returns; a failed commit is its error as it is. The
// closing rollback of a transaction that already ended is not an error
// (Tx.Rollback); any other failure of it is the error.
func beginFunc(ctx context.Context, conn Conn, fn func(Tx) error) (err error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if rerr := tx.Rollback(ctx); rerr != nil {
			err = rerr
		}
	}()
	if ferr := fn(tx); ferr != nil {
		_ = tx.Rollback(ctx) // pgx.BeginFunc drops this rollback's error
		return ferr
	}
	return tx.Commit(ctx)
}

// maxLeftTables bounds the list of tables and sequences a GRANTS_NOT_REVOKED names.
const maxLeftTables = 300

// grantsNotRevoked is GRANTS_NOT_REVOKED for the guard's refusal of an
// install that finishes with a role an earlier run left: the role still has
// a setup grant on a table or sequence not picked now that this admin
// cannot revoke (guardmodel.UnpickedGrantsDetail, then the relations). nil for any other
// error.
func (s *Service) grantsNotRevoked(err error, role string) *RefusalError {
	_, detail, ok := s.be.DatabaseError(err)
	if !ok || setup.SQLStateOf(err) != sqlstateLedgerInputInvalid {
		return nil
	}
	_, tables, ok := strings.Cut(detail, guardmodel.UnpickedGrantsDetail)
	if !ok {
		return nil
	}
	tables = printable(tables)
	if len(tables) > maxLeftTables {
		tables = strings.ToValidUTF8(tables[:maxLeftTables], "") + "…"
	}
	return refuse(CodeGrantsNotRevoked, fmt.Sprintf("The agent role %s still has access to tables or sequences that were not picked (%s), from an earlier setup run, and this admin cannot revoke it: another role made those grants. "+
		"That role, or the owner of the table or sequence, must revoke them (REVOKE ALL ON <table or sequence> FROM %s); then run the setup again on this page. Nothing changed.", role, tables, role))
}
