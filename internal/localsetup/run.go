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

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/demo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// Refusal codes and their statuses (CONTRACT.md, The local setup page,
// Errors): the connect page's reasons, plus INVALID_ARGUMENT and
// JOB_UNAVAILABLE.
const (
	CodeInvalidArgument         = "INVALID_ARGUMENT"
	CodeJobUnavailable          = "JOB_UNAVAILABLE"
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
	CodeTimeLimit               = "TIME_LIMIT"
)

// Refusal is a refused setup call: a code and its fixed message. Status,
// when set, is its HTTP status in place of the code's.
type RefusalError struct {
	Code    string
	Message string
	Status  int
}

func (r *RefusalError) Error() string { return r.Message }

func refuse(code, message string) *RefusalError { return &RefusalError{Code: code, Message: message} }

// AsRefusal is err as a refusal; anything else is SETUP_FAILED, without
// its text.
func AsRefusal(err error) *RefusalError {
	var r *RefusalError
	if errors.As(err, &r) {
		return r
	}
	return setupFailed()
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
		[]byte(req.Job), []byte(req.Agent), []byte(req.OSUser), []byte(demoFlag), []byte(b.database), []byte(b.host), []byte(b.picks),
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
	rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	if err != nil {
		return nil, refuse(CodeChallengeInvalid, "This passkey was made for another setup page. Reload the page and start again.")
	}
	cred, err := passkey.VerifyRegistration(rr, req.Passkey.RegistrationResponse, s.rp)
	if err != nil {
		return nil, refuse(CodePasskeyInvalid, "The passkey could not be checked. Create it again on this page.")
	}
	if len(req.Passkey.Label) > maxLabel {
		return nil, refuse(CodeInvalidArgument, "The passkey's label is too long.")
	}
	return &cred, nil
}

// checkBinding refuses a challenge made for another job, database or host.
func (s *Service) checkBinding(req Request, b bound) error {
	if !hmac.Equal(req.Challenge.MAC, s.mac(req, b, *req.Challenge)) {
		return refuse(CodeChallengeInvalid, "This passkey was made for another setup page or database. Reload the page and start again.")
	}
	return nil
}

// Run runs the install once: the guard, the sample data, the agent and the
// passkey in one transaction, then the agent's credential and engine.json,
// written as this engine's own user. One run at a time.
func (s *Service) Run(ctx context.Context, req Request) (RunAnswer, error) {
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
	var cred *passkey.Credential
	if req.Passkey != nil {
		if cred, err = s.verifyPasskey(req); err != nil {
			return RunAnswer{}, err
		}
	}
	conn, err := s.connect(ctx, req.DatabaseURL)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	password := guard.NewPassword()
	dsn, err := guard.AgentConnString(req.DatabaseURL, j.role, password)
	if err != nil {
		return RunAnswer{}, refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
	}
	files := s.files(req.Agent)
	var warnings, lines []string
	wrote := false
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		database, err := currentDatabase(ctx, tx)
		if err != nil {
			return err
		}
		if cred != nil {
			if err := s.checkBinding(req, bound{database: database, host: j.host, picks: picksKey(j.picks)}); err != nil {
				return err
			}
		}
		p, err := s.plan(ctx, tx, j, password, database, answersOf(req))
		if err != nil {
			return err
		}
		script, keep := p.script, p.keep
		needed, err := passkeyNeeded(ctx, tx, s.opts.Origin)
		if err != nil {
			return setupFailed()
		}
		if needed && cred == nil {
			return refuse(CodePasskeyRequired, "The database has no passkey for this computer yet: create one on this page first. Nothing changed.")
		}
		if err := setuprun.ApplyInitTx(ctx, tx, script); err != nil {
			return setupFailed()
		}
		if cred != nil {
			if err := guard.RegisterPasskey(ctx, tx, *cred, req.Passkey.Label); err != nil {
				return setupFailed()
			}
		}
		warnings = script.Warnings
		if req.Demo {
			leads, notes, err := demo.Counts(ctx, tx)
			if err != nil {
				return setupFailed()
			}
			lines = []string{fmt.Sprintf("demo ready: leads %d, lead_notes %d", leads, notes)}
		} else {
			lines = []string{fmt.Sprintf("agent %s ready: %d tables it can change, %d it can read", req.Agent, len(p.write), len(p.read))}
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
		if wrote {
			files.removeCredential() // its role was rolled back
		}
		return RunAnswer{}, timeLimit(ctx, AsRefusal(err))
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
