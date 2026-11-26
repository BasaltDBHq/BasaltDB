package handoff

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// pendingLoginTimeout bounds the login with the .pending credential.
const pendingLoginTimeout = 15 * time.Second

// maxPendingBytes bounds a .pending credential as stored, surrounding space
// included, as basalt init --remote bounds the one it reads.
const maxPendingBytes = 4096

// FinishFiles reaches an agent's .pending credential, its credential file,
// its .lock and the engine config the finisher clears the setup from.
type FinishFiles interface {
	// ReadPending reads the .pending credential, trimmed: an error wrapping
	// fs.ErrNotExist when there is none, and an error when the file holds
	// more than limit bytes.
	ReadPending(limit int) (string, os.FileInfo, error)
	// Promote moves the .pending credential over the credential file, once
	// .pending still names the file read (pending).
	Promote(pending os.FileInfo) error
	Lock() (func(), error)
	ClearSetup(agent, id string) (bool, error)
}

// AgentLogin is the agent's own connection the finisher reads with.
type AgentLogin interface {
	// SetupRecorded reports whether setup id is recorded in the database.
	SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error)
	Close(ctx context.Context) error
}

// LoginTarget is a credential without its password.
type LoginTarget struct {
	Host     string
	Port     uint16
	Database string
	User     string
}

// Finisher is agent.SetupFinisher for one agent of the engine: its config
// entry, its credential file and the pool the engine serves it on.
type Finisher struct {
	Agent, ConfigPath, CredFile string
	Files                       FinishFiles
	// Login is who the engine's credential logs in as and where: a
	// .pending credential is used only for the same.
	Login LoginTarget
	// Parse reads a credential's target and password. Its error is
	// replaced, since a parse error can echo the URL and its password.
	Parse func(dsn string) (LoginTarget, string, error)
	// Connect logs in with dsn. A refused login is one setup.LoginRefused
	// reports, read through Errors.
	Connect func(ctx context.Context, dsn string) (AgentLogin, error)
	// Errors reads the server's message of a refused login (Supabase's
	// pooler not knowing the role); internal/app gives the Postgres
	// adapter's. It is read only for an internal_error answer.
	Errors setup.DBErrors
	// Password is what the pool logs in with; Reset drops its connections
	// so the next ones log in with a promoted password.
	Password interface{ Set(string) }
	Reset    func()
	Log      *slog.Logger

	mu sync.Mutex
	// pending is the .pending credential last seen to log in and find the
	// pending setup recorded: what Finish promotes.
	pending *pendingCredential
	// promoted is the setup whose credential was promoted last: a second
	// finisher of the same setup (concurrent calls) finds it done.
	promoted string
	// warnedOtherDB is the setup the other-database warning was logged for,
	// so it is logged once per setup, not on every call.
	warnedOtherDB uuid.UUID
}

type pendingCredential struct {
	setupID  string
	file     os.FileInfo
	password string
}

// errInvalidCredential stands for a parse error, which can echo the URL and
// its password.
var errInvalidCredential = errors.New("the credential is not a valid Postgres URL")

// PendingRecorded logs in with <credentialFile>.pending, read without
// following a link and only when this process's user owns it with mode
// 0600, when it names the same database and role as the engine's own.
func (f *Finisher) PendingRecorded(ctx context.Context, id uuid.UUID) (recorded, has bool, err error) {
	path := f.CredFile + config.PendingSuffix
	dsn, fi, err := f.Files.ReadPending(maxPendingBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, false, nil
	case err != nil:
		return false, false, err
	}
	target, password, err := f.Parse(dsn)
	if err != nil {
		return false, false, fmt.Errorf("%s: %w", path, errInvalidCredential)
	}
	if target != f.Login {
		// A code for another database: basalt init --remote moves it over
		// on its next run, and the engine picks it up when restarted.
		f.warnOtherDB(id, path)
		return false, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pendingLoginTimeout)
	defer cancel()
	conn, err := f.Connect(ctx, dsn)
	switch {
	case setup.LoginRefused(f.Errors, err):
		return false, false, nil // the person has not run the code yet
	case err != nil:
		return false, false, err
	}
	defer conn.Close(ctx)
	recorded, err = conn.SetupRecorded(ctx, id)
	if err != nil {
		return false, true, err
	}
	if recorded {
		f.mu.Lock()
		f.pending = &pendingCredential{setupID: id.String(), file: fi, password: password}
		f.mu.Unlock()
	}
	return recorded, true, nil
}

// Finish takes the agent's lock, the one basalt init --remote takes, then
// promotes the .pending credential when asked and clears setup id from
// engine.json. A lock held elsewhere is an error: the next call tries again.
func (f *Finisher) Finish(_ context.Context, id string, promote bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	unlock, err := f.Files.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if promote {
		if err := f.promote(id); err != nil {
			return err
		}
	}
	cleared, err := f.Files.ClearSetup(f.Agent, id)
	if err != nil {
		return fmt.Errorf("clear the setup from %s: %w", f.ConfigPath, err)
	}
	f.Log.Info("the agent's setup is recorded; serving it", "setupId", id, "clearedFromConfig", cleared, "promotedCredential", promote)
	return nil
}

// warnOtherDB logs, once per setup, that the .pending credential names
// another database or role than the engine's.
func (f *Finisher) warnOtherDB(id uuid.UUID, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.warnedOtherDB == id {
		return
	}
	f.warnedOtherDB = id
	f.Log.Warn("the pending credential names another database or role than the engine's; restart the engine after the setup ran",
		"path", path, "setupId", id)
}

// promote moves the .pending credential of setup id over the credential
// file, once the .pending path still names the file that logged in (a
// regular file with one link), then has the pool log in with its password.
// A setup whose credential was already promoted (by a concurrent call) is
// done. f.mu is held.
func (f *Finisher) promote(id string) error {
	p := f.pending
	switch {
	case p == nil && f.promoted == id:
		return nil
	case p == nil || p.setupID != id:
		return errors.New("no pending credential logged in for this setup")
	}
	if err := f.Files.Promote(p.file); err != nil {
		return err
	}
	f.pending, f.promoted = nil, id
	f.Password.Set(p.password)
	f.Reset()
	return nil
}
