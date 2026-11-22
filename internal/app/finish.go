package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// The files basalt init --remote keeps next to an agent's credential file
// (CONTRACT.md, basalt init --remote): a rotated password waiting for the
// person's setup, and the lock both init and the engine take.
const (
	pendingSuffix = ".pending"
	lockSuffix    = ".lock"
)

// pendingLoginTimeout bounds the login with the .pending credential.
const pendingLoginTimeout = 15 * time.Second

// agentLogin is the agent's own connection the finisher reads with.
type agentLogin interface {
	guard.Querier
	Close(ctx context.Context) error
}

func connectAgent(ctx context.Context, dsn string) (agentLogin, error) {
	return pgdial.Connect(ctx, dsn)
}

// setupFinisher is agent.SetupFinisher for one agent of this engine: its
// config entry, its credential file and the pool the engine serves it on.
type setupFinisher struct {
	configPath, agent, credFile string
	// files reaches the credential files and the config: by path, or for
	// an engine running as root through directories it opened without
	// following a link (rootFiles). nil: by path.
	files agentFiles
	// login is who the engine's credential logs in as and where: a
	// .pending credential is used only for the same.
	login loginTarget
	// password is what the pool logs in with; reset drops its connections
	// so the next ones log in with a promoted password.
	password interface{ Set(string) }
	reset    func()
	connect  func(ctx context.Context, dsn string) (agentLogin, error)
	log      *slog.Logger

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

// loginTarget is a credential without its password.
type loginTarget struct {
	host     string
	port     uint16
	database string
	user     string
}

func targetOf(cc *pgx.ConnConfig) loginTarget {
	return loginTarget{host: cc.Host, port: cc.Port, database: cc.Database, user: cc.User}
}

// errInvalidCredential stands for a parse error, which can echo the URL and
// its password.
var errInvalidCredential = errors.New("the credential is not a valid Postgres URL")

// PendingRecorded logs in with <credentialFile>.pending, read without
// following a link and only when this process's user owns it with mode
// 0600, when it names the same database and role as the engine's own.
func (f *setupFinisher) PendingRecorded(ctx context.Context, id uuid.UUID) (recorded, has bool, err error) {
	path := f.credFile + pendingSuffix
	dsn, fi, err := f.fs().readPending()
	switch {
	case errNotExist(err):
		return false, false, nil
	case err != nil:
		return false, false, err
	}
	cc, err := pgdial.ConnConfig(dsn)
	if err != nil {
		return false, false, fmt.Errorf("%s: %w", path, errInvalidCredential)
	}
	if targetOf(cc) != f.login {
		// A code for another database: basalt init --remote moves it over
		// on its next run, and the engine picks it up when restarted.
		f.warnOtherDB(id, path)
		return false, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pendingLoginTimeout)
	defer cancel()
	conn, err := f.connect(ctx, dsn)
	// The service reads store errors mapped (postgres.MapError).
	err = postgres.MapError(err)
	switch {
	case agent.LoginRefused(err):
		return false, false, nil // the person has not run the code yet
	case err != nil:
		return false, false, err
	}
	defer conn.Close(ctx)
	recorded, err = guard.SetupRecorded(ctx, conn, id)
	if err != nil {
		return false, true, err
	}
	if recorded {
		f.mu.Lock()
		f.pending = &pendingCredential{setupID: id.String(), file: fi, password: cc.Password}
		f.mu.Unlock()
	}
	return recorded, true, nil
}

// Finish takes the agent's lock, the one basalt init --remote takes, then
// promotes the .pending credential when asked and clears setup id from
// engine.json. A lock held elsewhere is an error: the next call tries again.
func (f *setupFinisher) Finish(_ context.Context, id string, promote bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	unlock, err := f.fs().lock()
	if err != nil {
		return err
	}
	defer unlock()
	if promote {
		if err := f.promote(id); err != nil {
			return err
		}
	}
	cleared, err := f.fs().clearSetup(f.agent, id)
	if err != nil {
		return fmt.Errorf("clear the setup from %s: %w", f.configPath, err)
	}
	f.log.Info("the agent's setup is recorded; serving it", "setupId", id, "clearedFromConfig", cleared, "promotedCredential", promote)
	return nil
}

// fs is the finisher's files: by path unless set.
func (f *setupFinisher) fs() agentFiles {
	if f.files != nil {
		return f.files
	}
	return pathFiles{configPath: f.configPath, credFile: f.credFile}
}

// warnOtherDB logs, once per setup, that the .pending credential names
// another database or role than the engine's.
func (f *setupFinisher) warnOtherDB(id uuid.UUID, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.warnedOtherDB == id {
		return
	}
	f.warnedOtherDB = id
	f.log.Warn("the pending credential names another database or role than the engine's; restart the engine after the setup ran",
		"path", path, "setupId", id)
}

// promote moves the .pending credential of setup id over the credential
// file, once the .pending path still names the file that logged in (a
// regular file with one link), then has the pool log in with its password.
// A setup whose credential was already promoted (by a concurrent call) is
// done. f.mu is held.
func (f *setupFinisher) promote(id string) error {
	p := f.pending
	switch {
	case p == nil && f.promoted == id:
		return nil
	case p == nil || p.setupID != id:
		return errors.New("no pending credential logged in for this setup")
	}
	if err := f.fs().promote(p.file); err != nil {
		return err
	}
	f.pending, f.promoted = nil, id
	f.password.Set(p.password)
	f.reset()
	return nil
}
