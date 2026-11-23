//go:build unix

package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// recordingPassword records the passwords the pool is switched to.
type recordingPassword struct{ set []string }

func (p *recordingPassword) Set(pw string) { p.set = append(p.set, pw) }

// recordedLogin is an agent login that finds every setup recorded.
type recordedLogin struct{}

func (recordedLogin) SetupRecorded(context.Context, uuid.UUID) (bool, error) { return true, nil }
func (recordedLogin) Close(context.Context) error                            { return nil }

// rootLayout is a config directory as basalt init writes it: engine.json
// with agent bot and its pending setup, and agents/bot.url.
func rootLayout(t *testing.T, id uuid.UUID) (cfgPath, credFile string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "basalt")
	cfgPath, credFile = filepath.Join(dir, "engine.json"), filepath.Join(dir, "agents", "bot.url")
	require.NoError(t, config.WriteFile(credFile, []byte("postgres://bt_agent_bot:old@db:5432/app\n")))
	require.NoError(t, config.UpsertAgent(cfgPath, config.Settings{SocketDir: "/run/basalt"}, config.Agent{
		Name: "bot", OSUser: "bot", Store: config.PostgresStore(credFile), Setup: &config.Setup{
			SetupID: id.String(), Kind: guardmodel.SetupAgent,
			GuardVersion: guard.LatestVersion(), ExpiresAt: "2026-11-13T10:00:00Z", Code: "basalt-setup.1.abc.def", Fingerprint: "a1b2",
		},
	}))
	return cfgPath, credFile
}

// The engine's root adapter opens agents/ and never makes it; only basalt
// init may create it.
func TestRootEngineNeverCreatesTheAgentsDirectory(t *testing.T) {
	t.Parallel()
	cfgPath, credFile := rootLayout(t, uuid.Must(uuid.NewV7()))
	agents := filepath.Dir(credFile)
	require.NoError(t, os.RemoveAll(agents))
	_, err := openRootFiles(cfgPath, "bot", credFile)
	require.Error(t, err)
	_, err = os.Lstat(agents)
	require.ErrorIs(t, err, os.ErrNotExist, "agents/ is not created")
}

// As root the engine reads only agents/<agent>.url next to its config: a
// credentialFile anywhere else is refused before anything is read.
func TestRootEngineUsesOnlyTheComputedCredentialPath(t *testing.T) {
	t.Parallel()
	cfgPath, credFile := rootLayout(t, uuid.Must(uuid.NewV7()))
	elsewhere := filepath.Join(filepath.Dir(cfgPath), "other.url")
	require.NoError(t, config.WriteFile(elsewhere, []byte("postgres://x:y@h/db\n")))
	for _, named := range []string{elsewhere, filepath.Join(filepath.Dir(cfgPath), "agents", "other.url")} {
		_, err := agentFilesFor(agentEnv{configPath: cfgPath, asRoot: true}, config.Agent{Name: "bot", Store: config.PostgresStore(named)})
		require.ErrorContains(t, err, "as root, basalt engine uses only that path", named)
	}
	// A spelling of the same path is the same path.
	files, err := agentFilesFor(agentEnv{configPath: cfgPath, asRoot: true},
		config.Agent{Name: "bot", Store: config.PostgresStore(filepath.Join(filepath.Dir(credFile), "sub", "..", "bot.url"))})
	require.NoError(t, err)
	defer files.close()
	dsn, err := files.readCredential()
	require.NoError(t, err)
	require.Equal(t, "postgres://bt_agent_bot:old@db:5432/app", dsn)

	// Not as root, the config's path as it is.
	files, err = agentFilesFor(agentEnv{configPath: cfgPath}, config.Agent{Name: "bot", Store: config.PostgresStore(elsewhere)})
	require.NoError(t, err)
	_, ok := files.(pathFiles)
	require.True(t, ok)
}

// As root an agents/ swapped for a symlink is refused at start; after the
// start, the engine keeps working in the directories it opened, so a swap
// then redirects nothing; a symlinked .lock is a *LockUnusableError.
func TestRootEngineReachesItsFilesThroughTheOpenedDirectories(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	cfgPath, credFile := rootLayout(t, id)
	agents := filepath.Dir(credFile)
	elsewhere := filepath.Join(filepath.Dir(filepath.Dir(cfgPath)), "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))

	swap := func() {
		require.NoError(t, os.Rename(agents, agents+".moved"))
		require.NoError(t, os.Symlink(elsewhere, agents))
	}
	unswap := func() {
		require.NoError(t, os.Remove(agents))
		require.NoError(t, os.Rename(agents+".moved", agents))
	}
	swap()
	_, err := openRootFiles(cfgPath, "bot", credFile)
	require.ErrorContains(t, err, "a symlink is refused")
	unswap()

	files, err := openRootFiles(cfgPath, "bot", credFile)
	require.NoError(t, err)
	defer files.close()
	require.NoError(t, config.WriteFile(credFile+handoff.PendingSuffix, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	swap()

	pw := &recordingPassword{}
	var dialed string
	f := &handoff.Finisher{
		ConfigPath: cfgPath, Agent: "bot", CredFile: credFile, Files: files,
		Login: handoff.LoginTarget{Host: "db", Port: 5432, Database: "app", User: "bt_agent_bot"}, Parse: parseLogin,
		Connect: func(_ context.Context, dsn string) (handoff.AgentLogin, error) {
			dialed = dsn
			return recordedLogin{}, nil
		},
		Password: pw, Reset: func() {}, Log: slog.New(slog.DiscardHandler),
	}
	// The .pending login, read through the opened agents/, finds the setup
	// recorded.
	recorded, has, err := f.PendingRecorded(context.Background(), id)
	require.NoError(t, err)
	require.True(t, recorded)
	require.True(t, has)
	require.Equal(t, "postgres://bt_agent_bot:new@db:5432/app", dialed)
	require.NoError(t, f.Finish(context.Background(), id.String(), true))
	require.Equal(t, []string{"new"}, pw.set)

	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries, "nothing reached the symlink's target")
	raw, err := os.ReadFile(filepath.Join(agents+".moved", "bot.url"))
	require.NoError(t, err)
	require.Equal(t, "postgres://bt_agent_bot:new@db:5432/app\n", string(raw), "promoted in the directory opened")
	c, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Nil(t, c.Agents[0].Setup, "the setup is cleared through the opened config directory")

	unswap()
	require.NoError(t, os.Symlink(filepath.Join(agents, "x"), credFile+handoff.LockSuffix+".tmp"))
	require.NoError(t, os.Remove(credFile+handoff.LockSuffix))
	require.NoError(t, os.Rename(credFile+handoff.LockSuffix+".tmp", credFile+handoff.LockSuffix))
	_, err = files.Lock()
	var unusable *config.LockUnusableError
	require.True(t, errors.As(err, &unusable), err)
}

// The engine's own file adapters (by path, and through the directories a
// root engine opens) refuse to promote a .pending that changed after it
// logged in: replaced by another file, or given a second hard link. Finish
// fails, the credential file keeps its password, the pool's is not
// switched, and the setup stays in the config.
func TestTheEngineDoesNotPromoteAPendingCredentialChangedAfterItsLogin(t *testing.T) {
	t.Parallel()
	const pending = "postgres://bt_agent_bot:new@db:5432/app\n"
	changes := map[string]func(t *testing.T, path string){
		"replaced": func(t *testing.T, path string) {
			t.Helper()
			require.NoError(t, config.WriteFile(path, []byte("postgres://bt_agent_bot:planted@db:5432/app\n")))
		},
		"hard linked": func(t *testing.T, path string) {
			t.Helper()
			require.NoError(t, os.Link(path, path+".link"))
		},
	}
	adapters := map[string]func(t *testing.T, cfgPath, credFile string) agentFiles{
		"path": func(_ *testing.T, cfgPath, credFile string) agentFiles {
			return pathFiles{configPath: cfgPath, credFile: credFile}
		},
		"root": func(t *testing.T, cfgPath, credFile string) agentFiles {
			t.Helper()
			files, err := openRootFiles(cfgPath, "bot", credFile)
			require.NoError(t, err)
			return files
		},
	}
	for adapter, open := range adapters {
		for change, apply := range changes {
			t.Run(adapter+" "+change, func(t *testing.T) {
				t.Parallel()
				id := uuid.Must(uuid.NewV7())
				cfgPath, credFile := rootLayout(t, id)
				files := open(t, cfgPath, credFile)
				defer files.close()
				require.NoError(t, config.WriteFile(credFile+handoff.PendingSuffix, []byte(pending)))
				pw := &recordingPassword{}
				f := &handoff.Finisher{
					ConfigPath: cfgPath, Agent: "bot", CredFile: credFile, Files: files,
					Login: handoff.LoginTarget{Host: "db", Port: 5432, Database: "app", User: "bt_agent_bot"}, Parse: parseLogin,
					Connect:  func(context.Context, string) (handoff.AgentLogin, error) { return recordedLogin{}, nil },
					Password: pw, Reset: func() {}, Log: slog.New(slog.DiscardHandler),
				}
				recorded, has, err := f.PendingRecorded(context.Background(), id)
				require.NoError(t, err)
				require.True(t, recorded)
				require.True(t, has)

				apply(t, credFile+handoff.PendingSuffix)
				require.Error(t, f.Finish(context.Background(), id.String(), true))
				require.Empty(t, pw.set, "the pool keeps its password")
				raw, err := os.ReadFile(credFile)
				require.NoError(t, err)
				require.Equal(t, "postgres://bt_agent_bot:old@db:5432/app\n", string(raw), "the credential file is unchanged")
				c, err := config.Load(cfgPath)
				require.NoError(t, err)
				require.NotNil(t, c.Agents[0].Setup, "the setup is not cleared")
			})
		}
	}
}

// The engine's own file adapters refuse a .pending file over 4096 bytes as
// stored, its newline included, before anything logs in with it, as basalt
// init --remote does; at 4096 bytes it is read.
func TestTheEngineRefusesAPendingCredentialOver4096Bytes(t *testing.T) {
	t.Parallel()
	pw := func(n int) string { return strings.Repeat("p", n-len("postgres://bt_agent_bot:@db:5432/app")) }
	over := "postgres://bt_agent_bot:" + pw(4096) + "@db:5432/app\n"
	require.Len(t, over, 4097)
	exact := "postgres://bt_agent_bot:" + pw(4095) + "@db:5432/app\n"
	require.Len(t, exact, 4096)
	adapters := map[string]func(t *testing.T, cfgPath, credFile string) agentFiles{
		"path": func(_ *testing.T, cfgPath, credFile string) agentFiles {
			return pathFiles{configPath: cfgPath, credFile: credFile}
		},
		"root": func(t *testing.T, cfgPath, credFile string) agentFiles {
			t.Helper()
			files, err := openRootFiles(cfgPath, "bot", credFile)
			require.NoError(t, err)
			return files
		},
	}
	for adapter, open := range adapters {
		t.Run(adapter, func(t *testing.T) {
			t.Parallel()
			id := uuid.Must(uuid.NewV7())
			cfgPath, credFile := rootLayout(t, id)
			files := open(t, cfgPath, credFile)
			defer files.close()
			logins := 0
			f := &handoff.Finisher{
				ConfigPath: cfgPath, Agent: "bot", CredFile: credFile, Files: files,
				Login: handoff.LoginTarget{Host: "db", Port: 5432, Database: "app", User: "bt_agent_bot"}, Parse: parseLogin,
				Connect: func(context.Context, string) (handoff.AgentLogin, error) {
					logins++
					return recordedLogin{}, nil
				},
				Password: &recordingPassword{}, Reset: func() {}, Log: slog.New(slog.DiscardHandler),
			}
			require.NoError(t, config.WriteFile(credFile+handoff.PendingSuffix, []byte(over)))
			_, _, err := f.PendingRecorded(context.Background(), id)
			require.ErrorContains(t, err, "too large")
			require.NotContains(t, err.Error(), "ppp", "the credential is not echoed")
			require.Zero(t, logins, "nothing logs in with it")

			require.NoError(t, config.WriteFile(credFile+handoff.PendingSuffix, []byte(exact)))
			recorded, has, err := f.PendingRecorded(context.Background(), id)
			require.NoError(t, err)
			require.True(t, recorded)
			require.True(t, has)
		})
	}
}

// A root engine clears a setup in the config directory it opened at start:
// the config directory swapped for a symlink afterwards redirects nothing.
func TestRootEngineClearsTheSetupInTheOpenedConfigDirectory(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	cfgPath, credFile := rootLayout(t, id)
	files, err := openRootFiles(cfgPath, "bot", credFile)
	require.NoError(t, err)
	defer files.close()
	dir := filepath.Dir(cfgPath)
	elsewhere := filepath.Join(filepath.Dir(dir), "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	require.NoError(t, os.Rename(dir, dir+".moved"))
	require.NoError(t, os.Symlink(elsewhere, dir))

	cleared, err := files.ClearSetup("bot", id.String())
	require.NoError(t, err)
	require.True(t, cleared)
	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries)
	c, err := config.Load(filepath.Join(dir+".moved", "engine.json"))
	require.NoError(t, err)
	require.Nil(t, c.Agents[0].Setup)
}

// A root engine connects with the credential it reads, and pgx reads files
// for the caller from some parameters: a credential or .pending the owner
// of agents/ wrote must pass the allowlist basalt init --remote applies as
// root (pgdial.CheckForeignDSN). Root's own files are taken as they are.
func TestRootEngineChecksTheOwnersCredential(t *testing.T) {
	t.Parallel()
	cfgPath, credFile := rootLayout(t, uuid.Must(uuid.NewV7()))
	files, err := openRootFiles(cfgPath, "bot", credFile)
	require.NoError(t, err)
	defer files.close()
	r, ok := files.(*rootFiles)
	require.True(t, ok)
	require.Equal(t, os.Geteuid(), r.self)

	const ok1 = "postgres://bt_agent_bot:pw@db.example.com:5432/app?sslmode=verify-full&channel_binding=require"
	for _, tc := range []struct {
		dsn string
		ok  bool
	}{
		{dsn: ok1, ok: true},
		{dsn: "postgres://bt_agent_bot:pw@db.example.com:5432/app?sslrootcert=/root/ca.pem"},
		{dsn: "postgres://bt_agent_bot:pw@db.example.com:5432/app?passfile=/root/.pgpass"},
		{dsn: "postgres://bt_agent_bot@db.example.com:5432/app"},
		{dsn: "host=db.example.com user=bt_agent_bot password=pw sslkey=/root/k"},
	} {
		for _, name := range []string{credFile, credFile + handoff.PendingSuffix} {
			require.NoError(t, os.WriteFile(name, []byte(tc.dsn+"\n"), config.FileMode))
		}
		read := func() []error {
			_, err := files.readCredential()
			_, _, perr := files.ReadPending(4096)
			return []error{err, perr}
		}
		r.self = os.Geteuid() // root wrote them: taken as they are
		for _, err := range read() {
			require.NoError(t, err, tc.dsn)
		}
		r.self = os.Geteuid() + 1 // the owner of agents/ wrote them
		for _, err := range read() {
			if tc.ok {
				require.NoError(t, err, tc.dsn)
				continue
			}
			require.ErrorIs(t, err, pgdial.ErrForeignDSN, tc.dsn)
			require.ErrorContains(t, err, "as root, basalt engine takes from it only")
			require.NotContains(t, err.Error(), ":pw", "the password is not echoed")
		}
	}
}
