//go:build unix

package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/config"
)

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
			SetupID: id.String(), Kind: guard.SetupAgent,
			GuardVersion: guard.LatestVersion(), ExpiresAt: "2026-11-13T10:00:00Z", Code: "basalt-setup.1.abc.def", Fingerprint: "a1b2",
		},
	}))
	return cfgPath, credFile
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
	require.NoError(t, config.WriteFile(credFile+pendingSuffix, []byte("postgres://bt_agent_bot:new@db:5432/app\n")))
	swap()

	pw := &recordingPassword{}
	f := &setupFinisher{
		configPath: cfgPath, agent: "bot", credFile: credFile, files: files,
		login: loginTarget{host: "db", port: 5432, database: "app", user: "bt_agent_bot"}, password: pw, reset: func() {},
		log: slog.New(slog.DiscardHandler),
	}
	// What PendingRecorded keeps once the .pending login finds the setup
	// recorded, read through the opened agents/.
	dsn, fi, err := files.readPending()
	require.NoError(t, err)
	require.Equal(t, "postgres://bt_agent_bot:new@db:5432/app", dsn)
	f.pending = &pendingCredential{setupID: id.String(), file: fi, password: "new"}
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
	require.NoError(t, os.Symlink(filepath.Join(agents, "x"), credFile+lockSuffix+".tmp"))
	require.NoError(t, os.Remove(credFile+lockSuffix))
	require.NoError(t, os.Rename(credFile+lockSuffix+".tmp", credFile+lockSuffix))
	_, err = files.lock()
	var unusable *config.LockUnusableError
	require.True(t, errors.As(err, &unusable), err)
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

	cleared, err := files.clearSetup("bot", id.String())
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
		for _, name := range []string{credFile, credFile + pendingSuffix} {
			require.NoError(t, os.WriteFile(name, []byte(tc.dsn+"\n"), config.FileMode))
		}
		read := func() []error {
			_, err := files.readCredential()
			_, _, perr := files.readPending()
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
