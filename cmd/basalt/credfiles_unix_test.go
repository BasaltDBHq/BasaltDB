//go:build unix

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// Root hands the credential files it writes to the owner of agents/, the
// engine's user, and never to root.
func TestCredentialOwner(t *testing.T) {
	t.Parallel()
	require.Equal(t, -1, credentialOwner(0), "a root-owned agents/ keeps root's files")
	require.Equal(t, 1001, credentialOwner(1001))
}

// As root, init --remote reads a credential file owned by root or by the
// owner of agents/, and no one else's.
func TestRootCredFilesReadsRootOrTheDirOwner(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "agents")
	files, err := openRootCredFiles(appSetupHost{}, dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.close()
	r, ok := files.(rootCredFiles)
	require.True(t, ok)
	me := os.Geteuid()
	require.Equal(t, me, r.owner, "agents/ is this user's")
	require.Equal(t, me, r.self)

	r.self, r.owner = me+1, me // root is another uid; agents/ is this user's
	for uid, want := range map[int]bool{me + 1: true, me: true, me + 2: false} {
		ok, _ := r.ownedBy(uint32(uid))
		require.Equal(t, want, ok, uid)
	}
	r.owner = -1 // a root-owned agents/
	ok, _ = r.ownedBy(uint32(me))
	require.False(t, ok)
}

// A credential file the engine's user wrote is not root's to trust: pgx
// reads files for the caller from some parameters (passfile, sslkey, ...)
// and falls back to root's ~/.pgpass without a password, so root takes only
// a URL with a password and parameters that read no file.
func TestRootCredFilesChecksTheOwnersCredential(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "agents")
	files, err := openRootCredFiles(appSetupHost{}, dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.close()
	r := files.(rootCredFiles)
	cred := filepath.Join(dir, "bot.url")
	const refused = "takes from it only a postgres:// or postgresql:// URL"
	for _, tc := range []struct {
		dsn string
		ok  bool
	}{
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?sslmode=verify-full&channel_binding=require&application_name=x", ok: true},
		{dsn: "postgresql://basalt_agent_bot:pw@db.example.com/crm", ok: true},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?sslmode=prefer", ok: true},
		{dsn: "postgres://basalt_agent_bot@db.example.com:5432/crm"},
		{dsn: "postgres://basalt_agent_bot:@db.example.com:5432/crm"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?passfile=/root/.pgpass"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?sslmode=require&sslkey=/k&service=x"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?sslrootcert=/tmp/fifo"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?servicefile=/x&sslcert=/y&sslcrl=/z&sslpassword=s"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?host=evil.example.com"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com:5432/crm?options=-c%20x%3Dy"},
		// Where Go's URL parser and pgx's disagree.
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com/crm?application_name=a#&password=&host=evil.example.com&passfile=/root/.pgpass"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com/crm#?passfile=/root/.pgpass&password="},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com/crm?sslmode=require&sslrootcert=/nonexistent/x;"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com/crm?sslmode=require&pass%66ile=/root/.pgpass"},
		{dsn: "POSTGRES://basalt_agent_bot:pw@db.example.com/crm password= host=evil.example.com passfile=/root/.pgpass"},
		{dsn: "postgres://basalt_agent_bot:pw@db.example.com,evil.example.com/crm"},
		{dsn: "host=db.example.com password=pw dbname=crm"},
	} {
		require.NoError(t, os.WriteFile(cred, []byte(tc.dsn+"\n"), config.FileMode))

		r.self = os.Geteuid() // root wrote it: taken as it is
		_, _, err := r.read(cred)
		require.NoError(t, err, tc.dsn)

		r.self = os.Geteuid() + 1 // the owner of agents/ wrote it
		got, _, err := r.read(cred)
		if tc.ok {
			require.NoError(t, err, tc.dsn)
			require.Equal(t, tc.dsn, got)
			continue
		}
		require.ErrorContains(t, err, refused, tc.dsn)
		require.NotContains(t, err.Error(), ":pw", "the password is not echoed")
	}
}

// A hand-over this process may not make (it is not root) fails the write
// and leaves nothing: write gives the file to the owner of agents/.
func TestRootCredFilesWriteHandsOver(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root may give a file away")
	}
	dir := filepath.Join(t.TempDir(), "agents")
	files, err := openRootCredFiles(appSetupHost{}, dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.close()
	r := files.(rootCredFiles)
	r.owner = os.Geteuid() + 1
	require.Error(t, r.write(filepath.Join(dir, "bot.url.pending"), []byte("x\n")))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// What root writes in agents/ (the credential, its .pending and the lock)
// belongs to the directory's owner, so the engine, running as that user,
// reads the .pending credential with its own checks and can promote it.
func TestRootCredFilesHandsTheFilesToTheDirOwner(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "agents")
	cred := filepath.Join(dir, "bot.url")
	files, err := openRootCredFiles(appSetupHost{}, dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.close()
	owner := files.(rootCredFiles).owner

	unlock, err := files.lock(cred + lockSuffix)
	require.NoError(t, err)
	defer unlock()
	require.NoError(t, files.write(cred, []byte("postgres://basalt_agent_bot:one@db.example.com/crm\n")))
	require.NoError(t, files.write(cred+pendingSuffix, []byte("postgres://basalt_agent_bot:two@db.example.com/crm\n")))
	for _, p := range []string{cred, cred + pendingSuffix, cred + lockSuffix} {
		requireOwner(t, p, owner)
	}
	if os.Geteuid() != owner {
		return
	}
	// The engine's read before it promotes (internal/app, finish.go).
	dsn, _, err := config.ReadOwnCredential(cred + pendingSuffix)
	require.NoError(t, err)
	require.Contains(t, dsn, ":two@")
}

// Run as root: agents/ owned by another user gets that user's files.
func TestRootCredFilesHandOverAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const engineUID = 65534
	base := t.TempDir()
	require.NoError(t, os.Chmod(base, 0o755))
	dir := filepath.Join(base, "agents")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Chown(dir, engineUID, -1))
	files, err := openRootCredFiles(appSetupHost{}, dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.close()
	cred := filepath.Join(dir, "bot.url")
	unlock, err := files.lock(cred + lockSuffix)
	require.NoError(t, err)
	unlock()
	require.NoError(t, files.write(cred+pendingSuffix, []byte("postgres://basalt_agent_bot:two@db.example.com/crm\n")))
	require.NoError(t, files.rename(cred+pendingSuffix, cred))
	for _, p := range []string{cred, cred + lockSuffix} {
		requireOwner(t, p, engineUID)
	}
	_, _, err = files.read(cred)
	require.NoError(t, err, "root reads the file it handed over")
}

func requireOwner(t *testing.T, path string, uid int) {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equal(t, uint32(uid), st.Uid, path)
}

// trustedOwnerOf is rootTrustedOwner for the agents directory dir.
func trustedOwnerOf(t *testing.T, dir string) int {
	t.Helper()
	owner, err := rootTrustedOwner(filepath.Dir(dir))
	require.NoError(t, err)
	return owner
}

// As root, init --remote writes engine.json through the config directory
// it opened in paths: a config directory swapped for a symlink before the
// write (the engine's user owning a directory above it) redirects nothing.
func TestRootConfigDirWritesWhereItOpened(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir, elsewhere := filepath.Join(root, "basalt"), filepath.Join(root, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	trusted, err := rootTrustedOwner(dir)
	require.NoError(t, err)
	d, err := openRootConfigDir(appSetupHost{}, dir, trusted)
	require.NoError(t, err)
	defer d.close()

	require.NoError(t, os.Rename(dir, dir+".moved"))
	require.NoError(t, os.Symlink(elsewhere, dir))
	_, err = d.upsert("engine.json", config.Settings{SocketDir: "/run/basalt"}, config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore(filepath.Join(dir, "agents", "bot.url"))})
	require.NoError(t, err)
	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries)
	require.FileExists(t, filepath.Join(dir+".moved", "engine.json"))

	_, err = openRootConfigDir(appSetupHost{}, dir, trusted)
	require.ErrorContains(t, err, "a symlink is refused")
}

// As root, the engine's key goes only in a state directory the config
// directory's owner owns: /usr (root's) is refused for a config directory
// this user owns, and nothing is made there.
func TestRootEngineKeyNeedsTheConfigOwnersStateDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root owns both")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "basalt")
	trusted, err := rootTrustedOwner(dir)
	require.NoError(t, err)
	d, err := openRootConfigDir(appSetupHost{}, dir, trusted)
	require.NoError(t, err)
	defer d.close()
	_, err = rootEngineKey(appSetupHost{}, "/usr", runtime.GOOS, d, time.Now)
	require.ErrorContains(t, err, fmt.Sprintf("the state directory /usr is owned by uid 0, not uid %d (the owner of the config directory %s)", os.Geteuid(), dir))
	require.NoFileExists(t, filepath.Join("/usr", channel.KeyFileName))

	// Its own state directory: the key is made there.
	state := filepath.Join(dir, "state")
	require.NoError(t, os.Mkdir(state, 0o700))
	spki, err := rootEngineKey(appSetupHost{}, state, runtime.GOOS, d, time.Now)
	require.NoError(t, err)
	require.NotEmpty(t, spki)
}

// A missing state directory: the service manager makes only the default
// one; one next to a --config is made by hand.
func TestMissingStateDirHint(t *testing.T) {
	t.Parallel()
	def := config.DefaultStateDir(runtime.GOOS)
	require.ErrorContains(t, missingStateDir(def, runtime.GOOS, 998), "start the engine's service once")
	err := missingStateDir("/srv/bot/state", runtime.GOOS, 998)
	require.ErrorContains(t, err, "sudo install -d -m 0700 -o 998 /srv/bot/state")
	require.NotContains(t, err.Error(), "service once")
}

// As root, writeConfig writes engine.json through the config directory
// paths opened, not by path: the directory swapped for a symlink before the
// write redirects nothing.
func TestRootWriteConfigUsesTheOpenedConfigDir(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir, elsewhere := filepath.Join(root, "basalt"), filepath.Join(root, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	trusted, err := rootTrustedOwner(dir)
	require.NoError(t, err)
	d, err := openRootConfigDir(appSetupHost{}, dir, trusted)
	require.NoError(t, err)
	defer d.close()
	var stderr bytes.Buffer
	r := &remoteInit{
		c: &cliIO{stderr: &stderr}, configDir: d, osUser: "bot", credFile: filepath.Join(dir, "agents", "bot.url"),
		f:        remoteFlags{agent: "bot", configPath: filepath.Join(dir, "engine.json")},
		settings: config.Settings{SocketDir: "/run/basalt"},
	}
	require.NoError(t, os.Rename(dir, dir+".moved"))
	require.NoError(t, os.Symlink(elsewhere, dir))
	require.NoError(t, r.writeConfig(nil))
	requireEmptyDir(t, elsewhere)
	c, err := config.Load(filepath.Join(dir+".moved", "engine.json"))
	require.NoError(t, err)
	require.Equal(t, "bot", c.Agents[0].Name)
}
