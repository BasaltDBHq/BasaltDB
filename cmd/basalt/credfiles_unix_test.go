//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
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
	files, err := openRootCredFiles(dir)
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
	files, err := openRootCredFiles(dir)
	require.NoError(t, err)
	defer files.close()
	r := files.(rootCredFiles)
	cred := filepath.Join(dir, "bot.url")
	const host = "postgres://basalt_agent_bot%s@db.example.com:5432/crm%s"
	for _, tc := range []struct{ pw, query, err string }{
		{pw: ":pw", query: "?sslmode=verify-full&channel_binding=require&application_name=x"},
		{pw: ":pw"},
		{pw: "", err: "only with a password"},
		{pw: ":", err: "only with a password"},
		{pw: ":pw", query: "?passfile=/root/.pgpass", err: "the parameter passfile"},
		{pw: ":pw", query: "?sslmode=require&sslkey=/etc/ssl/private/k&service=x", err: "the parameter service, sslkey"},
		{pw: ":pw", query: "?sslrootcert=/tmp/fifo", err: "the parameter sslrootcert"},
		{pw: ":pw", query: "?servicefile=/x&sslcert=/y&sslcrl=/z&sslpassword=s", err: "servicefile, sslcert, sslcrl, sslpassword"},
	} {
		dsn := fmt.Sprintf(host, tc.pw, tc.query)
		require.NoError(t, os.WriteFile(cred, []byte(dsn+"\n"), config.FileMode))

		r.self = os.Geteuid() // root wrote it: taken as it is
		_, _, err := r.read(cred)
		require.NoError(t, err, dsn)

		r.self = os.Geteuid() + 1 // the owner of agents/ wrote it
		got, _, err := r.read(cred)
		if tc.err == "" {
			require.NoError(t, err, dsn)
			require.Equal(t, dsn, got)
			continue
		}
		require.ErrorContains(t, err, tc.err, dsn)
		require.NotContains(t, err.Error(), ":pw", "the password is not echoed")
	}
	require.NoError(t, os.WriteFile(cred, []byte("host=db.example.com password=pw\n"), config.FileMode))
	_, _, err = r.read(cred)
	require.ErrorContains(t, err, "only a postgres:// URL")
}

// A hand-over this process may not make (it is not root) fails the write
// and leaves nothing: write gives the file to the owner of agents/.
func TestRootCredFilesWriteHandsOver(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root may give a file away")
	}
	dir := filepath.Join(t.TempDir(), "agents")
	files, err := openRootCredFiles(dir)
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
	files, err := openRootCredFiles(dir)
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
	// The engine's read before it promotes (internal/engine, finish.go).
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
	files, err := openRootCredFiles(dir)
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
