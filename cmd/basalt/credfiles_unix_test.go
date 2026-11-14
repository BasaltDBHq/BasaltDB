//go:build unix

package main

import (
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
	ok, _ = r.ownedBy(uint32(me))
	require.True(t, ok)
	ok, _ = r.ownedBy(uint32(me + 1))
	require.False(t, ok)

	r.owner = -1 // a root-owned agents/
	ok, _ = r.ownedBy(uint32(me + 1))
	require.False(t, ok)
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
