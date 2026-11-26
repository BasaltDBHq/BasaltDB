//go:build unix

package credfiles

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// The suffixes of init --remote's files next to the credential file.
const (
	pendingSuffix = ".pending"
	lockSuffix    = ".lock"
)

// osHost reaches the real machine, as the CLI's host does.
type osHost struct{}

func (osHost) OSOpenTrustedDir(dir string, owner int, create bool) (TrustedDir, error) {
	return osservice.OpenTrustedDirPort(dir, owner, create)
}

func (osHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return osservice.OpenTrustedFile(path, owner)
}

func (osHost) OSLookupUID(name string) int { return osservice.LookupUID(name) }

func me(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)
	return u.Username
}

// Root hands the credential files it writes to the owner of agents/, the
// engine's user, and never to root.
func TestCredentialOwner(t *testing.T) {
	t.Parallel()
	require.Equal(t, -1, CredentialOwner(0), "a root-owned agents/ keeps root's files")
	require.Equal(t, 1001, CredentialOwner(1001))
}

// As root, init --remote reads a credential file owned by root or by the
// owner of agents/, and no one else's.
func TestRootCredFilesReadsRootOrTheDirOwner(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "agents")
	r, err := openRootFiles(dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer r.Close()
	me := os.Geteuid()
	require.Equal(t, me, r.owner, "agents/ is this user's")
	require.Equal(t, me, r.self)

	r.self, r.owner = me+1, me // root is another uid; agents/ is this user's
	fi, err := os.Stat(dir)
	require.NoError(t, err)
	for uid, want := range map[int]bool{me + 1: true, me: true, me + 2: false} {
		err := ownerfile.CheckOwner(ownedBy(t, fi, uid), r.rules())
		require.Equal(t, want, err == nil, "%d: %v", uid, err)
	}
	r.owner = -1 // a root-owned agents/
	err = ownerfile.CheckOwner(ownedBy(t, fi, me), r.rules())
	require.EqualError(t, err, fmt.Sprintf("owned by uid %d, not root", me))
}

// ownedBy is fi with its owner set to uid.
func ownedBy(t *testing.T, fi os.FileInfo, uid int) os.FileInfo {
	t.Helper()
	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid = uint32(uid)
	return statInfo{FileInfo: fi, st: &st}
}

type statInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (s statInfo) Sys() any { return s.st }

// A credential file the engine's user wrote is not root's to trust: pgx
// reads files for the caller from some parameters (passfile, sslkey, ...)
// and falls back to root's ~/.pgpass without a password, so root takes only
// a URL with a password and parameters that read no file.
func TestRootCredFilesChecksTheOwnersCredential(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "agents")
	r, err := openRootFiles(dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer r.Close()
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
		_, _, err := r.Read(cred)
		require.NoError(t, err, tc.dsn)

		r.self = os.Geteuid() + 1 // the owner of agents/ wrote it
		got, _, err := r.Read(cred)
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
	r, err := openRootFiles(dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer r.Close()
	r.owner = os.Geteuid() + 1
	require.Error(t, r.Write(filepath.Join(dir, "bot.url.pending"), []byte("x\n")))
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
	files, err := openRootFiles(dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.Close()
	owner := files.owner

	unlock, err := files.Lock(cred + lockSuffix)
	require.NoError(t, err)
	defer unlock()
	require.NoError(t, files.Write(cred, []byte("postgres://basalt_agent_bot:one@db.example.com/crm\n")))
	require.NoError(t, files.Write(cred+pendingSuffix, []byte("postgres://basalt_agent_bot:two@db.example.com/crm\n")))
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
	files, err := openRootFiles(dir, trustedOwnerOf(t, dir))
	require.NoError(t, err)
	defer files.Close()
	cred := filepath.Join(dir, "bot.url")
	unlock, err := files.Lock(cred + lockSuffix)
	require.NoError(t, err)
	unlock()
	require.NoError(t, files.Write(cred+pendingSuffix, []byte("postgres://basalt_agent_bot:two@db.example.com/crm\n")))
	require.NoError(t, files.Rename(cred+pendingSuffix, cred))
	for _, p := range []string{cred, cred + lockSuffix} {
		requireOwner(t, p, engineUID)
	}
	_, _, err = files.Read(cred)
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

// trustedOwnerOf is init --remote's trusted owner (RootTrustedOwner) for
// the agents directory dir.
func trustedOwnerOf(t *testing.T, dir string) int {
	t.Helper()
	owner, err := RootTrustedOwner(filepath.Dir(dir))
	require.NoError(t, err)
	return owner
}

// openRootFiles is OpenRootCredFiles as the RootCredFiles it opens, for
// the tests that read and set its fields.
func openRootFiles(dir string, trusted int) (RootCredFiles, error) {
	files, err := OpenRootCredFiles(osHost{}, dir, trusted)
	if err != nil {
		return RootCredFiles{}, err
	}
	return files.(RootCredFiles), nil
}
