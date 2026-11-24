package dial

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// addACL adds a macOS ACL entry to path and strips every entry at cleanup.
func addACL(t *testing.T, path, entry string) {
	t.Helper()
	out, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

func stripACL(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("/bin/chmod", "-N", path).CombinedOutput()
	require.NoError(t, err, string(out))
}

// An ACL entry that opens the socket directory or the socket to others is
// refused at dial and on every later connection, as a mode open to others
// is, though the directory's mode stays 0750. A deny entry passes.
func TestServiceRefusesASocketAnACLOpens(t *testing.T) {
	t.Parallel()
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	dir := shortBase(t)
	require.NoError(t, os.Chmod(dir, 0o750))
	gid := dirGID(t, dir)
	sock := filepath.Join(dir, "p.sock")
	listenUnix(t, sock)
	dialOnce := func() error {
		tr, err := Service(context.Background(), k, serviceEntry(TransportUnix), sock, me, gid, nil)
		if err == nil {
			_ = tr.Close()
		}
		return err
	}
	require.NoError(t, dialOnce())

	addACL(t, dir, "everyone allow list,search,add_file,read,write")
	fi, err := os.Lstat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o750), fi.Mode().Perm(), "the mode stays as it was")
	err = dialOnce()
	require.ErrorIs(t, err, ErrSocketDir, "an ACL opens the directory")
	require.ErrorContains(t, err, "the plugin socket directory "+dir+" has an ACL entry that opens it to others", "the refusal names the ACL")
	stripACL(t, dir)

	addACL(t, dir, "group:everyone deny delete")
	require.NoError(t, dialOnce(), "a deny entry takes nothing away from the rule")
	stripACL(t, dir)

	addACL(t, sock, "everyone allow write")
	require.ErrorIs(t, dialOnce(), ErrSocketACL, "an ACL opens the socket")
	stripACL(t, sock)

	// Opened after the first connection: the next one is refused.
	c, err := net.Dial("unix", sock)
	require.NoError(t, err)
	defer c.Close()
	check := ConnCheck(sock, me, gid, nil)
	require.NoError(t, check(c))
	addACL(t, dir, "everyone allow search")
	require.ErrorIs(t, check(c), ErrSocketDir)
}

// A socket directory made under a base whose ACL passes entries on to new
// directories is refused and removed.
func TestSocketDirRefusesAnInheritedACL(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	addACL(t, base, "everyone allow list,search,directory_inherit,only_inherit")
	_, _, err := socketDir(base)
	require.ErrorIs(t, err, errSocketDirNotPrivate)
	left, err := os.ReadDir(base)
	require.NoError(t, err)
	require.Empty(t, left)
}
