package osservice

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A directory on the way that an ACL entry lets others write is refused as
// a group- or other-writable mode is, though its mode stays 0700. A deny
// entry, as macOS puts on every home directory, passes.
func TestOpenTrustedRefusesADirectoryAnACLOpens(t *testing.T) {
	dir := realTempDir(t)
	sub := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(sub, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "f"), []byte("ok"), 0o600))
	acl := func(args ...string) {
		out, err := exec.Command("/bin/chmod", append(args, sub)...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", sub).Run() })

	acl("+a", "group:everyone deny delete")
	f, err := OpenTrustedFile(filepath.Join(sub, "f"), keepID)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	acl("+a", "everyone allow add_file,delete_child")
	_, err = OpenTrustedFile(filepath.Join(sub, "f"), keepID)
	require.ErrorContains(t, err, sub+" has an ACL entry that lets another user write it")

	acl("-N")
	f, err = OpenTrustedFile(filepath.Join(sub, "f"), keepID)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
