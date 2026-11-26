package plugin

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// An ACL entry that lets everyone add to a 0755 plugin root fails the path
// rule at add, as a group-writable mode does, and nothing is installed.
func TestInstallRefusesARootAnACLOpens(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	require.NoError(t, os.Mkdir(f.root, 0o755))
	out, err := exec.Command("/bin/chmod", "+a", "everyone allow add_file,add_subdirectory,delete_child", f.root).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", f.root).Run() })
	fi, err := os.Lstat(f.root)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "the mode stays as it was")

	_, err = installCopy(f.src, f.root, "", f.trust)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, f.root, ve.File)
	require.Equal(t, pluginmodel.WhyACLWritable, ve.Why)
	require.NotNil(t, ve.Path)
	require.Empty(t, entries(t, f.root))
}
