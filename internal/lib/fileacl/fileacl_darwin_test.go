package fileacl

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// addACL adds macOS ACL entry to path and strips every entry at cleanup, so
// TempDir can remove it.
func addACL(t *testing.T, path, entry string) {
	t.Helper()
	out, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

func TestOpensDarwin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		entries      []string
		write, other bool
	}{
		{name: "no ACL"},
		{name: "deny only, as on a home directory", entries: []string{"group:everyone deny delete"}},
		{name: "allow read", entries: []string{"everyone allow list,search,read"}, other: true},
		{name: "allow add_file", entries: []string{"everyone allow add_file"}, write: true, other: true},
		{name: "allow delete_child", entries: []string{"everyone allow delete_child"}, write: true, other: true},
		{name: "allow write_security", entries: []string{"everyone allow writesecurity"}, write: true, other: true},
		{name: "deny then allow", entries: []string{"group:everyone deny delete", "everyone allow add_subdirectory"}, write: true, other: true},
		{name: "allow only inherited by children", entries: []string{"everyone allow add_file,file_inherit,directory_inherit,only_inherit"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "d")
			require.NoError(t, os.Mkdir(dir, 0o750))
			for _, e := range c.entries {
				addACL(t, dir, e)
			}
			got, err := Opens(dir, Write)
			require.NoError(t, err)
			require.Equal(t, c.write, got, "Write")
			got, err = Opens(dir, Any)
			require.NoError(t, err)
			require.Equal(t, c.other, got, "Any")
		})
	}
}

// A symlink is not followed: an ACL on its target does not count.
func TestOpensDarwinNoFollow(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "t")
	require.NoError(t, os.Mkdir(target, 0o750))
	addACL(t, target, "everyone allow add_file")
	link := filepath.Join(base, "l")
	require.NoError(t, os.Symlink(target, link))
	got, err := Opens(link, Any)
	require.NoError(t, err)
	require.False(t, got)
}

func TestOpensDarwinMissing(t *testing.T) {
	t.Parallel()
	_, err := Opens(filepath.Join(t.TempDir(), "none"), Any)
	require.Error(t, err)
}

// A reply that does not hold the ACL it names is refused, not read past.
func TestParseFilesecRefusesShortReply(t *testing.T) {
	t.Parallel()
	_, err := parseFilesec([]byte{1, 2, 3}, rightsAny)
	require.Error(t, err)
	buf := make([]byte, 64)
	buf[0] = 64 // total
	buf[4] = 8  // offset from the reference
	buf[8] = 60 // length past the end
	_, err = parseFilesec(buf, rightsAny)
	require.Error(t, err)
}
