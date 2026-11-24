package dial

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A POSIX ACL entry for a named user fits under a 0750 mode (its mask shows
// as the group bits), so the mode alone does not show it: the socket
// directory check refuses it. Skipped where the file system takes no ACLs.
func TestSocketDirIsRefusesAPOSIXACL(t *testing.T) {
	t.Parallel()
	dir := shortBase(t)
	require.NoError(t, os.Chmod(dir, 0o750))
	me := uint32(os.Getuid())
	gid := dirGID(t, dir)
	require.True(t, SocketDirIs(dir, me, gid))

	// user::rwx user:4242:r-x group::r-x mask::r-x other::---
	le := binary.LittleEndian
	v := le.AppendUint32(nil, 2)
	for _, e := range [][3]uint32{{0x01, 7, 0xffffffff}, {0x02, 5, 4242}, {0x04, 5, 0xffffffff}, {0x10, 5, 0xffffffff}, {0x20, 0, 0xffffffff}} {
		v = le.AppendUint16(v, uint16(e[0]))
		v = le.AppendUint16(v, uint16(e[1]))
		v = le.AppendUint32(v, e[2])
	}
	err := unix.Setxattr(dir, "system.posix_acl_access", v, 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skip("this file system takes no POSIX ACLs")
	}
	require.NoError(t, err)
	fi, err := os.Lstat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o750), fi.Mode().Perm(), "the mode is closed to others")
	require.False(t, SocketDirIs(dir, me, gid))
}
