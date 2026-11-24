package fileacl

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

func encodeACL(entries ...aclEntry) []byte {
	b := binary.LittleEndian.AppendUint32(nil, aclVersion)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

const (
	tagUserObj  = 0x01
	tagGroupObj = 0x04
	tagOther    = 0x20
	undefinedID = 0xffffffff
)

// acl is a directory's access ACL: owner rwx, group r-x, others none, a
// named entry and the mask.
func acl(named aclEntry, mask uint16) []byte {
	return encodeACL(
		aclEntry{tagUserObj, 7, undefinedID},
		named,
		aclEntry{tagGroupObj, 5, undefinedID},
		aclEntry{tagMask, mask, undefinedID},
		aclEntry{tagOther, 0, undefinedID},
	)
}

func TestParseACL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		v            []byte
		write, other bool
	}{
		{name: "named user r-x", v: acl(aclEntry{tagUser, 5, 4242}, 5), other: true},
		{name: "named group rwx", v: acl(aclEntry{tagGroup, 7, 4242}, 7), write: true, other: true},
		{name: "named user rwx under an r-x mask", v: acl(aclEntry{tagUser, 7, 4242}, 5), other: true},
		{name: "named user under an empty mask", v: acl(aclEntry{tagUser, 7, 4242}, 0)},
		{name: "minimal ACL", v: encodeACL(aclEntry{tagUserObj, 7, undefinedID}, aclEntry{tagGroupObj, 5, undefinedID}, aclEntry{tagOther, 0, undefinedID})},
	}
	for _, c := range cases {
		got, err := parseACL(c.v, permWrite)
		require.NoError(t, err, c.name)
		require.Equal(t, c.write, got, "%s: Write", c.name)
		got, err = parseACL(c.v, permAll)
		require.NoError(t, err, c.name)
		require.Equal(t, c.other, got, "%s: Any", c.name)
	}
	_, err := parseACL([]byte{2, 0, 0, 0, 1}, permAll)
	require.Error(t, err, "a torn entry")
	_, err = parseACL(encodeACL()[:3], permAll)
	require.Error(t, err, "a short header")
}

// An ACL set on a real directory (as setfacl would) is read back. Skipped
// where the file system takes no POSIX ACLs.
func TestOpensLinux(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "d")
	require.NoError(t, os.Mkdir(dir, 0o750))
	got, err := Opens(dir, Any)
	require.NoError(t, err)
	require.False(t, got, "no ACL")
	err = unix.Setxattr(dir, aclXattr, acl(aclEntry{tagUser, 5, 4242}, 5), 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skip("this file system takes no POSIX ACLs")
	}
	require.NoError(t, err)
	got, err = Opens(dir, Any)
	require.NoError(t, err)
	require.True(t, got)
	got, err = Opens(dir, Write)
	require.NoError(t, err)
	require.False(t, got)
}

// Clear removes the access ACL and the default ACL new entries inherit.
func TestClearLinux(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "d")
	require.NoError(t, os.Mkdir(dir, 0o750))
	err := unix.Setxattr(dir, aclXattr, acl(aclEntry{tagUser, 5, 4242}, 5), 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skip("this file system takes no POSIX ACLs")
	}
	require.NoError(t, err)
	require.NoError(t, unix.Setxattr(dir, defaultXattr, acl(aclEntry{tagUser, 5, 4242}, 5), 0))
	f, err := os.Open(dir)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, Clear(int(f.Fd())))
	got, err := Opens(dir, Any)
	require.NoError(t, err)
	require.False(t, got)
	_, err = unix.Getxattr(dir, defaultXattr, make([]byte, 256))
	require.ErrorIs(t, err, unix.ENODATA, "the default ACL is gone")
	require.NoError(t, Clear(int(f.Fd())), "no ACL left to remove")
}
