package fileacl

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// The system.posix_acl_access value: a version, then one entry per tag
// (linux/posix_acl_xattr.h), little-endian.
const (
	aclXattr      = "system.posix_acl_access"
	defaultXattr  = "system.posix_acl_default"
	aclVersion    = 2
	aclHeader     = 4
	aclEntrySize  = 8 // tag u16, perm u16, id u32
	tagUser       = 0x02
	tagGroup      = 0x08
	tagMask       = 0x10
	permWrite     = 0x02
	permAll       = 0x07
	maxACLBufSize = 64 << 10
)

var errBadACL = errors.New("the file's ACL cannot be read")

// opens reads path's access ACL. Only the named user and group entries
// grant beyond the mode bits; each is limited by the mask entry, which the
// mode's group bits show. So on Linux a Write grant only counts when the
// mode's group write bit is set too, which the mode check already refuses;
// it is checked for one rule on both systems.
func opens(path string, g Grant) (bool, error) {
	buf := make([]byte, 1024)
	for {
		n, err := unix.Lgetxattr(path, aclXattr, buf)
		switch {
		case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EOPNOTSUPP):
			return false, nil
		case errors.Is(err, unix.ERANGE) && len(buf) < maxACLBufSize:
			buf = make([]byte, 2*len(buf))
			continue
		case err != nil:
			return false, err
		}
		perm := uint16(permAll)
		if g == Write {
			perm = permWrite
		}
		return parseACL(buf[:n], perm)
	}
}

// parseACL reports whether a named user or group entry in v grants any of
// perm once the mask entry is applied.
func parseACL(v []byte, perm uint16) (bool, error) {
	le := binary.LittleEndian
	if len(v) < aclHeader || le.Uint32(v) != aclVersion || (len(v)-aclHeader)%aclEntrySize != 0 {
		return false, errBadACL
	}
	entries := v[aclHeader:]
	mask := uint16(permAll)
	for i := 0; i < len(entries); i += aclEntrySize {
		if le.Uint16(entries[i:]) == tagMask {
			mask = le.Uint16(entries[i+2:])
		}
	}
	for i := 0; i < len(entries); i += aclEntrySize {
		switch le.Uint16(entries[i:]) {
		case tagUser, tagGroup:
			if le.Uint16(entries[i+2:])&mask&perm != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// clearACL removes fd's access ACL and default ACL; a missing one, or a file
// system without ACLs, is no error.
func clearACL(fd int) error {
	for _, name := range []string{aclXattr, defaultXattr} {
		err := unix.Fremovexattr(fd, name)
		if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
			return err
		}
	}
	return nil
}
