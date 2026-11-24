package fileacl

import (
	"encoding/binary"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kauth_filesec getattrlist returns for ATTR_CMN_EXTENDED_SECURITY, in
// host byte order (sys/kauth.h).
const (
	filesecMagic   = 0x012cc16d
	filesecNoACL   = 0xffffffff
	filesecHeader  = 4 + 16 + 16      // magic, owner GUID, group GUID
	aclHeader      = 4 + 4            // entry count, flags
	aceSize        = 16 + 4 + 4       // applicable GUID, flags, rights
	maxACLEntries  = 128              // KAUTH_ACL_MAX_ENTRIES
	replyLenSize   = 4                // the reply's leading u_int32_t length
	replyHeader    = replyLenSize + 8 // then one attrreference: offset, length
	attrBufSize    = replyHeader + filesecHeader + aclHeader + maxACLEntries*aceSize
	aceKindMask    = 0xf
	aceKindPermit  = 1
	aceOnlyInherit = 1 << 8

	rightListDirectory   = 1 << 1
	rightAddFile         = 1 << 2
	rightSearch          = 1 << 3
	rightDelete          = 1 << 4
	rightAddSubdirectory = 1 << 5
	rightDeleteChild     = 1 << 6
	rightWriteAttributes = 1 << 8
	rightWriteExtAttrs   = 1 << 10
	rightWriteSecurity   = 1 << 12
	rightTakeOwnership   = 1 << 13
	rightGenericAll      = 1 << 21
	rightGenericExecute  = 1 << 22
	rightGenericWrite    = 1 << 23
	rightGenericRead     = 1 << 24
	rightsWrite          = rightAddFile | rightDelete | rightAddSubdirectory | rightDeleteChild | rightWriteAttributes | rightWriteExtAttrs | rightWriteSecurity | rightTakeOwnership | rightGenericAll | rightGenericWrite
	rightsAny            = rightsWrite | rightListDirectory | rightSearch | rightGenericExecute | rightGenericRead
)

var errBadFilesec = errors.New("the file's ACL cannot be read")

func opens(path string, g Grant) (bool, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return false, err
	}
	al := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, attrBufSize)
	// x/sys/unix has no getattrlist wrapper; the call goes through libc.
	//nolint:staticcheck // SA1019: no libSystem wrapper for getattrlist is exported
	_, _, errno := unix.Syscall6(unix.SYS_GETATTRLIST,
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&al)), //nolint:gosec // G103: kept alive below
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_NOFOLLOW, 0) //nolint:gosec // G103: kept alive below
	runtime.KeepAlive(p)
	runtime.KeepAlive(&al)
	if errno != 0 {
		if errors.Is(errno, unix.ENOTSUP) {
			return false, nil
		}
		return false, errno
	}
	rights := uint32(rightsAny)
	if g == Write {
		rights = rightsWrite
	}
	return parseFilesec(buf, rights)
}

// parseFilesec reads the getattrlist reply in buf: its length, then an
// attrreference to the kauth_filesec. It reports whether an allow entry
// that applies to the file itself grants any of rights. A reply it cannot
// read whole is an error.
func parseFilesec(buf []byte, rights uint32) (bool, error) {
	he := binary.NativeEndian
	if len(buf) < replyHeader {
		return false, errBadFilesec
	}
	total := he.Uint32(buf[0:])
	if total < replyHeader || int64(total) > int64(len(buf)) {
		return false, errBadFilesec
	}
	off := int64(int32(he.Uint32(buf[4:])))
	n := int64(he.Uint32(buf[8:]))
	if n == 0 {
		return false, nil // no extended security on this file
	}
	start := replyLenSize + off // the offset is from the attrreference itself
	if start < replyHeader || start+n > int64(total) || n < filesecHeader+aclHeader {
		return false, errBadFilesec
	}
	fs := buf[start : start+n]
	if he.Uint32(fs[0:]) != filesecMagic {
		return false, errBadFilesec
	}
	count := he.Uint32(fs[filesecHeader:])
	if count == filesecNoACL {
		return false, nil
	}
	aces := fs[filesecHeader+aclHeader:]
	if count > maxACLEntries || int64(count)*aceSize > int64(len(aces)) {
		return false, errBadFilesec
	}
	for i := range int(count) {
		ace := aces[i*aceSize : (i+1)*aceSize]
		flags := he.Uint32(ace[16:])
		if flags&aceKindMask != aceKindPermit || flags&aceOnlyInherit != 0 {
			continue
		}
		if he.Uint32(ace[20:])&rights != 0 {
			return true, nil
		}
	}
	return false, nil
}
