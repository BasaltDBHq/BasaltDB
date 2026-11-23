package osservice

import "golang.org/x/sys/unix"

// clearUserFlags clears the flags a file's owner may set (uchg, uappnd and
// the rest of UF_SETTABLE) on the file open at fd, so an owner who made its
// log or directory immutable cannot stop root's later chown, chmod or
// rename, nor newsyslog's rotation. System flags stay as they are.
func clearUserFlags(fd int) error {
	var st unix.Stat_t
	if err := fstat(fd, &st); err != nil {
		return err
	}
	if st.Flags&unix.UF_SETTABLE == 0 {
		return nil
	}
	return unix.Fchflags(fd, int(st.Flags&^unix.UF_SETTABLE))
}
