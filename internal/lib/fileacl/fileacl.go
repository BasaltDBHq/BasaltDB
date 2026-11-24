// Package fileacl reads whether a file's access control list lets anyone do
// more than its mode bits say. An ACL entry can open a file or directory to
// other users without changing its mode, so a check of the mode alone misses
// it. macOS keeps extended ACLs (chmod +a), read with getattrlist; Linux
// keeps POSIX ACLs (setfacl), read from the system.posix_acl_access
// attribute. Other platforms report no ACL.
//
// Neither reader maps an entry's user to a uid (macOS names users by GUID,
// and resolving one needs the directory service), so an allow entry counts
// whoever it names, the file's owner included. Deny entries never count:
// they only take access away.
package fileacl

// Grant is the access an allow entry is checked for.
type Grant uint8

const (
	// Write is any change to the file or, for a directory, to its entries:
	// write, append, add a file or subdirectory, delete, delete a child, and
	// change its attributes, ACL or owner.
	Write Grant = iota + 1
	// Any is any access at all beyond reading the file's attributes.
	Any
)

// Opens reports whether path, not followed if it is a symlink, has an ACL
// entry that allows g. A file system without ACLs has none. An error means
// the ACL could not be read; a caller that guards a boundary refuses then.
func Opens(path string, g Grant) (bool, error) {
	return opens(path, g)
}
