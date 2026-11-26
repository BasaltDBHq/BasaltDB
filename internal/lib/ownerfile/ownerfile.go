// Package ownerfile reads a file only its owner may read, such as a key or a
// credential, and creates one once. A file is opened without following a
// symbolic link and without blocking on a FIFO, and every check is made on
// the open descriptor that is then read, so nothing can be swapped between
// the check and the read.
//
// The rules (Check): a regular file with one link (a second hard link is
// another path to the same secret, which someone else may have planted),
// owned by the effective uid unless the caller names other owners, with no
// access for group or others, and no larger than the caller's cap. Owner,
// mode and link count are checked on Unix only.
package ownerfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
)

// Rule is the rule a refused file breaks.
type Rule int

const (
	// Symlink: the path is a symbolic link.
	Symlink Rule = iota + 1
	// NotRegular: not a regular file (a directory, a FIFO, a device).
	NotRegular
	// HardLinks: the file has more than one hard link.
	HardLinks
	// Owner: the file belongs to a user Rules.Owners does not name.
	Owner
	// Mode: group or others have some access to the file.
	Mode
	// TooLarge: the file is larger than Rules.MaxBytes.
	TooLarge
	// Changed: the file changed size while it was read.
	Changed
	// Unlinked: the open file has no name left (removed after the open).
	Unlinked
)

// RefusedError is a file refused by one of the rules. It never holds what
// the file holds. Callers name the path.
type RefusedError struct {
	Rule Rule
	// UID is the file's owner and Want who may own it (Owner).
	UID  int
	Want string
	// Perm is the file's permission bits (Mode).
	Perm os.FileMode
	// Size is the file's size and Max the cap (TooLarge).
	Size, Max int64
	// Err is the system error behind the refusal, if any (Symlink).
	Err error
}

func (e *RefusedError) Error() string {
	switch e.Rule {
	case Symlink:
		return "a symbolic link, not a regular file"
	case NotRegular:
		return "not a regular file"
	case HardLinks:
		return "file has more than one hard link"
	case Owner:
		return fmt.Sprintf("owned by uid %d, not %s", e.UID, e.Want)
	case Mode:
		return fmt.Sprintf("mode %o is more open than 0600", e.Perm)
	case TooLarge:
		return fmt.Sprintf("%d bytes is more than the %d allowed", e.Size, e.Max)
	case Changed:
		return "changed while it was read"
	case Unlinked:
		return "file was removed while it was open"
	}
	return "refused"
}

func (e *RefusedError) Unwrap() error { return e.Err }

// Refusal is err's RefusedError, or nil when err is not a refusal.
func Refusal(err error) *RefusedError {
	var re *RefusedError
	if errors.As(err, &re) {
		return re
	}
	return nil
}

// Rules are what a caller sets beyond the fixed checks.
type Rules struct {
	// Owners are the uids that may own the file. None means this process's
	// effective uid alone. A negative uid matches nobody.
	Owners []int
	// OwnerName names Owners in a refusal ("root or uid 501"). The default
	// names the uids.
	OwnerName string
	// MaxBytes refuses a larger file. 0 is no cap.
	MaxBytes int64
}

func (r Rules) owners() []int {
	if len(r.Owners) == 0 {
		return []int{os.Geteuid()}
	}
	return r.Owners
}

func (r Rules) want() string {
	if r.OwnerName != "" {
		return r.OwnerName
	}
	if len(r.Owners) == 0 {
		return fmt.Sprintf("this process's user (uid %d)", os.Geteuid())
	}
	uids := make([]string, 0, len(r.Owners))
	for _, o := range r.Owners {
		uids = append(uids, "uid "+strconv.Itoa(o))
	}
	return strings.Join(uids, " or ")
}

// FileMode is the mode ReadOrCreate creates a file with.
const FileMode os.FileMode = 0o600

// permMask is the bits a file must not have: any access for group or others.
const permMask os.FileMode = 0o077

// Open opens path without following a symbolic link (Symlink) and without
// blocking on a FIFO, then checks the open file (Check). A missing file is
// the open's error, which wraps fs.ErrNotExist.
func Open(path string, r Rules) (*os.File, os.FileInfo, error) {
	f, err := OpenNoFollow(path)
	if err != nil {
		if isSymlinkErr(err) {
			return nil, nil, &RefusedError{Rule: Symlink, Err: err}
		}
		return nil, nil, err
	}
	fi, err := Check(f, r)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// Check checks f, an open file: a regular file with one link (CheckPlain;
// and not removed since it was opened, Unlinked), owned by one of r's owners
// (CheckOwner), with no access for group or others, no larger than
// r.MaxBytes.
func Check(f *os.File, r Rules) (os.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := CheckPlain(fi); err != nil {
		return nil, err
	}
	if unlinked(fi) {
		return nil, &RefusedError{Rule: Unlinked}
	}
	if err := CheckOwner(fi, r); err != nil {
		return nil, err
	}
	if checksModes && fi.Mode().Perm()&permMask != 0 {
		return nil, &RefusedError{Rule: Mode, Perm: fi.Mode().Perm()}
	}
	if r.MaxBytes > 0 && fi.Size() > r.MaxBytes {
		return nil, &RefusedError{Rule: TooLarge, Size: fi.Size(), Max: r.MaxBytes}
	}
	return fi, nil
}

// Read opens and checks path (Open) and reads it whole. The caller clears
// the bytes when they hold a secret.
func Read(path string, r Rules) ([]byte, os.FileInfo, error) {
	f, fi, err := Open(path, r)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	raw, err := readAll(f, fi)
	if err != nil {
		return nil, nil, err
	}
	return raw, fi, nil
}

// ReadOpen checks f (Check), a file the caller opened itself (relative to a
// directory it trusts, without following a link), and reads it whole.
func ReadOpen(f *os.File, r Rules) ([]byte, os.FileInfo, error) {
	fi, err := Check(f, r)
	if err != nil {
		return nil, nil, err
	}
	raw, err := readAll(f, fi)
	if err != nil {
		return nil, nil, err
	}
	return raw, fi, nil
}

// readAll reads the fi.Size() bytes of f into one buffer, with a byte more
// to notice growth, so reading leaves no grown copies of a secret behind. A
// file that grew or shrank since Stat is Changed.
func readAll(f *os.File, fi os.FileInfo) ([]byte, error) {
	raw := make([]byte, fi.Size()+1)
	n, err := io.ReadFull(f, raw)
	switch {
	case err == nil:
		clear(raw)
		return nil, &RefusedError{Rule: Changed}
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		if int64(n) != fi.Size() {
			clear(raw)
			return nil, &RefusedError{Rule: Changed}
		}
		return raw[:n], nil
	default:
		clear(raw)
		return nil, err
	}
}

// staleTempAge is how old a leftover temporary file must be before
// ReadOrCreate removes it, so a concurrent create's file is left alone.
const staleTempAge = time.Minute

// ReadOrCreate reads path (Read), first creating it with what fill returns
// when it does not exist. A file that exists is never replaced, and of two
// processes creating it at once both read the one linked first.
//
// The new file is written to a temporary file next to path (<name>.*.tmp,
// FileMode, synced), hard-linked to path, the temporary name removed and the
// directory synced: the file appears whole or not at all and its name
// survives a crash. Leftover temporary files this user owns are removed
// before path is read: at once when one is a second link to path (a create
// that stopped between the link and the removal, which Read would refuse),
// otherwise once older than a minute by now. fill's bytes are cleared.
func ReadOrCreate(path string, r Rules, fill func() ([]byte, error), now func() time.Time) ([]byte, os.FileInfo, error) {
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := create(path, fill); err != nil {
			return nil, nil, err
		}
	case err != nil:
		return nil, nil, err
	}
	removeStaleTemps(path, r, now)
	return Read(path, r)
}

// create writes fill's bytes to path once (ReadOrCreate). A file another
// process linked first is kept: the link then fails with "exists".
func create(path string, fill func() ([]byte, error)) error {
	raw, err := fill()
	defer clear(raw)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // the bytes stay reachable only through path
	if err := writeTemp(tmp, raw); err != nil {
		return err
	}
	err = os.Link(tmp.Name(), path)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// A concurrent ReadOrCreate may have removed it already (removeStaleTemps).
	if err := os.Remove(tmp.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// The new name (and the temporary one gone) survive a crash only once
	// the directory itself is on disk.
	if err := atomicfile.SyncDir(dir); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func writeTemp(tmp *os.File, raw []byte) error {
	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}

// removeStaleTemps removes path's leftover <name>.*.tmp files (ReadOrCreate):
// regular files one of r's owners owns that are a second link to path or
// older than staleTempAge. Best effort: a failure here changes nothing about
// path, which Read then checks.
func removeStaleTemps(path string, r Rules, now func() time.Time) {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), globEscape(filepath.Base(path))+".*.tmp"))
	if err != nil {
		return
	}
	target, _ := os.Lstat(path)
	for _, m := range matches {
		fi, err := os.Lstat(m)
		if err != nil || !fi.Mode().IsRegular() || CheckOwner(fi, r) != nil {
			continue
		}
		linked := target != nil && os.SameFile(fi, target)
		if linked || now().Sub(fi.ModTime()) >= staleTempAge {
			_ = os.Remove(m)
		}
	}
}

// globEscape quotes the glob metacharacters of a file name.
func globEscape(name string) string {
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune(`*?[\`, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
