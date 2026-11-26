//go:build unix

package config

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// openNoFollow opens path read-only without following a symlink at the path
// and without blocking on a FIFO or device (O_NONBLOCK), and refuses anything
// but a regular file with one link (a hardlink to a root-only file the engine
// user planted).
func openNoFollow(path string) (*os.File, error) {
	f, err := ownerfile.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = CheckPlainFile(fi)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// CheckPlainFile refuses anything but a regular file with a single link.
func CheckPlainFile(fi os.FileInfo) error { return ownerfile.CheckPlain(fi) }

// credentialRules are ReadCredential's owners: this process's effective
// user, or root (a file root wrote stays readable by an engine run as root
// and by the setup page). The other rules are ownerfile's.
func credentialRules() ownerfile.Rules {
	return ownerfile.Rules{Owners: []int{os.Geteuid(), rootUID}, OwnerName: "this process's user or root", MaxBytes: maxConfigBytes}
}
