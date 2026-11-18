package privdrop

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// OS is the real System.
type OS struct {
	// Executable is the binary CheckBinary checks; empty means this
	// process's own (tests run a copy they placed).
	Executable string
}

var _ System = OS{}

// Euid is the effective user id; a platform without one reports
// math.MaxUint32, which is never root.
func (OS) Euid() uint32 {
	id := os.Geteuid()
	if id < 0 {
		return ^uint32(0)
	}
	return uint32(id)
}

// Lookup resolves name with its primary group and supplementary groups.
func (OS) Lookup(name string) (Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return Account{}, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return Account{}, fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return Account{}, fmt.Errorf("gid %q: %w", u.Gid, err)
	}
	names, err := u.GroupIds()
	if err != nil {
		return Account{}, fmt.Errorf("groups of %s: %w", name, err)
	}
	a := Account{Name: name, UID: uint32(uid), GID: uint32(gid), Groups: []uint32{uint32(gid)}}
	for _, g := range names {
		id, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return Account{}, fmt.Errorf("group id %q: %w", g, err)
		}
		a.Groups = append(a.Groups, uint32(id))
	}
	return a, nil
}

// CheckBinary refuses the binary when anyone but root could change it or a
// directory above it, through its path and the file it resolves to.
func (o OS) CheckBinary() error {
	path := o.Executable
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		path = exe
	}
	return service.OSSystem{}.CheckBinary(filepath.Clean(path))
}

// Mkdir makes dir owned by owner the way basalt service install does: from /
// without following a symlink, taking over only a directory root or owner
// owns.
func (OS) Mkdir(dir Dir, owner string) error {
	return service.OSSystem{}.Mkdir(dir.Path, dir.Mode, owner, "")
}
