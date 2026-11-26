// Package credfiles reads and writes an agent's credential files for basalt
// init --remote and basalt service install: by path as the agent's own user,
// and as root through directories opened without following a link. Every
// read checks the open file (a regular file with one link, mode 0600 or
// tighter, the expected owner), and root's read of a file another user wrote
// passes pgdial.CheckForeignDSN in the same function.
package credfiles

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// MaxCredentialBytes bounds a credential: the connection string read from
// stdin, and what a credential file may hold.
const MaxCredentialBytes = servicespec.MaxCredentialBytes

// Files reaches init --remote's credential files: the setup service's
// CredFiles, the same interface type (an alias of it).
type Files = interface {
	Lock(path string) (func(), error)
	Read(path string) (string, os.FileInfo, error)
	Stat(path string) (os.FileInfo, error)
	Write(path string, data []byte) error
	Rename(from, to string) error
	Remove(path string) error
	Close()
}

// ConfigDir is the config directory init --remote opened as root: the setup
// service's RootConfigDir, the same interface type (an alias of it).
type ConfigDir = interface {
	Upsert(name string, s config.Settings, a config.Agent) (config.VaultWritten, error)
	Close()
}

// FilesHost is how setup reaches the files root reads and writes for the
// engine's user: directories and files opened from / without following a
// link anyone but root or their owner controls, and OS user ids.
type FilesHost interface {
	// OSOpenTrustedDir opens dir for root, refusing a directory on the way
	// that someone other than root or owner could swap; create makes it
	// when missing.
	OSOpenTrustedDir(dir string, owner int, create bool) (TrustedDir, error)
	// OSOpenTrustedFile opens path read-only for root: its directory as
	// OSOpenTrustedDir does, the file itself never through a symlink.
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
	// OSLookupUID is the uid of the OS user name, or -1 when there is no
	// such user.
	OSLookupUID(name string) int
}

// TrustedDir is a directory opened by OSOpenTrustedDir: files in it are
// reached relative to its descriptor, never by path. It is an alias of the
// interface itself, the same type as osservice.TrustedDirPort.
type TrustedDir = interface {
	config.Dir
	// CreateFile makes name with data, owned by owner (< 0: this process),
	// refusing one that exists.
	CreateFile(name string, data []byte, mode os.FileMode, owner int) error
	// Remove removes name from the directory.
	Remove(name string) error
	// Close closes the directory's descriptor.
	Close() error
}
