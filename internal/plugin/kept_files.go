//go:build unix

// The kept store: what a service-mode engine keeps on disk for the plugin
// entries it keeps itself (CONTRACT.md, Plugins, Plugin approval in service
// mode): the entries file <stateDir>/plugins.json, the installed copies under
// <stateDir>/plugins/, and the uploads a person's basalt plugin add sends over
// the person socket, under <stateDir>/plugin-uploads/.
//
// Every path it writes is below the state directory, which only the engine's
// OS user can write. It never reads a person's directory: a copy is staged
// from an upload the engine wrote itself, part by part, and is checked by the
// host's own staging and verification.

package plugin

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Names under the state directory.
const (
	EntriesFile = "plugins.json"
	lockFile    = EntriesFile + ".lock"
	UploadsDir  = "plugin-uploads"
)

// Limits (CONTRACT.md, Plugin approval in service mode, The upload and
// Engine-kept entries).
const (
	MaxPartBytes        = 64 << 10
	MaxUploadBytes      = 256 << 20
	MaxUploadPaths      = 1024
	MaxOpenUploads      = 4
	MaxStorageBytes     = 1 << 30
	MaxEntriesFileBytes = 1 << 20
	UploadTTL           = 15 * time.Minute
)

// Limits are the store's limits: DefaultLimits outside tests.
type Limits struct {
	PartBytes, UploadBytes, StorageBytes int64
	UploadPaths, OpenUploads             int
}

// DefaultLimits are the contract's.
func DefaultLimits() Limits {
	return Limits{PartBytes: MaxPartBytes, UploadBytes: MaxUploadBytes, StorageBytes: MaxStorageBytes, UploadPaths: MaxUploadPaths, OpenUploads: MaxOpenUploads}
}

// WithLimits replaces the store's limits (tests: the contract's are too
// large to reach in a test).
func (s *Store) WithLimits(l Limits) *Store {
	s.lim = l
	return s
}

// Modes of what the store makes.
const (
	pluginhostStateDirMode = 0o700
	copiesDirMode          = 0o755
	uploadDirMode          = 0o700
	uploadFile             = 0o600
	execFile               = 0o700
	privateFile            = 0o600
)

// Kind is how the person socket answers a PluginhostError.
type Kind int

// Kinds of PluginhostError.
const (
	// KindRefused is PLUGIN_REFUSED with Reason.
	KindRefused Kind = iota
	// KindInvalid is INVALID_ARGUMENT.
	KindInvalid
	// KindNotFound is NOT_FOUND.
	KindNotFound
)

// Reasons of PLUGIN_REFUSED the store gives.
const (
	ReasonTooLarge       = "TOO_LARGE"
	ReasonTooManyUploads = "TOO_MANY_UPLOADS"
	ReasonUnsafePath     = "UNSAFE_PATH"
	ReasonBadManifest    = "BAD_MANIFEST"
	ReasonNotTrusted     = "NOT_TRUSTED"
)

// PluginhostError is a refused store call. Message names a path relative to the
// upload or the state directory and the rule, never file contents.
type PluginhostError struct {
	Kind    Kind
	Reason  string
	Message string
}

func (e *PluginhostError) Error() string { return e.Message }

func refused(reason, format string, args ...any) *PluginhostError {
	return &PluginhostError{Kind: KindRefused, Reason: reason, Message: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) *PluginhostError {
	return &PluginhostError{Kind: KindInvalid, Message: fmt.Sprintf(format, args...)}
}

var errNoUpload = &PluginhostError{Kind: KindNotFound, Message: "no such upload: it is unknown, expired, used, dropped or another OS user's; begin a new one"}

// Store is a service engine's kept plugins: the entries file, the copies
// and the uploads. It is safe for concurrent use; uploads and the storage
// cap are tracked in memory and rebuilt from disk at New.
type Store struct {
	stateDir string
	now      func() time.Time
	goos     string

	lim Limits

	mu      sync.Mutex
	uploads map[uuid.UUID]*upload
	// copies is the bytes the installed copies take, recounted after every
	// change to them.
	copies int64
}

// NewPluginhost opens the store in stateDir: it makes the state directory when it is
// missing (mode 0700), removes every upload an earlier run left, and counts
// the copies. A state directory that is not a directory the engine's user
// owns, writable by no one else, is refused.
func NewPluginhost(stateDir string, now func() time.Time) (*Store, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("the state directory %s is not an absolute path", stateDir)
	}
	s := &Store{stateDir: filepath.Clean(stateDir), now: now, goos: runtime.GOOS, uploads: map[uuid.UUID]*upload{}, lim: DefaultLimits()}
	if err := os.MkdirAll(s.stateDir, pluginhostStateDirMode); err != nil {
		return nil, fmt.Errorf("the state directory %s cannot be made: %w", s.stateDir, err)
	}
	if err := checkOwnDir(s.stateDir); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(s.uploadsDir()); err != nil {
		return nil, fmt.Errorf("the uploads left in %s cannot be removed: %w", s.uploadsDir(), err)
	}
	s.recountCopies()
	return s, nil
}

// StateDir is the state directory the store keeps everything in.
func (s *Store) StateDir() string { return s.stateDir }

// Root is where the installed copies live: <stateDir>/plugins.
func (s *Store) Root() string { return filepath.Join(s.stateDir, pluginmodel.PluginsDirName) }

// Trust is the trust store engine-kept copies are verified with: same-user
// rules under the state directory, the engine's user as the owner. It holds
// no added key; an engine-kept copy is verified with plugin.RequireApproval,
// so only a built-in key makes a publisher known.
func (s *Store) Trust() (TrustStore, error) {
	return NewTrustStore(pluginmodel.ModeSameUser, s.goos, s.stateDir)
}

func (s *Store) uploadsDir() string { return filepath.Join(s.stateDir, UploadsDir) }

// checkOwnDir requires dir to be a directory (not a symlink) the engine's
// OS user owns, writable by no one else.
func checkOwnDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%s cannot be read: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a symlink is refused)", dir)
	}
	if uid, ok := ownerOf(fi); !ok || uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not owned by the engine's OS user", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by group or others", dir)
	}
	return nil
}

// recountCopies counts the bytes of every regular file under Root.
func (s *Store) recountCopies() {
	var n int64
	// What cannot be read counts as nothing: the walk goes on.
	_ = filepath.WalkDir(s.Root(), func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	s.mu.Lock()
	s.copies = n
	s.mu.Unlock()
}

// errNotEngineUser: a file of the store is not the engine's own.
var errNotEngineUser = errors.New("not owned by the engine's OS user")
