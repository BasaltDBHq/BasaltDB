//go:build unix

package plugin

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// upload is one open upload: bytes the engine holds for a peer uid, read by
// nothing until PLUGIN_OPEN takes it.
type upload struct {
	id      uuid.UUID
	uid     uint32
	expires time.Time
	sizes   map[string]int64
	total   int64
	// taken: PLUGIN_OPEN holds it; no part is added and it never expires.
	taken bool
}

// Upload is what PLUGIN_UPLOAD_BEGIN returns.
type Upload struct {
	ID        uuid.UUID
	ExpiresAt time.Time
}

// Begin opens a new upload for peer uid, after dropping the expired ones.
// At most MaxOpenUploads are open on the engine at a time, whoever began
// them (TOO_MANY_UPLOADS).
func (s *Store) Begin(uid uint32) (Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if len(s.uploads) >= s.lim.OpenUploads {
		return Upload{}, refused(ReasonTooManyUploads, "%d plugin uploads are already open on this engine; "+
			"they expire %s after they began: try again then", s.lim.OpenUploads, UploadTTL)
	}
	if err := os.MkdirAll(s.uploadsDir(), uploadDirMode); err != nil {
		return Upload{}, err
	}
	if err := checkOwnDir(s.uploadsDir()); err != nil {
		return Upload{}, refused(ReasonUnsafePath, "%s", err)
	}
	id := uuid.New()
	if err := os.Mkdir(filepath.Join(s.uploadsDir(), id.String()), uploadDirMode); err != nil {
		return Upload{}, err
	}
	u := &upload{id: id, uid: uid, expires: s.now().Add(UploadTTL).UTC().Truncate(time.Second), sizes: map[string]int64{}}
	s.uploads[id] = u
	return Upload{ID: id, ExpiresAt: u.expires}, nil
}

// expireLocked drops every upload past its expiry that PLUGIN_OPEN does
// not hold. s.mu is held.
func (s *Store) expireLocked() {
	now := s.now()
	for id, u := range s.uploads {
		if !u.taken && !now.Before(u.expires) {
			s.dropLocked(id)
		}
	}
}

// dropLocked removes upload id from memory and disk. s.mu is held.
func (s *Store) dropLocked(id uuid.UUID) {
	delete(s.uploads, id)
	_ = os.RemoveAll(filepath.Join(s.uploadsDir(), id.String()))
}

// usedLocked is the bytes the copies and the open uploads take. s.mu is
// held.
func (s *Store) usedLocked() int64 {
	n := s.copies
	for _, u := range s.uploads {
		n += u.total
	}
	return n
}

// fileLimit is the most bytes one path of an upload may hold: the
// manifest's own limits for the manifest and its signature, the upload's
// for any other file.
func (s *Store) fileLimit(p string) int64 {
	switch p {
	case ManifestFile:
		return MaxManifestBytes
	case SignatureFile:
		return MaxSignatureFileBytes
	}
	return s.lim.UploadBytes
}

// Part adds data (base64url without padding) at offset to path of upload
// id, which peer uid began, and returns the bytes now held for path. Parts
// of one path arrive in order. Refusals: NOT_FOUND for an upload that is not
// open for uid; INVALID_ARGUMENT, the upload kept, for a path that breaks
// the manifest's path rules or is a directory of another path, data that
// does not decode, and an offset other than the bytes held; PLUGIN_REFUSED
// TOO_LARGE, the upload dropped, for a part past any limit; UNSAFE_PATH,
// the upload dropped, when what is on disk is not what the engine wrote.
func (s *Store) Part(uid uint32, id uuid.UUID, p string, offset int64, data string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	u, ok := s.uploads[id]
	if !ok || u.uid != uid || u.taken {
		return 0, errNoUpload
	}
	if !ValidRelativePath(p) {
		return 0, invalid("path %q breaks the manifest's path rules: relative, at most 255 characters, "+
			"letters, digits, '.', '_' and '-', no segment starting with '.'", p)
	}
	// "" decodes to no bytes: the one part of an empty file.
	b, err := base64.RawURLEncoding.Strict().DecodeString(data)
	if err != nil {
		return 0, invalid("data is not base64url without padding")
	}
	if int64(len(b)) > s.lim.PartBytes {
		s.dropLocked(id)
		return 0, refused(ReasonTooLarge, "a part holds at most %d bytes; this one holds %d. The upload was dropped", s.lim.PartBytes, len(b))
	}
	held, known := u.sizes[p]
	if known && offset == 0 {
		return 0, invalid("%s already holds a part; send the next at offset %d", p, held)
	}
	if len(b) == 0 && (known || offset != 0) {
		// An empty part only makes an empty file: the first part of a path.
		return 0, invalid("data holds no bytes; only the one part of an empty file may")
	}
	if offset != held {
		return 0, invalid("offset %d is not the %d bytes held for %s; send its parts in order, each once", offset, held, p)
	}
	if !known && dirClash(u.sizes, p) {
		return 0, invalid("path %s is a directory of another path of the upload, or the other way round", p)
	}
	n := int64(len(b))
	switch {
	case held+n > s.fileLimit(p):
		s.dropLocked(id)
		return 0, refused(ReasonTooLarge, "%s is over its limit of %d bytes. The upload was dropped", p, s.fileLimit(p))
	case !known && len(u.sizes) >= s.lim.UploadPaths:
		s.dropLocked(id)
		return 0, refused(ReasonTooLarge, "an upload holds at most %d paths. The upload was dropped", s.lim.UploadPaths)
	case u.total+n > s.lim.UploadBytes:
		s.dropLocked(id)
		return 0, refused(ReasonTooLarge, "an upload holds at most %d bytes in all. The upload was dropped", s.lim.UploadBytes)
	case s.usedLocked()+n > s.lim.StorageBytes:
		s.dropLocked(id)
		return 0, refused(ReasonTooLarge, "the engine's plugin copies and uploads take at most %d bytes together; "+
			"remove a plugin first. The upload was dropped", s.lim.StorageBytes)
	}
	if err := s.writePart(u, p, offset, b); err != nil {
		s.dropLocked(id)
		return 0, err
	}
	u.sizes[p] = held + n
	u.total += n
	return held + n, nil
}

// dirClash reports whether p is a directory of a held path, or a held path
// is a directory of p.
func dirClash(sizes map[string]int64, p string) bool {
	for q := range sizes {
		if strings.HasPrefix(q, p+"/") || strings.HasPrefix(p, q+"/") {
			return true
		}
	}
	return false
}

// writePart writes b at offset to p in u's directory, inside it only: every
// directory on the way is one the engine made (no symlink, a directory),
// the file is new at offset 0 and otherwise the regular file of offset
// bytes the engine wrote, never followed through a link, never a device or
// a FIFO.
func (s *Store) writePart(u *upload, p string, offset int64, b []byte) error {
	root, err := os.OpenRoot(filepath.Join(s.uploadsDir(), u.id.String()))
	if err != nil {
		return refused(ReasonUnsafePath, "the upload's directory cannot be opened")
	}
	defer func() { _ = root.Close() }()
	unsafe := func(why string) error {
		return refused(ReasonUnsafePath, "%s %s; the engine wrote no such thing. The upload was dropped", p, why)
	}
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		dir := filepath.FromSlash(path.Join(parts[:i]...))
		fi, err := root.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := root.Mkdir(dir, uploadDirMode); err != nil {
				return unsafe("cannot be made")
			}
		case err != nil:
			return unsafe("cannot be read")
		case !fi.IsDir():
			return unsafe("has a component that is not a directory")
		}
	}
	name := filepath.FromSlash(p)
	flags := os.O_WRONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if offset == 0 {
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		flags |= os.O_APPEND
	}
	f, err := root.OpenFile(name, flags, uploadFile)
	if err != nil {
		return unsafe("cannot be opened as a new or held file")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return unsafe("is not a regular file")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 || fi.Size() != offset {
		return unsafe("is not the file the engine wrote")
	}
	if _, err := f.Write(b); err != nil {
		return refused(ReasonUnsafePath, "%s cannot be written. The upload was dropped", p)
	}
	return nil
}

// Taken is an upload PLUGIN_OPEN holds: its directory and the paths it
// holds. Release removes it, whatever PLUGIN_OPEN decided.
type Taken struct {
	s     *Store
	id    uuid.UUID
	Dir   string
	Paths []string
}

// Take hands upload id, which peer uid began, to PLUGIN_OPEN: it checks the
// expiry once, and from then on the upload is PLUGIN_OPEN's until Release.
func (s *Store) Take(uid uint32, id uuid.UUID) (*Taken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	u, ok := s.uploads[id]
	if !ok || u.uid != uid || u.taken {
		return nil, errNoUpload
	}
	u.taken = true
	return &Taken{s: s, id: id, Dir: filepath.Join(s.uploadsDir(), id.String()), Paths: slices.Sorted(maps.Keys(u.sizes))}, nil
}

// Release removes the taken upload from memory and disk.
func (t *Taken) Release() {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	t.s.dropLocked(t.id)
}

// MarkExecutables sets the execute bit on paths of the upload (each one it
// holds), so staging installs them with mode 0755, as a same-user install
// keeps a source's executable files.
func (t *Taken) MarkExecutables(paths []string) error {
	root, err := os.OpenRoot(t.Dir)
	if err != nil {
		return refused(ReasonUnsafePath, "the upload's directory cannot be opened")
	}
	defer func() { _ = root.Close() }()
	for _, p := range paths {
		if !slices.Contains(t.Paths, p) {
			return refused(ReasonBadManifest, "executables names %s, which the upload does not hold", p)
		}
		if err := root.Chmod(filepath.FromSlash(p), execFile); err != nil {
			return refused(ReasonUnsafePath, "%s cannot be made executable", p)
		}
	}
	return nil
}

// Open is how many uploads are open (tests).
func (s *Store) Open() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.uploads)
}

func ownerOf(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
