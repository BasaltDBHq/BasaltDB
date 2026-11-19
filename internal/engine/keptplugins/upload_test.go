//go:build unix

package keptplugins_test

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/keptplugins"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

const peer uint32 = 1001

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newStore is a store in a fresh state directory, which the test also
// returns with the directory around it, to check nothing lands outside.
func newStore(t *testing.T) (*keptplugins.Store, string, *clock) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	state := filepath.Join(base, "state")
	c := &clock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
	s, err := keptplugins.New(state, c.now)
	require.NoError(t, err)
	return s, base, c
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func requireRefused(t *testing.T, err error, kind keptplugins.Kind, reason string) {
	t.Helper()
	var ke *keptplugins.Error
	require.True(t, errors.As(err, &ke), "a store refusal: %v", err)
	require.Equal(t, kind, ke.Kind, ke.Message)
	if reason != "" {
		require.Equal(t, reason, ke.Reason, ke.Message)
	}
}

// listAll is every path under dir, relative to it.
func listAll(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		require.NoError(t, err)
		rel, err := filepath.Rel(dir, p)
		require.NoError(t, err)
		out = append(out, rel)
		return nil
	}))
	return out
}

// TestUploadHardening: an upload never writes outside its own directory,
// never through a link, never into a device or a FIFO, never past a limit,
// and an upload left half way is gone once it expires.
func TestUploadHardening(t *testing.T) {
	t.Run("path traversal, absolute paths, separators and NUL are refused", func(t *testing.T) {
		s, base, _ := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		before := listAll(t, base)
		for _, p := range []string{
			"../escape", "a/../../escape", "..", ".", "/etc/passwd", "/abs", "a//b", "a/./b", "a\\b", "..\\x",
			"a\x00b", "bin/\x00", ".hidden", "bin/.hidden", "", strings.Repeat("a", 256), "a b", "a/",
		} {
			_, err := s.Part(peer, u.ID, p, 0, b64([]byte("x")))
			requireRefused(t, err, keptplugins.KindInvalid, "")
		}
		require.Equal(t, before, listAll(t, base), "nothing was written anywhere")
		require.Equal(t, 1, s.Open(), "the upload is kept after an invalid argument")
	})

	t.Run("a symlink planted in the upload is never followed", func(t *testing.T) {
		s, base, _ := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		outside := filepath.Join(base, "outside")
		require.NoError(t, os.WriteFile(outside, []byte("keep"), 0o600))
		dir := filepath.Join(s.StateDir(), keptplugins.UploadsDir, u.ID.String())
		// As a file, then as a directory on the way.
		require.NoError(t, os.Symlink(outside, filepath.Join(dir, "f")))
		_, err = s.Part(peer, u.ID, "f", 0, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonUnsafePath)
		require.Zero(t, s.Open(), "the upload is dropped")

		u, err = s.Begin(peer)
		require.NoError(t, err)
		dir = filepath.Join(s.StateDir(), keptplugins.UploadsDir, u.ID.String())
		require.NoError(t, os.Symlink(base, filepath.Join(dir, "bin")))
		_, err = s.Part(peer, u.ID, "bin/outside", 0, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonUnsafePath)

		u, err = s.Begin(peer)
		require.NoError(t, err)
		_, err = s.Part(peer, u.ID, "g", 0, b64([]byte("x")))
		require.NoError(t, err)
		dir = filepath.Join(s.StateDir(), keptplugins.UploadsDir, u.ID.String())
		require.NoError(t, os.Remove(filepath.Join(dir, "g")))
		require.NoError(t, os.Symlink(outside, filepath.Join(dir, "g")))
		_, err = s.Part(peer, u.ID, "g", 1, b64([]byte("y")))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonUnsafePath)
		got, err := os.ReadFile(outside)
		require.NoError(t, err)
		require.Equal(t, "keep", string(got), "the file the links named is unchanged")
	})

	t.Run("a FIFO or a hard link in place of a held file is refused", func(t *testing.T) {
		s, base, _ := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		_, err = s.Part(peer, u.ID, "p", 0, b64([]byte("x")))
		require.NoError(t, err)
		dir := filepath.Join(s.StateDir(), keptplugins.UploadsDir, u.ID.String())
		require.NoError(t, os.Remove(filepath.Join(dir, "p")))
		require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "p"), 0o600))
		done := make(chan error, 1)
		go func() { _, err := s.Part(peer, u.ID, "p", 1, b64([]byte("y"))); done <- err }()
		select {
		case err := <-done:
			requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonUnsafePath)
		case <-time.After(10 * time.Second):
			t.Fatal("a write to a FIFO blocked")
		}

		u, err = s.Begin(peer)
		require.NoError(t, err)
		_, err = s.Part(peer, u.ID, "h", 0, b64([]byte("x")))
		require.NoError(t, err)
		dir = filepath.Join(s.StateDir(), keptplugins.UploadsDir, u.ID.String())
		outside := filepath.Join(base, "linked")
		require.NoError(t, os.WriteFile(outside, []byte("k"), 0o600))
		require.NoError(t, os.Remove(filepath.Join(dir, "h")))
		require.NoError(t, os.Link(outside, filepath.Join(dir, "h")))
		_, err = s.Part(peer, u.ID, "h", 1, b64([]byte("y")))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonUnsafePath)
		got, err := os.ReadFile(outside)
		require.NoError(t, err)
		require.Equal(t, "k", string(got))
	})

	t.Run("a part past the declared size or out of order", func(t *testing.T) {
		s, _, _ := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		_, err = s.Part(peer, u.ID, "a", 0, b64([]byte("12")))
		require.NoError(t, err)
		for _, off := range []int64{0, 1, 3, 1 << 40, -1} {
			_, err = s.Part(peer, u.ID, "a", off, b64([]byte("x")))
			requireRefused(t, err, keptplugins.KindInvalid, "")
		}
		_, err = s.Part(peer, u.ID, "b", 5, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindInvalid, "")
		for _, data := range []string{"", "AA==", "A", "!!", "a+b/"} {
			_, err = s.Part(peer, u.ID, "a", 2, data)
			requireRefused(t, err, keptplugins.KindInvalid, "")
		}
		_, err = s.Part(peer, u.ID, "a/b", 0, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindInvalid, "")
		n, err := s.Part(peer, u.ID, "a", 2, b64([]byte("3")))
		require.NoError(t, err)
		require.EqualValues(t, 3, n)

		_, err = s.Part(peer, u.ID, plugin.SignatureFile, 0, b64(make([]byte, plugin.MaxSignatureFileBytes+1)))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooLarge)
		require.Zero(t, s.Open(), "a part over a limit drops the upload")
	})

	t.Run("an upload is its own uid's", func(t *testing.T) {
		s, _, _ := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		_, err = s.Part(peer+1, u.ID, "a", 0, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindNotFound, "")
		_, err = s.Take(peer+1, u.ID)
		requireRefused(t, err, keptplugins.KindNotFound, "")
		_, err = s.Part(peer, uuid.New(), "a", 0, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindNotFound, "")
	})

	t.Run("parallel uploads from one uid", func(t *testing.T) {
		s, _, _ := newStore(t)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() { _, err := s.Begin(peer); errs <- err })
		}
		wg.Wait()
		close(errs)
		ok, tooMany := 0, 0
		for err := range errs {
			if err == nil {
				ok++
				continue
			}
			requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooManyUploads)
			tooMany++
		}
		require.Equal(t, keptplugins.MaxOpenUploads, ok)
		require.Equal(t, 8-keptplugins.MaxOpenUploads, tooMany)

		// Parts of one path sent at once: one wins each offset, the bytes
		// on disk are exactly what was accepted.
		s2, _, _ := newStore(t)
		u, err := s2.Begin(peer)
		require.NoError(t, err)
		var accepted sync.Map
		for i := range 16 {
			wg.Go(func() {
				if _, err := s2.Part(peer, u.ID, "f", 0, b64([]byte{byte('a' + i)})); err == nil {
					accepted.Store(i, true)
				}
			})
		}
		wg.Wait()
		n := 0
		accepted.Range(func(any, any) bool { n++; return true })
		require.Equal(t, 1, n, "one part at offset 0")
		got, err := os.ReadFile(filepath.Join(s2.StateDir(), keptplugins.UploadsDir, u.ID.String(), "f"))
		require.NoError(t, err)
		require.Len(t, got, 1)
	})

	t.Run("an upload abandoned half way is removed when it expires", func(t *testing.T) {
		s, _, c := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		_, err = s.Part(peer, u.ID, "a", 0, b64([]byte("half")))
		require.NoError(t, err)
		dir := filepath.Join(s.StateDir(), keptplugins.UploadsDir, u.ID.String())
		require.DirExists(t, dir)
		c.add(keptplugins.UploadTTL)
		// Checked at the next begin.
		u2, err := s.Begin(peer)
		require.NoError(t, err)
		require.NoDirExists(t, dir)
		_, err = s.Part(peer, u.ID, "a", 4, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindNotFound, "")
		_, err = s.Take(peer, u.ID)
		requireRefused(t, err, keptplugins.KindNotFound, "")

		// And at the engine's next start.
		_, err = s.Part(peer, u2.ID, "b", 0, b64([]byte("x")))
		require.NoError(t, err)
		s2, err := keptplugins.New(s.StateDir(), c.now)
		require.NoError(t, err)
		require.Zero(t, s2.Open())
		require.NoDirExists(t, filepath.Join(s.StateDir(), keptplugins.UploadsDir))
	})
}

// TestUploadLimits: each limit of an upload, with the limits made small
// enough to reach.
func TestUploadLimits(t *testing.T) {
	small := keptplugins.Limits{PartBytes: 8, UploadBytes: 20, StorageBytes: 30, UploadPaths: 3, OpenUploads: 2}
	begin := func(t *testing.T) (*keptplugins.Store, uuid.UUID) {
		s, _, _ := newStore(t)
		s.WithLimits(small)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		return s, u.ID
	}
	t.Run("part", func(t *testing.T) {
		s, id := begin(t)
		_, err := s.Part(peer, id, "a", 0, b64(make([]byte, 9)))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooLarge)
		require.Zero(t, s.Open())
	})
	t.Run("paths", func(t *testing.T) {
		s, id := begin(t)
		for _, p := range []string{"a", "b", "c"} {
			_, err := s.Part(peer, id, p, 0, b64([]byte("x")))
			require.NoError(t, err)
		}
		_, err := s.Part(peer, id, "d", 0, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooLarge)
	})
	t.Run("upload", func(t *testing.T) {
		s, id := begin(t)
		var off int64
		for range 2 {
			n, err := s.Part(peer, id, "a", off, b64(make([]byte, 8)))
			require.NoError(t, err)
			off = n
		}
		_, err := s.Part(peer, id, "a", off, b64(make([]byte, 5)))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooLarge)
	})
	t.Run("storage, shared by every upload", func(t *testing.T) {
		s, id := begin(t)
		u2, err := s.Begin(peer + 1)
		require.NoError(t, err)
		var off int64
		for range 2 {
			n, err := s.Part(peer, id, "a", off, b64(make([]byte, 8)))
			require.NoError(t, err)
			off = n
		}
		_, err = s.Part(peer+1, u2.ID, "a", 0, b64(make([]byte, 8)))
		require.NoError(t, err)
		_, err = s.Part(peer+1, u2.ID, "a", 8, b64(make([]byte, 8)))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooLarge)
	})
	t.Run("open uploads", func(t *testing.T) {
		s, _ := begin(t)
		_, err := s.Begin(peer + 1)
		require.NoError(t, err)
		_, err = s.Begin(peer + 2)
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooManyUploads)
	})
	t.Run("manifest", func(t *testing.T) {
		s, _, _ := newStore(t)
		u, err := s.Begin(peer)
		require.NoError(t, err)
		var off int64
		chunk := make([]byte, keptplugins.MaxPartBytes)
		for off < plugin.MaxManifestBytes {
			n, err := s.Part(peer, u.ID, plugin.ManifestFile, off, b64(chunk))
			require.NoError(t, err)
			off = n
		}
		_, err = s.Part(peer, u.ID, plugin.ManifestFile, off, b64([]byte("x")))
		requireRefused(t, err, keptplugins.KindRefused, keptplugins.ReasonTooLarge)
	})
}
