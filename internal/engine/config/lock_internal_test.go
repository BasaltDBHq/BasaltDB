//go:build unix

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A root writer never leaves a lock file the engine's user cannot open
// (CONTRACT.md, On the engine, Lock files).
func TestLockHandOver(t *testing.T) {
	t.Parallel()
	const engine, other = 501, 777
	for _, tc := range []struct {
		name                         string
		proc, file, dir, owner, want int
		chown                        bool
	}{
		{name: "root, its own file, the engine's directory", proc: 0, file: 0, dir: engine, owner: -1, want: engine, chown: true},
		{name: "service install names the engine's user", proc: 0, file: 0, dir: 0, owner: engine, want: engine, chown: true},
		{name: "already the engine's: left alone", proc: 0, file: engine, dir: engine, owner: -1},
		{name: "another user's file: never taken over", proc: 0, file: other, dir: engine, owner: engine},
		{name: "not root: nothing to hand over", proc: engine, file: engine, dir: engine, owner: -1},
		{name: "named owner, the engine's own directory", proc: 0, file: 0, dir: engine, owner: engine, want: engine, chown: true},
		{name: "named owner, a third user's directory: not root's to give", proc: 0, file: 0, dir: other, owner: engine},
		{name: "a root directory, owner unknown: stays root's", proc: 0, file: 0, dir: 0, owner: -1},
	} {
		got, chown := lockHandOver(tc.proc, tc.file, tc.dir, tc.owner)
		require.Equal(t, tc.chown, chown, tc.name)
		if tc.chown {
			require.Equal(t, tc.want, got, tc.name)
		}
	}
}

// A lock file the process cannot open is a LockUnusableError naming it, not
// a lock held elsewhere.
func TestLockFileUnusable(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == rootUID {
		t.Skip("root opens any file")
	}
	path := filepath.Join(t.TempDir(), "engine.json.lock")
	require.NoError(t, os.WriteFile(path, nil, 0o000))
	_, err := LockFile(path)
	var unusable *LockUnusableError
	require.True(t, errors.As(err, &unusable), "%v", err)
	require.Equal(t, path, unusable.Path)
	require.False(t, errors.Is(err, ErrLocked))

	link := filepath.Join(t.TempDir(), "agent.url.lock")
	require.NoError(t, os.Symlink(path, link))
	_, err = LockFile(link)
	require.True(t, errors.As(err, &unusable), "a symlink: %v", err)

	ok := filepath.Join(t.TempDir(), "ok.lock")
	held, err := LockConfigAs(filepath.Join(filepath.Dir(ok), "engine.json"), os.Geteuid())
	require.NoError(t, err)
	require.NoError(t, held.HandTo(os.Geteuid()), "nothing to hand over when not root")
	_, err = LockFile(filepath.Join(filepath.Dir(ok), "engine.json.lock"))
	require.ErrorIs(t, err, ErrLocked, "held until released")
	held.Release()
	release, err := LockFile(filepath.Join(filepath.Dir(ok), "engine.json.lock"))
	require.NoError(t, err)
	release()
}
