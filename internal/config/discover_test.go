package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func touch(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
}

func TestDiscoverFindsTheOneThatExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	system, user := filepath.Join(dir, "etc", "engine.json"), filepath.Join(dir, "home", "engine.json")

	got, err := Discover(system, user)
	require.NoError(t, err)
	require.Equal(t, system, got, "none found: the system path, where init creates it")

	touch(t, user)
	got, err = Discover(system, user)
	require.NoError(t, err)
	require.Equal(t, user, got)

	require.NoError(t, os.Remove(user))
	touch(t, system)
	got, err = Discover(system, user)
	require.NoError(t, err)
	require.Equal(t, system, got)
}

func TestDiscoverBothFoundNamesBoth(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	system, user := filepath.Join(dir, "etc", "engine.json"), filepath.Join(dir, "home", "engine.json")
	touch(t, system)
	touch(t, user)

	got, err := Discover(system, user)
	require.Empty(t, got)
	var both *BothConfigsError
	require.True(t, errors.As(err, &both))
	require.Contains(t, err.Error(), system)
	require.Contains(t, err.Error(), user)
}

func TestDiscoverWithoutUserPathUsesSystem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	system := filepath.Join(dir, "engine.json")
	touch(t, system)
	got, err := Discover(system, "")
	require.NoError(t, err)
	require.Equal(t, system, got)
}

// A system config this person cannot even stat (its directory is the
// engine's own) is still the config: it never falls through to the user's.
func TestDiscoverSystemPathThatCannotBeInspectedCountsAsFound(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can inspect anything")
	}
	t.Parallel()
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	system := filepath.Join(locked, "engine.json")
	touch(t, system)
	require.NoError(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	user := filepath.Join(dir, "home", "engine.json")
	touch(t, user)

	_, err := Discover(system, user)
	var both *BothConfigsError
	require.True(t, errors.As(err, &both))

	require.NoError(t, os.Remove(user))
	got, err := Discover(system, user)
	require.NoError(t, err)
	require.Equal(t, system, got)
}

func TestUserPath(t *testing.T) {
	t.Parallel()
	require.Equal(t, "/home/me/.config/basalt/engine.json", UserPath("/home/me/.config"))
}
