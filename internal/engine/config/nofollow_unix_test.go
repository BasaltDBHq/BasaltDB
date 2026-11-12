//go:build unix

package config_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestLoadNoFollowRefusesSymlinkAndHardlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte("root only"), 0o600))

	link := filepath.Join(dir, "engine.json")
	require.NoError(t, os.Symlink(secret, link))
	_, err := config.LoadNoFollow(link)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "root only")

	hard := filepath.Join(dir, "hard.json")
	require.NoError(t, os.Link(secret, hard))
	_, err = config.LoadNoFollow(hard)
	require.ErrorContains(t, err, "hard link")
}

// fifoWait bounds how long a FIFO test waits before it calls the open hung.
const fifoWait = 5 * time.Second

// withinFIFOWait runs fn and fails the test if it does not return in time.
func withinFIFOWait(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(fifoWait):
		t.Fatal("opening a FIFO blocked")
		return nil
	}
}

func TestLoadAndUpsertRefuseFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	err := withinFIFOWait(t, func() error {
		_, err := config.LoadNoFollow(path)
		return err
	})
	require.ErrorContains(t, err, "not a regular file")

	err = withinFIFOWait(t, func() error {
		_, err := config.Upserted(path, config.Settings{}, config.Agent{Name: "bot"})
		return err
	})
	require.ErrorContains(t, err, "not a regular file")
}

func TestUpsertedRefusesSymlinkedConfig(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte("{}"), 0o600))
	link := filepath.Join(dir, "engine.json")
	require.NoError(t, os.Symlink(secret, link))

	_, err := config.Upserted(link, config.Settings{}, config.Agent{Name: "bot"})

	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrNotExist)
}
