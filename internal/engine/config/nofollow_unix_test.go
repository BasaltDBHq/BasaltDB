//go:build unix

package config_test

import (
	"os"
	"path/filepath"
	"testing"

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
