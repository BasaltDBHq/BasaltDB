package config_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// RootCredentialPath is agents/<agent>.url next to the config, absolute,
// for a relative config path as well; a spelling of it is the same path.
func TestRootCredentialPath(t *testing.T) {
	t.Parallel()
	want, err := filepath.Abs(filepath.Join("etc", "agents", "bot.url"))
	require.NoError(t, err)
	for _, named := range []string{want, "etc/agents/bot.url", "etc/agents/sub/../bot.url"} {
		got, err := config.RootCredentialPath("etc/engine.json", "bot", named)
		require.NoError(t, err, named)
		require.Equal(t, want, got)
	}
	_, err = config.RootCredentialPath("etc/engine.json", "bot", "etc/agents/other.url")
	var pe *config.CredentialPathError
	require.True(t, errors.As(err, &pe), err)
	require.Equal(t, want, pe.Want)
	require.ErrorContains(t, err, "the config names the credential file etc/agents/other.url, not "+want+" where basalt init puts it")
}
