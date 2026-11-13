package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestLoadApprovalPage(t *testing.T) {
	t.Parallel()
	c, err := config.Load(write(t, "engine.json", `{
		"socketDir": "/s",
		"agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}],
		"approvalPage": "http://localhost:8787/approve/"
	}`, 0o600))
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8787/approve/", c.ApprovalPage)
	base, err := c.PagesBase()
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8787", base, "the older approvalPage key gives its origin")
}

// The Telegram notifier is parked outside the engine: a config that still
// has notify is refused, as any unknown key is, with a message naming it.
func TestLoadRefusesParkedNotify(t *testing.T) {
	t.Parallel()
	for name, notify := range map[string]string{
		"telegram": `{"telegram": {"botTokenFile": "/t", "chatId": "1"}}`,
		"empty":    `{}`,
		"null":     `null`,
	} {
		_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}], "notify": `+notify+`}`, 0o600))
		require.ErrorContains(t, err, `"notify" is no longer supported`, name)
		require.ErrorContains(t, err, "Telegram", name)
	}
}
