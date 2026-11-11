package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestLoadNotifyAndApprovalPage(t *testing.T) {
	t.Parallel()
	c, err := config.Load(write(t, "engine.json", `{
		"socketDir": "/s",
		"agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}],
		"approvalPage": "http://localhost:8787/approve/",
		"notify": {"telegram": {"botTokenFile": "/etc/basalt/telegram.token", "chatId": "-100123"}}
	}`, 0o600))
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8787/approve/", c.ApprovalPage)
	require.Equal(t, &config.Telegram{BotTokenFile: "/etc/basalt/telegram.token", ChatID: "-100123"}, c.Notify.Telegram)

	plain, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}]}`, 0o600))
	require.NoError(t, err)
	require.Nil(t, plain.Notify.Telegram)

	for name, notify := range map[string]string{
		"no token file":   `{"telegram": {"chatId": "1"}}`,
		"no chat":         `{"telegram": {"botTokenFile": "/t"}}`,
		"token in config": `{"telegram": {"botTokenFile": "/t", "chatId": "1", "botToken": "123:abc"}}`,
	} {
		_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}], "notify": `+notify+`}`, 0o600))
		require.Error(t, err, name)
	}
}
