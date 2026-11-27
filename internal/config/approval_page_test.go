package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

func TestLoadApprovalPage(t *testing.T) {
	t.Parallel()
	c, err := config.Load(write(t, "engine.json", `{
		"socketDir": "/s",
		"agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}],
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
		_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}], "notify": `+notify+`}`, 0o600))
		require.ErrorContains(t, err, `"notify" is no longer supported`, name)
		require.ErrorContains(t, err, "Telegram", name)
	}
}

// An engine.json from before the last breaking release (an agent with its
// own credentialFile) is refused with what fixes it, basalt init, not the
// decoder's unknown-field text.
func TestLoadRefusesAConfigFromBeforeTheLastBreakingRelease(t *testing.T) {
	t.Parallel()
	path := write(t, "engine.json", `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c/a.cred"}]}`, 0o600)
	_, err := config.Load(path)
	require.True(t, config.IsBreaking(err))
	require.EqualError(t, err, "config "+path+": it was written by a BasaltDB release before the last breaking one (breaking 0, this basalt needs 1): "+
		"run basalt init, which moves it aside and sets this computer up again")
}

// An engine.json from an older basalt init carries the agent's saved
// flags in "initArgs". Nothing reads them any more (the database's grants
// are the only record of an agent's tables), but the file still loads,
// with every other field, and the next write leaves the key out.
func TestLoadIgnoresOldInitArgs(t *testing.T) {
	t.Parallel()
	path := write(t, "engine.json", `{"socketDir": "/s", "operatedBy": "AGENT", "pagesUrl": "https://portal.basaltvault.app", "agents": [
		{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c/a.url"},
		 "initArgs": ["--agent=a", "--write=public.leads", "--all-tables=true", "--operated-by=agent"]},
		{"name": "b", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c/b.url"}}]}`, 0o600)
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "AGENT", c.OperatedBy)
	require.Equal(t, []config.Agent{
		{Name: "a", OSUser: "u", Store: config.PostgresStore("/c/a.url")},
		{Name: "b", OSUser: "u", Store: config.PostgresStore("/c/b.url")},
	}, c.Agents)

	_, err = config.UpsertAgentVault(path, config.Settings{}, config.Agent{Name: "b", OSUser: "u", Store: config.PostgresStore("/c/b.url")})
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "initArgs", "the next write drops the old key")
	_, err = config.Load(path)
	require.NoError(t, err)

	// Any other unknown agent key is still refused.
	other := write(t, "engine.json", `{"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}, "initArg": []}]}`, 0o600)
	_, err = config.Load(other)
	require.ErrorContains(t, err, "unknown field")
}
