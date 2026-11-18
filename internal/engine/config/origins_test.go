package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// loadWith writes a config with the given top-level keys and loads it.
func loadWith(t *testing.T, keys map[string]any) error {
	t.Helper()
	c := map[string]any{
		"socketDir": "/run/basalt",
		"agents":    []map[string]any{{"name": "bot", "osUser": "bot", "store": map[string]any{"kind": "POSTGRES", "credentialFile": "/etc/basalt/agents/bot.url"}}},
	}
	for k, v := range keys {
		c[k] = v
	}
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, raw, config.FileMode))
	_, err = config.Load(path)
	return err
}

// The page origins are a closed list (CONTRACT.md, Page origins; CO-8).
func TestPageOriginsAreAClosedList(t *testing.T) {
	t.Parallel()
	const portal, local = "https://portal.basaltvault.app", "http://localhost:8787"
	for _, tc := range []struct {
		name string
		keys map[string]any
		err  string
	}{
		{name: "person: local", keys: map[string]any{"pagesUrl": local}},
		{name: "person: default local", keys: map[string]any{}},
		{name: "person: portal", keys: map[string]any{"pagesUrl": portal}},
		{name: "agent: portal", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": portal}},
		{name: "agent: local refused", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": local}, err: "an agent-operated engine uses the portal's pages"},
		{name: "agent: default local refused", keys: map[string]any{"operatedBy": "AGENT"}, err: "an agent-operated engine uses the portal's pages"},
		{name: "agent: loopback IP refused", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": "http://127.0.0.1:8787"}, err: "the local pages run only at localhost"},
		{name: "agent: local with devLocalPages", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": local, "devLocalPages": true}},
		{name: "devLocalPages on a person's engine refused", keys: map[string]any{"pagesUrl": local, "devLocalPages": true}, err: "only for an agent-operated engine"},
		{name: "devLocalPages on the portal refused", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": portal, "devLocalPages": true}, err: "needs a local pagesUrl"},
		{name: "devLocalPages with the pages off refused", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": local, "devLocalPages": true, "pagesAddr": "off"}, err: "serve the pages on loopback"},
		{name: "person: pages.dev refused", keys: map[string]any{"pagesUrl": "https://basalt-portal.pages.dev"}, err: "use https://portal.basaltvault.app or a local"},
		{name: "agent: pages.dev refused", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": "https://abc.basalt-portal.pages.dev"}, err: "use https://portal.basaltvault.app or a local"},
		{name: "agent: pages.dev refused with devLocalPages", keys: map[string]any{"operatedBy": "AGENT", "pagesUrl": "https://basalt-portal.pages.dev", "devLocalPages": true}, err: "use https://portal.basaltvault.app or a local"},
		{name: "the old console refused", keys: map[string]any{"pagesUrl": "https://console.basaltvault.app"}, err: "use https://portal.basaltvault.app or a local"},
	} {
		err := loadWith(t, tc.keys)
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
	}
}

// basalt init never writes a config the engine would refuse: the upsert
// checks the origins, and devLocalPages goes with the pages it is for.
func TestUpsertChecksTheOrigins(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	a := config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore("/etc/basalt/agents/bot.url")}
	err := config.UpsertAgent(path, config.Settings{SocketDir: "/run/basalt", OperatedBy: "AGENT", PagesURL: "http://localhost:8787"}, a)
	require.ErrorContains(t, err, "an agent-operated engine uses the portal's pages")
	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/run/basalt", OperatedBy: "AGENT", PagesURL: "http://localhost:8787", DevLocalPages: true}, a))
	c, err := config.Load(path)
	require.NoError(t, err)
	require.True(t, c.DevLocalPages)
	require.NoError(t, config.UpsertAgent(path, config.Settings{PagesURL: "https://portal.basaltvault.app"}, a), "init again without the flag")
	c, err = config.Load(path)
	require.NoError(t, err)
	require.False(t, c.DevLocalPages, "moving to the portal drops the exception")
}
