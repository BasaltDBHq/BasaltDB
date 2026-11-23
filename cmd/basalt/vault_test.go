//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

func TestVaultModeFlag(t *testing.T) {
	t.Parallel()
	var m VaultMode
	require.NoError(t, m.Set("on"))
	require.Equal(t, config.VaultOn, m.enum())
	require.NoError(t, m.Set("off"))
	require.Equal(t, config.VaultOff, m.enum())
	for _, bad := range []string{"ON", "true", "", "yes"} {
		require.Error(t, m.Set(bad), bad)
	}
	require.Empty(t, VaultMode("").enum(), "no choice keeps the config's")
}

func TestChooseVault(t *testing.T) {
	t.Parallel()
	const personWhy = "default for --operated-by=person; --vault=on to turn it on"
	const agentWhy = "default for --operated-by=agent; --vault=off to turn it off"
	for _, tc := range []struct {
		name       string
		given      VaultMode
		operatedBy OperatedBy
		pages      string
		want       vaultChoice
	}{
		{"agent default", "", OperatedByAgent, links.Portal, vaultChoice{"", VaultModeOn, agentWhy}},
		{"person default", "", OperatedByPerson, links.Portal, vaultChoice{"", VaultModeOff, personWhy}},
		{"person on the portal", VaultModeOn, OperatedByPerson, links.Portal, vaultChoice{VaultModeOn, VaultModeOff, personWhy}},
		{"agent turns it off", VaultModeOff, OperatedByAgent, links.Portal, vaultChoice{VaultModeOff, VaultModeOn, agentWhy}},
		{"off with local pages", VaultModeOff, OperatedByPerson, links.DefaultLocal, vaultChoice{VaultModeOff, VaultModeOff, personWhy}},
	} {
		got, err := chooseVault(tc.given, tc.operatedBy, tc.pages, personWhy)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}

	byAgent := vaultChoice{"", VaultModeOn, agentWhy}
	require.Equal(t, "basalt: vault: on (default for --operated-by=agent; --vault=off to turn it off)\n",
		byAgent.line(config.VaultWritten{Vault: config.VaultOn}), "the contract's line")
	require.Equal(t, "basalt: vault: off (kept from engine.json; --vault=on to change)\n",
		byAgent.line(config.VaultWritten{Vault: config.VaultOff, Kept: true}))
	require.Equal(t, "basalt: vault: off (--vault=off)\n",
		vaultChoice{VaultModeOff, VaultModeOn, agentWhy}.line(config.VaultWritten{Vault: config.VaultOff}))

	for _, pages := range []string{links.DefaultLocal, "http://localhost:7777"} {
		_, err := chooseVault(VaultModeOn, OperatedByPerson, pages, personWhy)
		require.ErrorIs(t, err, cli.ErrUsage, "--vault=on needs the portal's pages, not %s", pages)
	}
}

func TestServiceInstallKeepsTheVaultOnARerun(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "engine.json")
	spec := osservice.Spec{GOOS: "linux", Binary: fakeBin, ConfigPath: cfgPath, User: me(t)}
	install := func(a agentInstall) (string, string) {
		t.Helper()
		var lines bytes.Buffer
		a.report = func(v config.VaultWritten) { lines.WriteString(a.vaultChoice().line(v)) }
		got, err := agentSpecFromStdin(strings.NewReader("postgres://agent:pw@h/db\n"), spec, a, true, false)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(cfgPath, got.Files[0].Content, config.FileMode))
		c, err := config.Load(cfgPath)
		require.NoError(t, err)
		return c.Vault, lines.String()
	}
	a := agentInstall{name: "bot", osUser: agentOSUser(t), personUIDs: []uint32{4242}}

	a.vaultDefault = config.VaultOff
	v, line := install(a)
	require.Equal(t, config.VaultOff, v, "a new config takes the default")
	require.Equal(t, "basalt: vault: off ("+personDefaultWhy+")\n", line)

	a.vault, a.vaultDefault = config.VaultOn, ""
	v, line = install(a)
	require.Equal(t, config.VaultOn, v, "--vault is the person's choice")
	require.Equal(t, "basalt: vault: on (--vault=on)\n", line)

	a.vault, a.vaultDefault = "", config.VaultOff
	v, line = install(a)
	require.Equal(t, config.VaultOn, v, "a rerun without --vault never undoes the choice")
	require.Equal(t, "basalt: vault: on (kept from engine.json; --vault=off to change)\n", line)
}

func TestInitRemoteWritesTheVault(t *testing.T) {
	t.Parallel()
	cfg := withState(t, tempConfig(t))
	r := remote(t, cfg, "--agent", "bot")
	require.Equal(t, config.VaultOn, r.cfg.Vault, "a new engine is agent-operated with the Vault on")
	require.True(t, r.cfg.VaultEnabled(), "the portal's pages: the engine dials out exactly when vault is ON")
	require.Contains(t, r.stderr, "basalt: vault: on\n")
	fi, err := os.Stat(cfg)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), fi.Mode().Perm())

	// A rerun keeps the config's choice: the engine never starts dialing
	// out on its own.
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))
	editConfig(t, cfg, func(c *config.Config) { c.Vault = config.VaultOff })
	again := remote(t, cfg, "--agent", "bot")
	require.Equal(t, config.VaultOff, again.cfg.Vault)
	require.False(t, again.cfg.VaultEnabled())
	require.Contains(t, again.stderr, "basalt: vault: off (kept from engine.json)\n")
}

func TestConfigUpsertAppliesTheVaultDefaultOnlyWhenThereIsNone(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", Store: config.PostgresStore("/c/bot.url")}
	upsert := func(s config.Settings) config.VaultWritten {
		t.Helper()
		v, err := config.UpsertAgentVault(path, s, bot)
		require.NoError(t, err)
		c, err := config.Load(path)
		require.NoError(t, err)
		require.Equal(t, v.Vault, c.Vault, "what it says it wrote")
		return v
	}
	require.Equal(t, config.VaultWritten{Vault: config.VaultOn},
		upsert(config.Settings{SocketDir: "/s", PagesURL: links.Portal, OperatedBy: "AGENT", VaultDefault: config.VaultOn}), "a new config: the default")
	require.Equal(t, config.VaultWritten{Vault: config.VaultOff}, upsert(config.Settings{OperatedBy: "AGENT", Vault: config.VaultOff}))
	require.Equal(t, config.VaultWritten{Vault: config.VaultOff, Kept: true},
		upsert(config.Settings{OperatedBy: "AGENT", VaultDefault: config.VaultOn}), "same operatedBy: the person's choice stays")
	require.Equal(t, config.VaultWritten{Vault: config.VaultOff},
		upsert(config.Settings{OperatedBy: "PERSON", VaultDefault: config.VaultOff}), "a new operatedBy: its default")
	require.Equal(t, config.VaultWritten{Vault: config.VaultOn},
		upsert(config.Settings{OperatedBy: "AGENT", VaultDefault: config.VaultOn}), "and back")
	require.Equal(t, config.VaultWritten{Vault: config.VaultOn, Kept: true}, upsert(config.Settings{}), "nothing asked: kept")
}

func TestConfigUpsertKeepsTheVaultWithoutAChoice(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", Store: config.PostgresStore("/c/bot.url")}
	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/s", PagesURL: links.Portal, Vault: config.VaultOn}, bot))
	require.NoError(t, config.UpsertAgent(path, config.Settings{SocketDir: "/s"}, bot))
	c, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, config.VaultOn, c.Vault)
	require.NoError(t, config.UpsertAgent(path, config.Settings{Vault: config.VaultOff}, bot))
	c, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, config.VaultOff, c.Vault)
	require.Error(t, config.UpsertAgent(path, config.Settings{Vault: "on"}, bot), "engine.json holds ON or OFF")
}
