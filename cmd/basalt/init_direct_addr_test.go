package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// --direct-addr is for an agent-operated engine on the portal's pages, and
// takes off or a loopback address and port (CONTRACT.md, Direct transport).
func TestInitDirectAddrUsage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"person-operated", []string{"--direct-addr", "127.0.0.1:8787"}, "only for --operated-by=agent"},
		{"local passkey origin", []string{"--operated-by", "agent", "--dev-local-pages", "--direct-addr", "127.0.0.1:8787"}, "portal"},
		{"not loopback", []string{"--operated-by", "agent", "--direct-addr", "0.0.0.0:8787"}, "loopback"},
		{"a host name", []string{"--operated-by", "agent", "--direct-addr", "localhost:8787"}, "loopback"},
		{"no port", []string{"--operated-by", "agent", "--direct-addr", "127.0.0.1"}, "loopback"},
		{"empty", []string{"--operated-by", "agent", "--direct-addr="}, "host:port or off"},
	} {
		r := cli(t, nil, "", append([]string{"init", "--agent", "x2"}, tc.args...)...)
		require.Equal(t, exitUsage, r.code, tc.name+": "+r.stderr)
		require.Contains(t, r.stderr, tc.want, tc.name)
	}
	cfg := tempConfig(t)
	for _, v := range []string{"0.0.0.0:8787", "example.com:80", "127.0.0.1", ""} {
		r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--database-url", supabaseURL, "--direct-addr="+v)
		require.Equal(t, exitUsage, r.code, v+": "+r.stderr)
	}
	require.NoFileExists(t, cfg, "a refused address writes nothing")
}

// init sets directAddr in engine.json, saves the flag, a re-run without it
// keeps the value, and off turns it off.
func TestInitDirectAddrIsWrittenAndKept(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	base := []string{
		"init", "--agent", "x1", "--write", "public.leads", "--prefix", d.Names.Prefix, "--operated-by", "agent",
		"--config", cfgPath, "--os-user", "tester", "--yes", "--skip-passkey",
	}
	env := map[string]string{envAdminURL: d.URL}
	load := func() config.Config {
		t.Helper()
		c, err := config.Load(cfgPath)
		require.NoError(t, err)
		return c
	}

	r := cli(t, env, "", append(append([]string{}, base...), "--direct-addr", "127.0.0.1:8787")...)
	require.Equal(t, exitOK, r.code, r.stderr)
	c := load()
	require.Equal(t, "127.0.0.1:8787", c.DirectAddr)
	require.Equal(t, links.Portal, c.PagesURL)
	require.Contains(t, c.Agents[0].InitArgs, "--direct-addr=127.0.0.1:8787")
	cmds, err := agent.NewCommands("x1", cfgPath, "linux", c.Agents[0].InitArgs)
	require.NoError(t, err, "the saved flag round-trips")
	require.Contains(t, cmds.Init("--add-passkey"), "--direct-addr=127.0.0.1:8787")
	require.NotContains(t, cmds.InitRemote("--new-code"), "direct-addr", "init --remote's saved flags leave it out")

	// Without the flag the engine.json value stays.
	r = cli(t, env, "", base...)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, "127.0.0.1:8787", load().DirectAddr)

	r = cli(t, env, "", append(append([]string{}, base...), "--direct-addr", "off")...)
	require.Equal(t, exitOK, r.code, r.stderr)
	c = load()
	require.Equal(t, "off", c.DirectAddr)
	direct, err := c.Direct()
	require.NoError(t, err)
	require.Empty(t, direct)
}

// init --remote takes --direct-addr too, whatever the operator.
func TestInitRemoteDirectAddr(t *testing.T) {
	t.Parallel()
	cfgPath := tempConfig(t)
	r := remote(t, cfgPath, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL, "--direct-addr", "127.0.0.1:8787")
	require.Equal(t, "127.0.0.1:8787", r.cfg.DirectAddr)
	require.Contains(t, r.cfg.Agents[0].InitArgs, "--direct-addr=127.0.0.1:8787")

	again := remote(t, cfgPath, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	require.Equal(t, "127.0.0.1:8787", again.cfg.DirectAddr, "a re-run without it keeps engine.json's value")

	off := remote(t, cfgPath, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL, "--direct-addr", "off")
	require.Equal(t, "off", off.cfg.DirectAddr)
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.True(t, strings.Contains(string(raw), `"directAddr": "off"`))
}
