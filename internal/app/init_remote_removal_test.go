package app

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

// removalConfig is an agent-operated engine whose agent has a credential:
// a connect-only setup the person confirmed.
func removalConfig(t *testing.T) (string, remoteRun) {
	t.Helper()
	cfg := connectOnlyConfig(t)
	first := remote(t, cfg, connectOnlyArgs...)
	require.NoError(t, os.WriteFile(first.credFile, []byte("postgresql://basalt_agent_bot:pw@db.example.com:5432/shop?sslmode=verify-full\n"), 0o600))
	return cfg, first
}

// basalt init --remove on an agent-operated engine makes a removal link:
// an AGENT code with no change for the credential's database, carrying the
// engine's key, recorded as the agent's pending removal next to its
// pending setup, and printed again while it lives. It logs in nowhere.
func TestInitRemoteRemoveMakesARemovalLink(t *testing.T) {
	t.Parallel()
	cfg, first := removalConfig(t)
	r := remote(t, cfg, "--agent", "bot", "--remove")

	require.True(t, r.res.Removal)
	require.Equal(t, links.Portal+"/connect#remove="+r.res.Code, r.res.ConnectURL)
	require.Equal(t, setupcode.KindAgent, r.payload.Kind)
	require.NotNil(t, r.payload.Target)
	require.Equal(t, "shop", r.payload.Target.Database)
	require.Equal(t, "db.example.com", r.payload.Target.Host)
	require.NotNil(t, r.payload.Engine, "the engine collects its removal with its key")
	require.Empty(t, r.payload.Agent.Verifier, "no new password")
	require.Empty(t, r.payload.Agent.Write)
	require.Nil(t, r.payload.Agent.AllTables)

	a := r.cfg.Agents[0]
	require.NotNil(t, a.Removal)
	require.Equal(t, r.payload.SetupID, a.Removal.SetupID)
	require.Equal(t, r.res.Code, a.Removal.Code)
	require.NotNil(t, a.Setup, "the pending setup is kept")
	require.Equal(t, first.res.SetupID, a.Setup.SetupID)

	require.Contains(t, r.stdout, "Removal link for bot")
	require.Contains(t, r.stdout, "\n\n"+r.res.ConnectURL+"\n\n")
	require.NotContains(t, r.stdout, "mcp --agent", "a removal registers no MCP server")
	_, err := setupcode.Decode(r.res.Code)
	require.NoError(t, err)

	again := remote(t, cfg, "--agent", "bot", "--remove")
	require.True(t, again.res.Reused)
	require.Equal(t, r.res.Code, again.res.Code)
	require.Contains(t, again.stderr, "a removal link is pending")
}

// Without --remote, --remove on a config this user finds whose operatedBy
// is AGENT is the connect page's removal, not the local page's.
func TestInitRemoveOnAnAgentOperatedEngineRoutesToTheConnectPage(t *testing.T) {
	t.Parallel()
	cfg, _ := removalConfig(t)
	out := noDB(t).cli(t, "--config", cfg, "--agent", "bot", "--remove")
	require.Equal(t, cli.ExitOK, out.code, out.stderr)
	require.Contains(t, out.stdout, links.Portal+"/connect#"+setup.RemovalPrefix)
}

// With no credential for the agent there is nothing to remove.
func TestInitRemoteRemoveWithNothingToRemove(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	remote(t, cfg, connectOnlyArgs...)
	e := noDB(t)
	var stdout, stderr bytes.Buffer
	c := e.io(&stdout, &stderr)
	_, err := setupcli.InitRemote(c, setupHost{}, takePathFlags(c, runInit, []string{"--remote", "--config", cfg, "--agent", "bot", "--remove"}))
	require.ErrorIs(t, err, setup.ErrNothingToRemove)
	require.False(t, strings.Contains(stdout.String(), "#remove="))
}
