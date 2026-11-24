package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// basalt mcp --agent with two engine configs, the agent in neither: it
// stops and names the agent and both paths, where it used to stop on the
// two configs whatever the agent.
func TestMCPNamesTheAgentWhenNoConfigHoldsIt(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	system := filepath.Join(h.configDir, "etc", "engine.json")
	user := filepath.Join(h.configDir, "basalt", "engine.json")
	for _, p := range []string{system, user} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(`{"socketDir": "/s", "agents": [{"name": "other", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/x/other.url"}}]}`), 0o600))
	}
	var out, errw bytes.Buffer
	code := enginecli.RunMCPAt(context.Background(), []string{"--agent", "demo_bot"},
		cli.Stdio{In: strings.NewReader(""), Out: &out, Err: &errw}, h, engineCLIHost{}, system)
	require.Equal(t, cli.ExitError, code, errw.String())
	require.Contains(t, errw.String(), "demo_bot")
	require.Contains(t, errw.String(), system)
	require.Contains(t, errw.String(), user)
}
