//go:build unix

package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// requireNoTrustStep: a path refusal never suggests trusting a key or a
// chmod.
func requireNoTrustStep(t *testing.T, body mcp.ToolError) {
	t.Helper()
	require.NotContains(t, body.PersonMessage, "plugin trust")
	require.NotContains(t, body.PersonMessage, "chmod")
	for _, s := range body.NextSteps {
		require.NotContains(t, s.Command, "plugin trust")
		require.NotContains(t, s.Command, "chmod")
	}
}

// A plugin directory its group can write is refused UNSAFE_PATH, naming the
// directory, who can write it and what to do; the command again is the
// person's step.
func TestAddRefusesAWritableDirectoryAsUnsafePath(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	require.NoError(t, os.Mkdir(e.root, 0o755))
	require.NoError(t, os.Chmod(e.root, 0o775))
	body := refusal(t, e.run(nil, "y\n", "add", e.src, "--agents", "product_a", "--json"), reasonUnsafePath)
	require.Contains(t, body.Message, e.root)
	require.Contains(t, body.PersonMessage, e.root+" can be written by members of group ")
	require.Contains(t, body.PersonMessage, "mode 0775")
	require.Contains(t, body.PersonMessage, "Trusting a key does not fix this")
	require.Contains(t, body.PersonMessage, "Basalt does not change it")
	requireNoTrustStep(t, body)
	require.Equal(t, "basalt plugin add "+e.src+" --agents product_a --config "+e.configPath, body.NextSteps[1].Command)
	require.Contains(t, body.NextSteps[0].Text, e.root)
}

// A plugin directory that is a symlink is refused UNSAFE_PATH, saying so.
func TestAddRefusesASymlinkAsUnsafePath(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	elsewhere := filepath.Join(e.base, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o755))
	require.NoError(t, os.Symlink(elsewhere, e.root))
	body := refusal(t, e.run(nil, "y\n", "add", e.src, "--agents", "product_a", "--json"), reasonUnsafePath)
	require.Contains(t, body.PersonMessage, e.root+" is a symbolic link owned by ")
	requireNoTrustStep(t, body)
}

// A path owned by a user the rule does not allow there is refused
// UNSAFE_PATH, naming its owner and the owners allowed. No test runs as
// root, so it cannot give a directory to another user: the refusal is the
// one the path rule builds, constructed here.
func TestWrongOwnerIsAnUnsafePath(t *testing.T) {
	t.Parallel()
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
	c.goos = "linux"
	e := &pluginEnv{c: c, configPath: config.DefaultPath("linux"), mode: plugin.ModeService}
	ve := &plugin.VerifyError{
		Reason: plugin.RefusedNotTrusted, File: "/opt/basalt", Why: "is owned by a user other than root and the required owner",
		Path: &plugin.PathFault{Kind: plugin.PathOwner, UID: 4242424, GID: 0, Mode: fs.ModeDir | 0o755, Owners: []uint32{0}},
	}
	err := e.verifyRefusal(ve, "basalt plugin add /src --agents a")
	var r *pluginRefusedError
	require.ErrorAs(t, err, &r)
	require.Equal(t, reasonUnsafePath, r.reason)
	require.Contains(t, r.person, "/opt/basalt is owned by uid 4242424, but there it must be owned by root")
	require.LessOrEqual(t, len(r.person), 500)
	body := r.body()
	requireNoTrustStep(t, *body)
	require.Equal(t, mcp.ActorAgent, body.NextSteps[0].Actor)
	require.Equal(t, mcp.ActionAskPerson, body.NextSteps[0].Action)
	require.Equal(t, "basalt plugin add /src --agents a", body.NextSteps[1].Command)
}
