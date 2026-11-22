package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

type result struct {
	code           int
	stdout, stderr string
}

// cli runs basalt with stdin and an environment holding only env.
func cli(t *testing.T, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	return cliOn(t, systemSocketHost(t), env, stdin, args...)
}

// cliOn is cli on host h: pass newFakeHost(t) for a person who is not root,
// whose config dir is short enough for the sockets next to the config.
func cliOn(t *testing.T, h *fakeHost, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cache := t.TempDir()
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string {
			if v, ok := env[k]; ok || k != envCacheDir {
				return v
			}
			return cache
		})
	c.host = h
	code := runGuard(c, args)
	return result{code, stdout.String(), stderr.String()}
}

var guardCommands = map[string]func(*cliIO, []string) int{
	"init": runInit, "passkey": runPasskey,
}

// agentFixture is the agent setUpAgent leaves set up.
type agentFixture struct {
	write, read []string
	// person, when set, registers that portal passkey, and the engine
	// uses the portal's pages; else the local pages.
	person *passkeytest.Authenticator
}

// setUpAgent sets up agent name in d as a finished setup leaves it, for
// the tests of the other commands: the guard and the agent's role
// (guardtest), the agent's credential file next to configPath, and
// engine.json naming it (config). It returns the credential file path.
func setUpAgent(t *testing.T, d *guardtest.DB, configPath, name string, fx agentFixture) string {
	t.Helper()
	a := d.NewAgent(t, name, fx.write, fx.read)
	credFile := filepath.Join(filepath.Dir(configPath), "agents", name+".url")
	require.NoError(t, os.MkdirAll(filepath.Dir(credFile), 0o700))
	require.NoError(t, config.WriteFile(credFile, []byte(a.URL+"\n")))
	pages := links.DefaultLocal
	if fx.person != nil {
		pages = links.Portal
		// As the registration page stores it: with the request's 16-byte
		// user handle.
		cred := fx.person.Credential()
		cred.UserHandle = make([]byte, 16)
		_, err := rand.Read(cred.UserHandle)
		require.NoError(t, err)
		require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, cred, dbName(t, d)+" · "+name))
	}
	settings := config.Settings{
		SocketDir: config.DefaultSocketDir(runtime.GOOS), StateDir: filepath.Join(filepath.Dir(configPath), stateDirName),
		Mode: config.ModeSameUser, PagesURL: pages, VaultDefault: config.VaultOff,
	}
	initArgs := []string{"--agent=" + name, "--prefix=" + d.Names.Prefix, "--os-user=tester"}
	_, err := config.UpsertAgentVault(configPath, settings, config.Agent{
		Name: name, OSUser: "tester", Store: config.PostgresStore(credFile), InitArgs: initArgs,
	})
	require.NoError(t, err)
	return credFile
}

// initAgent is setUpAgent for agent bot writing public.leads.
func initAgent(t *testing.T, d *guardtest.DB, configPath string) {
	t.Helper()
	setUpAgent(t, d, configPath, "bot", agentFixture{write: []string{"public.leads"}})
}

func tempConfig(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "basalt", "engine.json")
}

func TestHelpSaysOneEngineServesManyAgents(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--help"}, {"init", "-h"}} {
		code, stdout, stderr := runArgs(args...)
		require.Equal(t, exitOK, code, stderr)
		out := stdout + stderr
		for _, want := range []string{"One engine serves many agents", "one database", "basalt init --remote --agent NAME"} {
			require.Contains(t, out, want, args)
		}
	}
}

// runGuard runs args[0] on c with the path flags moved into c.paths.
func runGuard(c *cliIO, args []string) int {
	cmd := guardCommands[args[0]]
	return cmd(c, takePathFlags(c, cmd, args[1:]))
}
