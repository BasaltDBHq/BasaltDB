//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// mcpStartDeadline is well under the shim's 15s autostart wait, so a
// command that looks for the engine in the wrong socket directory fails
// this test instead of hanging until DefaultStartWait.
const mcpStartDeadline = 10 * time.Second

// userConfigHost is osHost with a fixed UserConfigDir, so basalt mcp
// without --config finds the per-user config init left, while euid still
// matches the file owner (or auto-start is skipped).
type userConfigHost struct {
	osHost
	dir string
}

func (h userConfigHost) UserConfigDir() (string, error) { return h.dir, nil }

// Running the mcpCommand from a non-root init --remote reaches the engine
// in the per-user run directory, with no 15s autostart wait. The printed
// command names only the agent: basalt mcp finds the config, and the socket
// directory in it.
func TestInitRemoteMCPCommandReachesTheEngineDefaultConfig(t *testing.T) {
	t.Setenv(testAsBasaltEnv, "1")
	skipIfSystemConfig(t)
	d, dbURL := remoteDB(t)
	h := newFakeHost(t)
	e := remoteEnv{host: h}

	// The person confirmed the database on the connect page: the engine
	// wrote the credential, and the database does not record the setup
	// yet. The Vault is off so the engine reaches no portal here.
	first := remoteWith(t, e, "", "--agent", "bot")
	cfg := filepath.Join(h.configDir, config.UserDirName, "engine.json")
	loaded, err := config.Load(cfg)
	require.NoError(t, err)
	credFile := loaded.Agents[0].Store.CredentialFile
	require.NoError(t, config.WriteFile(credFile, []byte(agentDSN(t, dbURL, d.Names.Prefix, "bot", "0123abcd")+"\n")))
	require.NoError(t, os.Remove(config.SecretPath(credFile, "bot")))
	editConfig(t, cfg, func(c *config.Config) {
		c.Vault = config.VaultOff
		c.Agents[0].Setup.AwaitingAddress = false
	})

	res := remoteWith(t, e, "", "--agent", "bot").res
	require.NotEqual(t, first.res.SetupID, res.SetupID)
	socketDir := filepath.Join(h.configDir, config.UserDirName, "run")
	require.Equal(t, []string{fakeBin, "mcp", "--agent", "bot"}, res.MCPCommand)

	runViaConnect(t, d, res.Code, "public.leads")

	// osHost with the same UserConfigDir init used, so basalt mcp finds the
	// per-user config and auto-start sees the real file owner.
	requireMCPCommandReachesEngine(t, res.MCPCommand, userConfigHost{dir: h.configDir}, socketDir)
}

// requireMCPCommandReachesEngine runs the printed mcpCommand (argv after
// "basalt mcp") and requires a status tool call that finds the engine
// reachable, well under the 15s autostart wait.
func requireMCPCommandReachesEngine(t *testing.T, mcpCommand []string, h cli.Machine, socketDir string) {
	t.Helper()
	t.Cleanup(func() {
		if pid, up, _ := pidlock.Running(app.LockPath(socketDir)); up {
			if ppid, err := parentOf(pid); err == nil {
				_ = syscall.Kill(ppid, syscall.SIGTERM)
			}
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), mcpStartDeadline)
	defer cancel()
	in, inW := io.Pipe()
	var errBuf bytes.Buffer
	outR, outW := io.Pipe()
	exited := make(chan int, 1)
	began := time.Now()
	go func() {
		// argv is the printed command without the program and "mcp" subcommand.
		exited <- runMCPOn(ctx, mcpCommand[2:], cli.Stdio{In: in, Out: outW, Err: &errBuf}, h, appMCPHost{})
		_ = outW.Close()
	}()
	_, err := fmt.Fprintf(inW, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(outR)
	_, err = r.ReadString('\n')
	require.NoError(t, err, errBuf.String())
	line, err := r.ReadString('\n')
	require.NoError(t, err, errBuf.String())
	require.Less(t, time.Since(began), mcpStartDeadline, "status must answer without the 15s autostart wait: %s", errBuf.String())
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &resp), line+errBuf.String())
	require.Len(t, resp.Result.Content, 1, line+errBuf.String())
	var report struct {
		Ready  bool `json:"ready"`
		Engine struct {
			Reachable bool `json:"reachable"`
		} `json:"engine"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &report))
	require.True(t, report.Engine.Reachable, resp.Result.Content[0].Text)
	require.True(t, report.Ready, resp.Result.Content[0].Text)

	require.NoError(t, inW.Close())
	require.Equal(t, cli.ExitOK, <-exited, errBuf.String())
}
