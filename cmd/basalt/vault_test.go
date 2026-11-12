//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
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
	for _, tc := range []struct {
		name       string
		given      VaultMode
		operatedBy OperatedBy
		pages      string
		want       vaultChoice
	}{
		{"agent default", "", OperatedByAgent, links.Portal,
			vaultChoice{VaultModeOn, "default for --operated-by=agent; --vault=off to turn it off"}},
		{"person default", "", OperatedByPerson, links.Portal, vaultChoice{VaultModeOff, personWhy}},
		{"person on the portal", VaultModeOn, OperatedByPerson, links.Portal, vaultChoice{VaultModeOn, "--vault=on"}},
		{"agent turns it off", VaultModeOff, OperatedByAgent, links.Portal, vaultChoice{VaultModeOff, "--vault=off"}},
		{"off with local pages", VaultModeOff, OperatedByPerson, links.DefaultLocal, vaultChoice{VaultModeOff, "--vault=off"}},
	} {
		got, err := chooseVault(tc.given, tc.operatedBy, tc.pages, personWhy)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
	require.Equal(t, "basalt: vault: on (default for --operated-by=agent; --vault=off to turn it off)\n",
		vaultChoice{VaultModeOn, "default for --operated-by=agent; --vault=off to turn it off"}.line(), "the contract's line")

	for _, pages := range []string{links.DefaultLocal, "http://localhost:7777", links.HostedConsole} {
		_, err := chooseVault(VaultModeOn, OperatedByPerson, pages, personWhy)
		require.ErrorIs(t, err, errUsage, "--vault=on needs the portal's pages, not %s", pages)
	}
}

func TestInitRefusesVaultOnWithLocalPagesBeforeAnything(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--vault=on"},
		{"--vault", "on", "--passkey-origin", "http://localhost:7777"},
		{"--vault=on", "--passkey-origin", links.HostedConsole},
		{"--vault=maybe"},
	} {
		cfg := tempConfig(t)
		r := cliNoDB(t, append([]string{"init", "--agent", "bot", "--write", "public.leads", "--no-service", "--config", cfg}, args...)...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, r.stdout, "no SQL: nothing ran")
		require.NoFileExists(t, cfg)
	}
}

func TestEngineSettingsWriteTheVaultChoice(t *testing.T) {
	t.Parallel()
	f := initFlags{configPath: "/etc/basalt/engine.json", socketDir: "/run/basalt", vault: vaultChoice{mode: VaultModeOff}}
	require.Equal(t, config.VaultOff, engineSettings(f, "linux").Vault)
	f.vault.mode = VaultModeOn
	require.Equal(t, config.VaultOn, engineSettings(f, "linux").Vault)
	require.Contains(t, serviceInstallArgs(f, "/b"), "--vault=on")
}

func TestInitRemoteWritesTheVault(t *testing.T) {
	t.Parallel()
	base := []string{"--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL}
	for _, tc := range []struct {
		name  string
		args  []string
		want  string
		line  string
		dials bool
	}{
		{"person default", nil, config.VaultOff,
			"basalt: vault: off (default for --operated-by=person; --vault=on to turn it on)\n", false},
		{"agent default", []string{"--operated-by", "agent"}, config.VaultOn,
			"basalt: vault: on (default for --operated-by=agent; --vault=off to turn it off)\n", true},
		{"agent turns it off", []string{"--operated-by", "agent", "--vault=off"}, config.VaultOff,
			"basalt: vault: off (--vault=off)\n", false},
		{"person turns it on", []string{"--vault", "on"}, config.VaultOn, "basalt: vault: on (--vault=on)\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := tempConfig(t)
			r := remote(t, cfg, append(append([]string{}, base...), tc.args...)...)
			require.Equal(t, tc.want, r.cfg.Vault)
			require.Equal(t, tc.dials, r.cfg.VaultEnabled(), "the portal's pages: the engine dials out exactly when vault is ON")
			require.Contains(t, r.stderr, tc.line)
			fi, err := os.Stat(cfg)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(config.FileMode), fi.Mode().Perm())
		})
	}

	t.Run("a rerun writes its own choice", func(t *testing.T) {
		t.Parallel()
		cfg := tempConfig(t)
		first := remote(t, cfg, append(append([]string{}, base...), "--operated-by", "agent", "--vault=off")...)
		require.Equal(t, config.VaultOff, first.cfg.Vault)
		again := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--operated-by", "agent")
		require.Equal(t, config.VaultOn, again.cfg.Vault, "no --vault: the default for this run, printed")
		require.Contains(t, again.stderr, "basalt: vault: on (default for --operated-by=agent; --vault=off to turn it off)\n")
	})
}

func TestConfigUpsertKeepsTheVaultWithoutAChoice(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	bot := config.Agent{Name: "bot", OSUser: "alice", CredentialFile: "/c/bot.url"}
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

// engineKeys makes the engine's key file in a new state directory, as the
// engine does on its first start, and returns the directory and the keys.
func engineKeys(t *testing.T) (string, *channel.EngineKeys) {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	keys, err := channel.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), time.Now)
	require.NoError(t, err)
	return stateDir, keys
}

// keyMaterial is every private value in the key file: what no output may
// carry.
func keyMaterial(t *testing.T, stateDir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDir, channel.KeyFileName))
	require.NoError(t, err)
	var f map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &f))
	var out []string
	for _, k := range []string{"signingKey", "boxKey"} {
		v, ok := f[k]
		require.True(t, ok, k)
		var s string
		if json.Unmarshal(v, &s) == nil {
			out = append(out, s)
			continue
		}
		var obj map[string]string
		require.NoError(t, json.Unmarshal(v, &obj), k)
		for _, s := range obj {
			out = append(out, s)
		}
	}
	require.NotEmpty(t, out)
	return out
}

func requireNoKeyMaterial(t *testing.T, stateDir, out string) {
	t.Helper()
	for _, secret := range keyMaterial(t, stateDir) {
		require.NotEmpty(t, secret)
		require.NotContains(t, out, secret, "a private key")
		if len(secret) > 32 {
			require.NotContains(t, out, secret[:32], "part of a private key")
		}
	}
}

func TestLocalVault(t *testing.T) {
	t.Parallel()
	portalOn := config.Config{Vault: config.VaultOn, PagesURL: links.Portal}

	t.Run("no key file yet", func(t *testing.T) {
		t.Parallel()
		report, id := localVault(portalOn, filepath.Join(t.TempDir(), "state"))
		require.Nil(t, report)
		require.Nil(t, id)
	})
	t.Run("off", func(t *testing.T) {
		t.Parallel()
		stateDir, keys := engineKeys(t)
		for _, cfg := range []config.Config{{}, {Vault: config.VaultOff, PagesURL: links.Portal}, {Vault: config.VaultOn, PagesURL: links.DefaultLocal}} {
			report, id := localVault(cfg, stateDir)
			require.Equal(t, &agent.VaultStatus{State: string(vault.StateOff), EngineID: keys.EngineID(), Fingerprint: keys.Fingerprint()}, report)
			require.Nil(t, id)
		}
	})
	t.Run("on: the state is the engine's", func(t *testing.T) {
		t.Parallel()
		stateDir, keys := engineKeys(t)
		report, id := localVault(portalOn, stateDir)
		require.Nil(t, report, "only the running engine knows the connection")
		require.Equal(t, &agent.VaultStatus{EngineID: keys.EngineID(), Fingerprint: keys.Fingerprint()}, id)
	})
	t.Run("key error", func(t *testing.T) {
		t.Parallel()
		stateDir, _ := engineKeys(t)
		path := filepath.Join(stateDir, channel.KeyFileName)
		require.NoError(t, os.Chmod(path, 0o644))
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		report, id := localVault(portalOn, stateDir)
		require.Equal(t, &agent.VaultStatus{State: string(vault.StateKeyError)}, report, "no engine id without the key file")
		require.Nil(t, id)
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, before, after, "status never touches the key file")
		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
	})
}

func TestPrintStatusShowsEveryVaultState(t *testing.T) {
	t.Parallel()
	stateDir, keys := engineKeys(t)
	id := agent.VaultStatus{EngineID: keys.EngineID(), Fingerprint: keys.Fingerprint()}
	idLine := "Engine id:    " + keys.Fingerprint() + " (id " + keys.EngineID() + ")\n"
	for _, tc := range []struct {
		state, want string
		withID      bool
	}{
		{"OFF", "Vault:        OFF (approval links are the engine's own)\n", true},
		{"CONNECTING", "Vault:        CONNECTING (approvals use long links until it is connected)\n", true},
		{"CONNECTED", "Vault:        CONNECTED (approvals use portal short links)\n", true},
		{"UNREACHABLE", "Vault:        UNREACHABLE (approvals still work, through long links)\n", true},
		{"KEY_ERROR", "Vault:        KEY_ERROR (the engine's key file " + filepath.Join(stateDir, channel.KeyFileName) + " is refused", false},
	} {
		v := agent.VaultStatus{State: tc.state}
		if tc.withID {
			v.EngineID, v.Fingerprint = id.EngineID, id.Fingerprint
		}
		var w bytes.Buffer
		printStatus(&w, statusOut{StatusReport: agent.StatusReport{Agent: "bot", Vault: &v}, StateDir: stateDir})
		require.Contains(t, w.String(), tc.want, tc.state)
		if tc.withID {
			require.Contains(t, w.String(), idLine, tc.state)
		} else {
			require.NotContains(t, w.String(), "Engine id:", tc.state)
		}
		requireNoKeyMaterial(t, stateDir, w.String())
	}

	// Same-user mode with the Vault on: the id, and who knows the state.
	var w bytes.Buffer
	printStatus(&w, statusOut{StatusReport: agent.StatusReport{Agent: "bot"}, StateDir: stateDir, vaultID: &id})
	require.Contains(t, w.String(), "Vault:        ON in the config; only the running engine knows whether it is connected")
	require.Contains(t, w.String(), idLine)

	// Nothing known: no vault lines.
	w.Reset()
	printStatus(&w, statusOut{StatusReport: agent.StatusReport{Agent: "bot"}, StateDir: stateDir})
	require.NotContains(t, w.String(), "Vault:")
	require.NotContains(t, w.String(), "Engine id:")
}

func TestStatusShowsTheEnginesVaultThroughThePersonSocket(t *testing.T) {
	t.Parallel()
	stateDir, keys := engineKeys(t)
	for _, state := range []vault.State{vault.StateOff, vault.StateConnecting, vault.StateConnected, vault.StateUnreachable, vault.StateKeyError} {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()
			v := &agent.VaultStatus{State: string(state)}
			if state != vault.StateKeyError {
				v.EngineID, v.Fingerprint = keys.EngineID(), keys.Fingerprint()
			}
			report := agent.StatusReport{Agent: "bot", OperatedBy: "PERSON", Engine: agent.EngineStatus{Reachable: true}, Vault: v, Problems: []agent.Problem{}}
			socket := fakeEngine(t, report, dbTarget(t, "postgres://agent@db.example.com:5432/app"))

			r := serviceCmd(t, runStatus, socket, nil, "--agent", "bot", "--json")
			require.Equal(t, exitOK, r.code, r.stderr)
			var out map[string]any
			require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
			got := out["vault"].(map[string]any)
			require.Equal(t, string(state), got["state"])
			if state == vault.StateKeyError {
				require.Equal(t, map[string]any{"state": "KEY_ERROR"}, got)
			} else {
				require.Equal(t, keys.EngineID(), got["engineId"])
				require.Equal(t, keys.Fingerprint(), got["fingerprint"])
			}

			text := serviceCmd(t, runStatus, socket, nil, "--agent", "bot")
			require.Equal(t, exitOK, text.code, text.stderr)
			require.Contains(t, text.stdout, "Vault:        "+string(state))
			require.Equal(t, state != vault.StateKeyError, strings.Contains(text.stdout, "Engine id:    "+keys.Fingerprint()))
			requireNoKeyMaterial(t, stateDir, r.stdout+r.stderr+text.stdout+text.stderr)
		})
	}
}
