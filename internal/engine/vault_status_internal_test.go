package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// onePasskey answers the passkey count status reads; nothing else is called.
type onePasskey struct{ agent.ApprovalStore }

func (onePasskey) Passkeys(context.Context) ([]passkey.Credential, error) {
	return make([]passkey.Credential, 1), nil
}

// vaultInStatus is status.vault as an agent's status tool reports ev.
func vaultInStatus(t *testing.T, ev engineVault) map[string]any {
	t.Helper()
	svc := agent.NewService(agent.Deps{
		Name: "bot", Reader: struct{ agent.Reader }{}, Store: struct{ agent.Store }{}, Reads: struct{ agent.ReadRecorder }{},
		Approvals: onePasskey{}, Reverts: struct{ agent.RevertStore }{},
		Log: quietLog(), Now: time.Now, Vault: ev,
	})
	r, err := svc.Status(context.Background())
	require.NoError(t, err)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	v, ok := body["vault"].(map[string]any)
	require.True(t, ok, "the engine always reports vault: %s", raw)
	return v
}

func TestStatusReportsAKeyError(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	openVault(config.Config{}, stateDir, time.Now, quietLog(), nil, nil, nil)
	require.NoError(t, os.Chmod(filepath.Join(stateDir, channel.KeyFileName), 0o644))

	ev := openVault(config.Config{Vault: config.VaultOn, PagesURL: links.Portal}, stateDir, time.Now, quietLog(), nil, nil, nil)
	require.Equal(t, map[string]any{"state": "KEY_ERROR"}, vaultInStatus(t, ev), "no engine id without the key file")
}

func TestStatusReportsVaultOff(t *testing.T) {
	t.Parallel()
	ev := openVault(config.Config{}, t.TempDir(), time.Now, quietLog(), nil, nil, nil)
	v := vaultInStatus(t, ev)
	require.Equal(t, "OFF", v["state"])
	require.Equal(t, ev.status().EngineID, v["engineId"], "the engine id whenever the key file loads")
	require.Equal(t, ev.status().Fingerprint, v["fingerprint"])
}
