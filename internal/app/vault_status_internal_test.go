package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
)

// onePasskey answers the passkey count status reads; nothing else is called.
type onePasskey struct{ SQLStore }

func (onePasskey) Passkeys(context.Context) ([]passkey.Credential, error) {
	return make([]passkey.Credential, 1), nil
}

// vaultInStatus is status.vault as an agent's status tool reports ev.
func vaultInStatus(t *testing.T, ev vault.Engine) map[string]any {
	t.Helper()
	d := testAgentDeps("bot", onePasskey{})
	d.Status.Vault = ev
	svc := NewService(d)
	r, err := svc.status.Status(context.Background())
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
	openVault(config.Config{}, stateDir, time.Now, quietLog(), nil, nil)
	require.NoError(t, os.Chmod(filepath.Join(stateDir, channel.KeyFileName), 0o644))

	ev := openVault(config.Config{Vault: config.VaultOn, PagesURL: links.Portal}, stateDir, time.Now, quietLog(), nil, nil)
	require.Equal(t, map[string]any{"state": "KEY_ERROR"}, vaultInStatus(t, ev), "no engine id without the key file")
}

func TestStatusReportsVaultOff(t *testing.T) {
	t.Parallel()
	ev := openVault(config.Config{}, t.TempDir(), time.Now, quietLog(), nil, nil)
	v := vaultInStatus(t, ev)
	require.Equal(t, "OFF", v["state"])
	require.Equal(t, ev.Status().EngineID, v["engineId"], "the engine id whenever the key file loads")
	require.Equal(t, ev.Status().Fingerprint, v["fingerprint"])
}
