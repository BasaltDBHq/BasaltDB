package vault

import (
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Engine is the engine's keys and its socket to the Vault (CONTRACT.md,
// Vault channel).
type Engine struct {
	// Client keeps the socket; nil when the engine does not dial out.
	Client *Client
	// Status is vault in status: KEY_ERROR, OFF, or the socket's state.
	Status func() Status
	// Keys are the engine's keys, nil when the key file is refused
	// (KEY_ERROR): they sign receipts whatever vault says.
	Keys *channel.EngineKeys
}

// Receipts is the signer of the agents' receipts: none (a nil interface)
// when the key file is refused, and the answers then carry noReceipt.
func (v Engine) Receipts() Keys {
	if v.Keys == nil {
		return nil
	}
	return v.Keys
}

// VaultStatus is status.vault for every agent's status tool: OFF (with the
// engine id when the keys load), KEY_ERROR, or the socket's state.
func (v Engine) VaultStatus() guidance.VaultStatus {
	st := v.Status()
	return guidance.VaultStatus{State: string(st.State), EngineID: st.EngineID, Fingerprint: st.Fingerprint}
}
