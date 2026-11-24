package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// Vault settings (CONTRACT.md, Vault channel, Configuration and status).
const (
	// VaultOn turns the engine's socket to the Vault on.
	VaultOn = "ON"
	// VaultOff, or no vault key at all, leaves it off.
	VaultOff = "OFF"
)

// vaultLoopbackHosts are the only hosts a vaultUrl override may name: the
// contract lists them, and a name that only resolves to loopback is not one.
var vaultLoopbackHosts = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// CheckVaultURL accepts an empty override, or a ws:// URL on a loopback
// address with nothing after the host but an optional "/": the engine adds
// /v1/engines/<engineId> itself. Anything else is refused, so a config file
// cannot point the engine's identity at another host.
func CheckVaultURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ws" || u.User != nil || u.Opaque != "" ||
		!vaultLoopbackHosts[strings.ToLower(u.Hostname())] ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("vaultUrl %q: it is for development and tests only and must be ws://127.0.0.1:<port>, ws://[::1]:<port> or ws://localhost:<port>; remove it to use the Vault", raw)
	}
	return nil
}

// VaultEnabled reports whether the engine dials out to the Vault: vault is
// ON and the pages are the portal. A passkey with RP ID localhost cannot
// sign on the portal, so local pages never use the Vault.
func (c Config) VaultEnabled() bool {
	if c.Vault != VaultOn {
		return false
	}
	base, err := c.PagesBase()
	return err == nil && base == links.Portal
}
