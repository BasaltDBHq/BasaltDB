package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// The Vault in basalt init and basalt status (CONTRACT.md, Vault channel,
// Configuration and status; owner decision VC-19).

// flagVault is --vault on basalt init, init --remote and service install.
const flagVault = "vault"

// VaultMode is the value of --vault: whether the engine dials out to the
// Vault for portal link sessions. CLI input spelling only; engine.json
// holds config.VaultOn or config.VaultOff.
type VaultMode string

// --vault values.
const (
	VaultModeOn  VaultMode = "on"
	VaultModeOff VaultMode = "off"
)

// String implements flag.Value.
func (v *VaultMode) String() string { return string(*v) }

// Set implements flag.Value, refusing anything but on and off.
func (v *VaultMode) Set(s string) error {
	switch VaultMode(s) {
	case VaultModeOn, VaultModeOff:
		*v = VaultMode(s)
		return nil
	}
	return fmt.Errorf("must be %s or %s", VaultModeOn, VaultModeOff)
}

// enum is the value engine.json stores; "" (no choice) keeps the config's.
func (v VaultMode) enum() string {
	switch v {
	case VaultModeOn:
		return config.VaultOn
	case VaultModeOff:
		return config.VaultOff
	}
	return ""
}

// vaultChoice is the vault value init writes and why, for the line init
// prints (`vault: on (default for --operated-by=agent; --vault=off to turn
// it off)`).
type vaultChoice struct {
	mode VaultMode
	why  string
}

// line is what init prints on stderr once it wrote the choice.
func (v vaultChoice) line() string {
	return fmt.Sprintf("basalt: vault: %s (%s)\n", v.mode, v.why)
}

// chooseVault is the vault value for an engine whose pages base is
// pagesURL: --vault when given, else the default (on with
// --operated-by=agent, off otherwise). --vault=on needs the portal's
// pages: a passkey on any other origin cannot sign on the portal, and the
// engine never dials out for them, so it is a usage error (exit 2).
// defaultWhy says why the default is what it is.
func chooseVault(given VaultMode, operatedBy OperatedBy, pagesURL, defaultWhy string) (vaultChoice, error) {
	switch {
	case given == VaultModeOn && pagesURL != links.Portal:
		return vaultChoice{}, fmt.Errorf("%w: --vault=on needs the portal's pages (%s), and these are %s: "+
			"a passkey registered there cannot sign on the portal, so the engine would not use the Vault", errUsage, links.Portal, pagesURL)
	case given != "":
		return vaultChoice{mode: given, why: "--vault=" + string(given)}, nil
	case operatedBy == OperatedByAgent:
		return vaultChoice{mode: VaultModeOn, why: "default for --operated-by=agent; --vault=off to turn it off"}, nil
	}
	return vaultChoice{mode: VaultModeOff, why: defaultWhy}, nil
}

// localVault is status.vault for basalt status in same-user mode, from
// the files the engine reads itself: KEY_ERROR when the engine's key file
// is refused (it is never replaced, so the engine refuses it too), OFF with
// the engine id when the engine does not dial out. With the Vault on, the
// connection state is known only to the running engine: the report leaves
// vault out and identity carries the engine id for the text output. No
// key file yet (the engine makes it on its first start), or one owned by
// another OS user, which this user cannot judge: nothing.
func localVault(cfg config.Config, stateDir string) (report, identity *agent.VaultStatus) {
	path := filepath.Join(stateDir, channel.KeyFileName)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) || !ownedByMe(path) {
		return nil, nil
	}
	keys, err := channel.LoadKeys(path)
	if err != nil {
		return &agent.VaultStatus{State: string(vault.StateKeyError)}, nil
	}
	id := &agent.VaultStatus{EngineID: keys.EngineID(), Fingerprint: keys.Fingerprint()}
	if cfg.VaultEnabled() {
		return nil, id
	}
	id.State = string(vault.StateOff)
	return id, nil
}

// ownedByMe reports whether this OS user owns path.
func ownedByMe(path string) bool {
	me, err := user.Current()
	if err != nil {
		return false
	}
	owner := fileOwner(path)
	return owner != "" && (owner == me.Username || owner == me.Uid)
}

// vaultWords is status.vault's state for the person.
func vaultWords(v agent.VaultStatus, stateDir string) string {
	switch vault.State(v.State) {
	case vault.StateOff:
		return "OFF (approval links are the engine's own)"
	case vault.StateConnecting:
		return "CONNECTING (approvals use long links until it is connected)"
	case vault.StateConnected:
		return "CONNECTED (approvals use portal short links)"
	case vault.StateUnreachable:
		return "UNREACHABLE (approvals still work, through long links)"
	case vault.StateKeyError:
		return fmt.Sprintf("KEY_ERROR (the engine's key file %s is refused: the Vault stays off and approvals use long links; "+
			"correct its owner, the engine's OS user, and its mode, 0600; the engine never replaces it)",
			filepath.Join(stateDir, channel.KeyFileName))
	}
	return v.State
}

// engineIDWords is the engine id as people compare it: the fingerprint,
// then the whole id.
func engineIDWords(v agent.VaultStatus) string {
	return fmt.Sprintf("%s (id %s)", v.Fingerprint, v.EngineID)
}
