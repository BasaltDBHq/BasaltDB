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

// flagVaultDefault is service install's vault for a config that has none:
// init passes it instead of --vault when the person gave none.
const flagVaultDefault = "vault-default"

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

// personDefaultWhy is why basalt init (person mode) defaults to off.
const personDefaultWhy = "default in person mode, where the engine serves its own pages"

// vaultChoice is what init asks the config's vault to be: --vault when the
// person gave it, else def, which applies only when the config has no
// vault yet or init changes its operatedBy. Otherwise the config's value
// stays, so a rerun never undoes the person's choice (VC-19).
type vaultChoice struct {
	given VaultMode // --vault; "" when not given
	def   VaultMode
	why   string // why def is the default
}

// settings sets s's vault and its default from v.
func (v vaultChoice) settings(s config.Settings) config.Settings {
	s.Vault, s.VaultDefault = v.given.enum(), v.def.enum()
	return s
}

// line is what init prints on stderr once it wrote w (`vault: on (default
// for --operated-by=agent; --vault=off to turn it off)`).
func (v vaultChoice) line(w config.VaultWritten) string {
	mode := modeOf(w.Vault)
	switch {
	case v.given != "":
		return fmt.Sprintf("basalt: vault: %s (--vault=%s)\n", v.given, v.given)
	case w.Kept:
		return fmt.Sprintf("basalt: vault: %s (kept from engine.json; --vault=%s to change)\n", mode, mode.other())
	}
	return fmt.Sprintf("basalt: vault: %s (%s)\n", mode, v.why)
}

// modeOf is the --vault spelling of an engine.json vault.
func modeOf(enum string) VaultMode {
	switch enum {
	case config.VaultOn:
		return VaultModeOn
	case config.VaultOff:
		return VaultModeOff
	}
	return ""
}

// other is the opposite mode.
func (v VaultMode) other() VaultMode {
	if v == VaultModeOn {
		return VaultModeOff
	}
	return VaultModeOn
}

// chooseVault is the vault choice for an engine whose pages base is
// pagesURL: --vault when given, else the default (on with
// --operated-by=agent on the portal's pages, off otherwise, as with
// --dev-local-pages). --vault=on needs the portal's
// pages: a passkey on any other origin cannot sign on the portal, and the
// engine never dials out for them, so it is a usage error (exit 2).
// defaultWhy says why the default is off.
func chooseVault(given VaultMode, operatedBy OperatedBy, pagesURL, defaultWhy string) (vaultChoice, error) {
	if given == VaultModeOn && pagesURL != links.Portal {
		return vaultChoice{}, fmt.Errorf("%w: --vault=on needs the portal's pages (%s), and these are %s: "+
			"a passkey registered there cannot sign on the portal, so the engine would not use the Vault", errUsage, links.Portal, pagesURL)
	}
	if operatedBy == OperatedByAgent && pagesURL == links.Portal {
		return vaultChoice{given: given, def: VaultModeOn, why: "default for --operated-by=agent; --vault=off to turn it off"}, nil
	}
	return vaultChoice{given: given, def: VaultModeOff, why: defaultWhy}, nil
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
