package setup

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// The Vault in basalt init and basalt status (CONTRACT.md, Vault channel,
// Configuration and status; owner decision VC-19).

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

// Enum is the value engine.json stores; "" (no choice) keeps the config's.
func (v VaultMode) Enum() string {
	switch v {
	case VaultModeOn:
		return config.VaultOn
	case VaultModeOff:
		return config.VaultOff
	}
	return ""
}

// PersonDefaultWhy is why basalt init (person mode) defaults to off.
const PersonDefaultWhy = "default in person mode, where the engine serves its own pages"

// VaultChoice is what init asks the config's vault to be: --vault when the
// person gave it, else Def, which applies only when the config has no
// vault yet or init changes its operatedBy. Otherwise the config's value
// stays, so a rerun never undoes the person's choice (VC-19).
type VaultChoice struct {
	Given VaultMode // --vault; "" when not given
	Def   VaultMode
	Why   string // why Def is the default
}

// Settings sets s's vault and its default from v.
func (v VaultChoice) Settings(s config.Settings) config.Settings {
	s.Vault, s.VaultDefault = v.Given.Enum(), v.Def.Enum()
	return s
}

// Line is what init prints on stderr once it wrote w (`vault: on (default
// for --operated-by=agent; --vault=off to turn it off)`).
func (v VaultChoice) Line(w config.VaultWritten) string {
	mode := ModeOf(w.Vault)
	switch {
	case v.Given != "":
		return fmt.Sprintf("basalt: vault: %s (--vault=%s)\n", v.Given, v.Given)
	case w.Kept:
		return fmt.Sprintf("basalt: vault: %s (kept from engine.json; --vault=%s to change)\n", mode, mode.other())
	}
	return fmt.Sprintf("basalt: vault: %s (%s)\n", mode, v.Why)
}

// ModeOf is the --vault spelling of an engine.json vault.
func ModeOf(enum string) VaultMode {
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
