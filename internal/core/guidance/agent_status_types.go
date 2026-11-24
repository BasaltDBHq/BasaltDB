package guidance

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// VaultStatus is status.vault: state is OFF, CONNECTING, CONNECTED,
// UNREACHABLE or KEY_ERROR; the engine id and its fingerprint whenever the
// key file loads.
type VaultStatus struct {
	State       string `json:"state"`
	EngineID    string `json:"engineId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// EngineRecordStatus is status.engineRecord: this engine's key as the
// agent's database records it (CONTRACT.md, Vault channel, Engine keys).
type EngineRecordStatus struct {
	State      string `json:"state"`
	RecordedAt string `json:"recordedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

// StatusReport is the status tool's result.
type StatusReport struct {
	Agent       string         `json:"agent"`
	OperatedBy  string         `json:"operatedBy"`
	Enforcement string         `json:"enforcement"`
	Ready       bool           `json:"ready"`
	Engine      EngineStatus   `json:"engine"`
	Guard       GuardStatus    `json:"guard"`
	Setup       SetupStatus    `json:"setup"`
	Pages       PagesStatus    `json:"pages"`
	Vault       *VaultStatus   `json:"vault,omitempty"`
	Passkeys    PasskeysStatus `json:"passkeys"`
	Ledger      *LedgerStatus  `json:"ledger,omitempty"`
	// EngineRecord is the engine's own key in the agent's database; absent
	// when the engine is down.
	EngineRecord *EngineRecordStatus `json:"engineRecord,omitempty"`
	// Trust is what verifies the agent's database certificate; absent when
	// the engine is down.
	Trust *TrustStatus `json:"trust,omitempty"`
	// Crash is the newest saved crash report, Access what the agent can
	// read and write, Plugins the health of the plugin entries served to
	// it; each absent when there is nothing to show.
	Crash    *CrashStatus   `json:"crash,omitempty"`
	Access   *AccessStatus  `json:"access,omitempty"`
	Plugins  []PluginHealth `json:"plugins,omitempty"`
	Problems []Problem      `json:"problems"`
	// Update is set when a newer release is out (CONTRACT.md, Update
	// notice).
	Update *UpdateInfo `json:"update,omitempty"`
}

// EngineStatus is status.engine.
type EngineStatus struct {
	Reachable bool   `json:"reachable"`
	Build     string `json:"build,omitempty"`
	// StartedBy is why this engine started: HAND, MCP or CRASH.
	StartedBy string `json:"startedBy,omitempty"`
	// LastStop is why a supervisor gave up on the engine, from an engine
	// that does not answer; the engine itself never reports it.
	LastStop *LastStop `json:"lastStop,omitempty"`
}

// LastStop is status.engine.lastStop: the supervisor gave up restarting the
// engine for Reason at At.
type LastStop struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	// EngineSHA256 is last-stop.json's engineSha256, used only to decide
	// the start hold-off; it is never sent in status.
	EngineSHA256 string `json:"-"`
}

// GuardStatus is status.guard.
type GuardStatus struct {
	State              string `json:"state"`
	Installed          *int   `json:"installed,omitempty"`
	Build              int    `json:"build,omitempty"`
	MissingBreaking    []int  `json:"missingBreaking,omitempty"`
	MissingNonBreaking []int  `json:"missingNonBreaking,omitempty"`
}

// SetupStatus is status.setup.
type SetupStatus struct {
	State       string `json:"state"`
	SetupID     string `json:"setupId,omitempty"`
	Kind        string `json:"kind,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// ConnectOnly is set while the pending code is connect-only.
	ConnectOnly bool `json:"connectOnly,omitempty"`
	// Database is the collected and probed database (CONFIRM_DATABASE).
	Database *setupcode.Address `json:"database,omitempty"`
}

// PagesStatus is status.pages.
type PagesStatus struct {
	Served bool   `json:"served"`
	URL    string `json:"url"`
}

// PasskeysStatus is status.passkeys; Active is absent when the engine is
// down or cannot count them.
type PasskeysStatus struct {
	Registered bool `json:"registered"`
	Active     *int `json:"active,omitempty"`
	// Keys names each active passkey with its check code, computed from the
	// public key in the database (CONTRACT.md, Connect, The passkey check
	// code); absent when none is active or they cannot be read.
	Keys []PasskeyStatus `json:"keys,omitempty"`
	// Summary is the same in words for the person, set once a setup is
	// recorded (state DONE).
	Summary string `json:"summary,omitempty"`
}

// PasskeyStatus is one entry of status.passkeys.keys. CheckCode is absent
// when the key cannot be read.
type PasskeyStatus struct {
	CredentialID passkey.Bytes `json:"credentialId"`
	CheckCode    string        `json:"checkCode,omitempty"`
}

// LedgerStatus is status.ledger: absent when the guard or its size cannot
// be read.
type LedgerStatus struct {
	Bytes           int64 `json:"bytes"`
	ValuesKeptDays  int   `json:"valuesKeptDays"`
	RecordsKeptDays int   `json:"recordsKeptDays"`
}
