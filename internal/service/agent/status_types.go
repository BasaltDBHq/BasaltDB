package agent

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
)

// The status tool (CONTRACT.md, MCP tools, status; api/mcp/tools/status.json).
// The engine answers it with what it reads from the agent's database; the
// shim answers it with EngineDownStatus when the engine socket does not.

// Problem codes of the status tool (api/mcp/errors/next-steps.json, problems).
const (
	problemEngineUnreachable   = guidance.ReasonEngineUnreachable
	problemDatabaseUnreachable = guidance.ReasonDatabaseUnreachable
	problemTooManyConnections  = guidance.ReasonTooManyConnections
	problemCredentialRejected  = guidance.ReasonCredentialRejected
	problemGuardMissing        = guidance.ReasonGuardMissing
	problemGuardOutdated       = guidance.ReasonGuardOutdated
	problemUpgradeAvailable    = "GUARD_UPGRADE_AVAILABLE"
	problemNoPasskey           = "NO_PASSKEY"
	problemSetupNotRun         = "SETUP_NOT_RUN"
	problemSetupExpired        = "SETUP_EXPIRED"
	problemSetupChangePending  = "SETUP_CHANGE_PENDING"
	problemLockFileUnusable    = "LOCK_FILE_UNUSABLE"
	problemLedgerReinstalled   = "LEDGER_REINSTALLED"
	problemPortalMismatch      = "PORTAL_MISMATCH"
	problemEngineRevoked       = "ENGINE_REVOKED"
	// The problems of a connect-only setup (CONTRACT.md, The engine and a
	// connect-only code).
	problemConfirmDatabase    = "CONFIRM_DATABASE"
	problemDatabaseRefused    = "DATABASE_REFUSED"
	problemUnreachableFromBot = "DATABASE_UNREACHABLE_FROM_BOT"
	problemTrustRootMismatch  = "TRUST_ROOT_MISMATCH"
	problemAddressInvalid     = "ADDRESS_INVALID"
	problemSetupNotFound      = "SETUP_NOT_FOUND"
	problemClockSkew          = "CLOCK_SKEW"
	problemEngineAsRoot       = "ENGINE_AS_ROOT"
	// problemEngineStartFailed: basalt mcp tried to start the engine and
	// could not (CONTRACT.md, MCP tools, status).
	problemEngineStartFailed = "ENGINE_START_FAILED"
	// problemEngineGaveUp: the supervisor gave up restarting a crashing
	// engine (status engine.lastStop).
	problemEngineGaveUp = "ENGINE_GAVE_UP"
)

// status.engineRecord.state (CONTRACT.md, Configuration and status).
const (
	engineRecorded    = "RECORDED"
	engineNotRecorded = "NOT_RECORDED"
	engineRevoked     = "REVOKED"
	engineUnknown     = "UNKNOWN"
)

// engineRecordTimeout bounds the read of the engine's record for status.
const engineRecordTimeout = 5 * time.Second

// EngineRecordReader reads this engine's row in the agent's database
// (guard.EngineRecord): nil when it is not recorded, an error when the
// guard is older than version 33 or the database cannot be read.
type EngineRecordReader func(ctx context.Context, engineID string) (*EngineRecord, error)

// Retention of the ledger (CONTRACT.md, Configuration and status): the
// guard prunes values after 30 days and deletes records after 365.
const (
	ledgerValuesKeptDays  = 30
	ledgerRecordsKeptDays = 365
)

// Enforcement values of the status tool.
const (
	EnforcementEngineAndGuard = "ENGINE_AND_GUARD"
	EnforcementGuardOnly      = "GUARD_ONLY"
)

// Setup states of the status tool.
const (
	setupNone    = "NONE"
	setupPending = "PENDING"
	setupExpired = "EXPIRED"
	setupDone    = "DONE"
	// setupConfirmDatabase: a connect-only setup's database was collected
	// and probed, and waits for the person's confirmation.
	setupConfirmDatabase = "CONFIRM_DATABASE"
	// setupRefused: the person said the collected database is not theirs.
	setupRefused = "REFUSED"
)

// Probe reads, on the agent's own credential, what status reports from the
// database and what decides whether a tool call is served. The default
// reports a current guard and no setups.
type Probe interface {
	GuardStatus(ctx context.Context) (guardmodel.Status, error)
	SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error)
	LatestSetup(ctx context.Context) (guardmodel.AgentSetup, bool, error)
	// LedgerBytes is the size of basalt_meta (status.ledger).
	LedgerBytes(ctx context.Context) (int64, error)
	// Reinstalls are the reinstalls the ledger and the engine's kept copy
	// record (problem LEDGER_REINSTALLED).
	ReinstallNotice(ctx context.Context, limit int) (message string, ok bool, err error)
}

type noProbe struct{ latest func() int }

func (p noProbe) GuardStatus(context.Context) (guardmodel.Status, error) {
	v := p.latest()
	return guardmodel.Status{State: guardmodel.GuardOK, Installed: v, Build: v}, nil
}

func (noProbe) SetupRecorded(context.Context, uuid.UUID) (bool, error) { return false, nil }

func (noProbe) LatestSetup(context.Context) (guardmodel.AgentSetup, bool, error) {
	return guardmodel.AgentSetup{}, false, nil
}

// errNoProbe: without a real probe there is no size to report, and status
// leaves the ledger out rather than say 0.
var errNoProbe = errors.New("no probe reads the ledger size")

func (noProbe) LedgerBytes(context.Context) (int64, error) { return 0, errNoProbe }

func (noProbe) ReinstallNotice(context.Context, int) (string, bool, error) { return "", false, nil }

// VaultReporter says how the engine's connection to the hosted Vault stands
// (status.vault, CONTRACT.md, Vault channel, Configuration and status).
// Optional: without one, status leaves vault out.
type VaultReporter interface {
	VaultStatus() VaultStatus
}

// VaultStatus is status.vault: state is OFF, CONNECTING, CONNECTED,
// UNREACHABLE or KEY_ERROR; the engine id and its fingerprint whenever the
// key file loads.
type VaultStatus struct {
	State       string `json:"state"`
	EngineID    string `json:"engineId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// PortalFinding is what the engine's daily portal check last found
// (CONTRACT.md, CLI, basalt portal verify). Mismatch is true when the portal
// serves other pages than this build embeds; Summary counts them by status,
// for example "2 DIFFERS, 1 MISSING".
type PortalFinding struct {
	CheckedAt time.Time
	Mismatch  bool
	Summary   string
}

// PortalReporter gives the last daily portal check. Optional: without one,
// or before the first check, status says nothing about the portal.
type PortalReporter interface {
	PortalFinding() (PortalFinding, bool)
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
	Crash    *CrashStatus       `json:"crash,omitempty"`
	Access   *AccessStatus      `json:"access,omitempty"`
	Plugins  []PluginHealth     `json:"plugins,omitempty"`
	Problems []guidance.Problem `json:"problems"`
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
	Database *handoff.Address `json:"database,omitempty"`
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
