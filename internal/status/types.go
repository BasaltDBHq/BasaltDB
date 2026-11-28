package status

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// The status tool (CONTRACT.md, MCP tools, status; api/mcp/tools/status.json).
// The engine answers it with what it reads from the agent's database; the
// shim answers it with EngineDownStatusAfterStart when the engine socket does not.

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
	problemLockFileUnusable    = "LOCK_FILE_UNUSABLE"
	problemLedgerReinstalled   = "LEDGER_REINSTALLED"
	problemPortalMismatch      = "PORTAL_MISMATCH"
	problemEngineRevoked       = "ENGINE_REVOKED"
	// problemEngineStartFailed: basalt mcp tried to start the engine and
	// could not (CONTRACT.md, MCP tools, status).
	problemEngineStartFailed = "ENGINE_START_FAILED"
	// problemEngineGaveUp: the supervisor gave up restarting a crashing
	// engine (status engine.lastStop).
	problemEngineGaveUp = "ENGINE_GAVE_UP"
	// problemRemoved: no engine answers and its config folder is gone:
	// the person removed BasaltDB from this computer.
	problemRemoved = "REMOVED"
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
	enforcementEngineAndGuard = "ENGINE_AND_GUARD"
	enforcementGuardOnly      = "GUARD_ONLY"
)

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

// PortalFinding is what the engine's daily portal check last found
// (CONTRACT.md, CLI, basalt portal verify). Mismatch is true when the portal
// serves other pages than this build embeds; Summary counts them by status,
// for example "2 DIFFERS, 1 MISSING".
type PortalFinding struct {
	CheckedAt time.Time
	Mismatch  bool
	Summary   string
}
