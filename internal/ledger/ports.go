package ledger

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
)

// Store is the agent's store as the timer uses it, on the agent's own
// credential (the Postgres adapter's postgres.Upkeep).
type Store interface {
	// InstallID identifies this install of the ledger.
	InstallID(ctx context.Context) (uuid.UUID, error)
	// VerifyChain verifies the whole chain; VerifyChainFrom verifies it
	// from head (from its start when head is nil) and returns the new head.
	VerifyChain(ctx context.Context) (action.ChainStatus, error)
	VerifyChainFrom(ctx context.Context, head *action.ChainHead) (action.ChainStatus, action.ChainHead, error)
	// SettlePin moves or reports a pin of install, another install.
	SettlePin(ctx context.Context, pin action.ChainHead, install uuid.UUID) (action.SettledPin, error)
	// LastHeartbeat is the agent's latest heartbeat, zero when none.
	LastHeartbeat(ctx context.Context) (time.Time, error)
	Heartbeat(ctx context.Context, detail map[string]any) error
	RecordDeadMan(ctx context.Context, detail map[string]any) error
	RecordUncovered(ctx context.Context, detail map[string]any) error
	UncoveredTables(ctx context.Context) ([]action.Uncovered, error)
	RLSBlindTables(ctx context.Context) ([]string, error)
	Prune(ctx context.Context) (action.PruneResult, error)
}

// Pins keeps the last verified chain head per agent (pinfile.File in the
// engine's state directory).
type Pins interface {
	Load(name string) (chainpin.Pin, bool, error)
	Save(name string, p chainpin.Pin) error
}

// Refresher forgets what it learned about row-level security, so the next
// statement asks the database again.
type Refresher interface {
	Refresh()
}

// PIICheck is the hourly PII classification check (pii.Watch): it
// reloads the classification map when it moved and warns about
// unclassified columns.
type PIICheck interface {
	Tick(ctx context.Context) error
}
