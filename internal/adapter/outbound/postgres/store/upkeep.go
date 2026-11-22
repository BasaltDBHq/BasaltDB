package store

import (
	"context"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// Upkeep is the store side of the engine's timer (upkeep.Store) on one
// agent's credential: the guard's functions take the agent from
// session_user, so each agent checks in for itself. Its errors are only
// logged, never answered to an agent, so they are not mapped.
type Upkeep struct {
	db guard.Querier
}

// NewUpkeep returns the upkeep store on db. It panics on a nil db.
func NewUpkeep(db guard.Querier) *Upkeep {
	if db == nil {
		panic("postgres: upkeep db required")
	}
	return &Upkeep{db: db}
}

// InstallID identifies this install of the guard (guard.InstallID).
func (u *Upkeep) InstallID(ctx context.Context) (uuid.UUID, error) {
	return guard.InstallID(ctx, u.db)
}

// VerifyChain verifies the whole ledger chain (basalt_meta.verify_chain).
func (u *Upkeep) VerifyChain(ctx context.Context) (action.ChainStatus, error) {
	st, err := guard.VerifyChain(ctx, u.db)
	return action.ChainStatus(st), err
}

// VerifyChainFrom verifies the chain from head, or from its start when head
// is nil, and returns the new head (basalt_meta.verify_chain_from).
func (u *Upkeep) VerifyChainFrom(ctx context.Context, head *action.ChainHead) (action.ChainStatus, action.ChainHead, error) {
	from := guard.Genesis()
	if head != nil {
		from = guard.ChainHead(*head)
	}
	st, next, err := guard.VerifyChainFrom(ctx, u.db, from)
	return action.ChainStatus(st), action.ChainHead(next), err
}

// SettlePin moves or reports a pin of another install (ledger.SettlePin).
func (u *Upkeep) SettlePin(ctx context.Context, pin action.ChainHead, install uuid.UUID) (action.SettledPin, error) {
	s, err := ledger.SettlePin(ctx, u.db, guard.ChainHead(pin), install)
	return action.SettledPin{Fate: pinFate(s.Fate), Head: action.ChainHead(s.Head), RecordErr: s.RecordErr}, err
}

// pinFate maps the ledger's fate of a pin.
func pinFate(f ledger.PinFate) action.PinFate {
	switch f {
	case ledger.PinMoved:
		return action.PinMoved
	case ledger.PinSetAside:
		return action.PinSetAside
	case ledger.PinKept:
		return action.PinKept
	}
	return action.PinKept
}

// LastHeartbeat is the agent's latest HEARTBEAT, zero when none.
func (u *Upkeep) LastHeartbeat(ctx context.Context) (time.Time, error) {
	q, args, err := psql.Select("max(at)").From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": string(guard.EventHeartbeat)}).ToSql()
	if err != nil {
		return time.Time{}, err
	}
	var last *time.Time
	if err := u.db.QueryRow(ctx, q, args...).Scan(&last); err != nil {
		return time.Time{}, err
	}
	if last == nil {
		return time.Time{}, nil
	}
	return *last, nil
}

// Heartbeat writes a HEARTBEAT ledger row with detail.
func (u *Upkeep) Heartbeat(ctx context.Context, detail map[string]any) error {
	return guard.Heartbeat(ctx, u.db, detail)
}

// RecordDeadMan writes a DEAD_MAN ledger row with detail.
func (u *Upkeep) RecordDeadMan(ctx context.Context, detail map[string]any) error {
	return guard.RecordEvent(ctx, u.db, guard.EventDeadMan, detail)
}

// RecordUncovered writes an UNCOVERED_TABLES ledger row with detail.
func (u *Upkeep) RecordUncovered(ctx context.Context, detail map[string]any) error {
	return guard.RecordEvent(ctx, u.db, guard.EventUncoveredTables, detail)
}

// UncoveredTables lists the agent-writable tables without the guard.
func (u *Upkeep) UncoveredTables(ctx context.Context) ([]action.Uncovered, error) {
	tables, err := guard.UncoveredTables(ctx, u.db)
	if err != nil {
		return nil, err
	}
	return mapSlice(tables, func(t guard.Uncovered) action.Uncovered { return action.Uncovered(t) }), nil
}

// RLSBlindTables lists the tables the agent can SELECT where row-level
// security hides every row from it.
func (u *Upkeep) RLSBlindTables(ctx context.Context) ([]string, error) {
	return guard.RLSBlindTables(ctx, u.db, "", nil)
}

// Prune applies retention (basalt_meta.prune).
func (u *Upkeep) Prune(ctx context.Context) (action.PruneResult, error) {
	r, err := guard.Prune(ctx, u.db)
	return action.PruneResult(r), err
}
