package ledger_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	pgledger "github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// healthOptions chooses how checkHealth verifies the chain.
type healthOptions struct {
	// Pin is the head verified last time; nil verifies from the genesis
	// (the full check).
	Pin *guard.ChainHead
	// Full recomputes the whole chain from the anchor even with a pin.
	Full bool
	// PinInstall is the guard install Pin was verified on (guard.InstallID).
	// A pin of another install is moved, or reported and set aside
	// (pgledger.SettlePin), never checked against the current chain.
	PinInstall uuid.UUID
	// SetAside is the kept copy of the pins set aside.
	SetAside []guard.SetAside
}

// deadMan is the last DEAD_MAN row.
type deadMan struct {
	At            time.Time
	LastHeartbeat string
	SilentHours   int64
}

// health is what the upkeep tests read of the ledger to check what a tick
// left there: the chain, the reinstalls, the heartbeat and the dead man.
type health struct {
	Chain guard.ChainStatus
	// Head is the head the check verified. It is the pin passed in when the
	// chain is broken.
	Head guard.ChainHead
	// Install is the guard install checked (guard.InstallID).
	Install uuid.UUID
	// PinSetAside: the pin was of another install, not on the current chain,
	// and was reported; the new chain was checked from its start.
	PinSetAside bool
	// PinMoved: the pin was of another install and still verified on the
	// current chain; it moved to Install and nothing was recorded.
	PinMoved bool
	// Reinstalls are the reinstalls the ledger and the kept copy record.
	Reinstalls guard.Reinstalls
	// LastHeartbeat is zero when the agent never sent one.
	LastHeartbeat  time.Time
	HeartbeatStale bool
	// DeadMan is the last DEAD_MAN row of the past guardmodel.DeadManAfter,
	// or nil.
	DeadMan *deadMan
}

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// checkHealth verifies the chain (incrementally from opts.Pin) and finds the
// agent's last heartbeat and recent dead-man row. now is the caller's clock.
func checkHealth(ctx context.Context, q guard.Querier, now time.Time, opts healthOptions) (health, error) {
	var h health
	var err error
	if h.Install, err = guard.InstallID(ctx, q); err != nil {
		return health{}, fmt.Errorf("guard install: %w", err)
	}
	kept := false
	if opts.Pin != nil && opts.PinInstall != h.Install {
		if kept, err = settle(ctx, q, &h, &opts); err != nil {
			return health{}, err
		}
	}
	if !kept {
		if h.Chain, h.Head, err = verify(ctx, q, opts); err != nil {
			return health{}, err
		}
	}
	if h.Reinstalls, err = guard.ReadReinstalls(ctx, q, opts.SetAside); err != nil {
		return health{}, fmt.Errorf("reinstalls: %w", err)
	}
	sql, args, err := psql.Select("max(at)").From("basalt_meta.agent_ledger").
		Where("kind = ?", string(guard.EventHeartbeat)).ToSql()
	if err != nil {
		return health{}, err
	}
	var last *time.Time
	if err := q.QueryRow(ctx, sql, args...).Scan(&last); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return health{}, err
	}
	if last != nil {
		h.LastHeartbeat = *last
		h.HeartbeatStale = now.Sub(*last) > guardmodel.DeadManAfter
	}
	dm, found, err := lastDeadMan(ctx, q, now)
	if err != nil {
		return health{}, err
	}
	if found {
		h.DeadMan = &dm
	}
	return h, nil
}

// settle handles a pin of another install (pgledger.SettlePin) and sets the
// pin to verify from: the moved head, or none after a set-aside. A pin that
// could not be reported is kept (true) and the chain is reported broken at
// it.
func settle(ctx context.Context, q guard.Querier, h *health, opts *healthOptions) (bool, error) {
	s, err := pgledger.SettlePin(ctx, q, *opts.Pin, opts.PinInstall)
	if err != nil {
		return false, err
	}
	switch s.Fate {
	case pgledger.PinMoved:
		h.PinMoved, opts.Pin = true, &s.Head
	case pgledger.PinSetAside:
		h.PinSetAside, opts.Pin = true, nil
	case pgledger.PinKept:
		h.Chain, h.Head = guard.ChainStatus{BrokenAt: opts.Pin.Seq}, *opts.Pin
		return true, nil
	}
	return false, nil
}

// verify runs the full check from the genesis when there is no pin or
// opts.Full, and the incremental check from the pin when there is one.
func verify(ctx context.Context, q guard.Querier, opts healthOptions) (guard.ChainStatus, guard.ChainHead, error) {
	pin := guard.Genesis()
	if opts.Pin != nil {
		pin = *opts.Pin
	}
	if opts.Full && opts.Pin != nil {
		st, _, err := guard.VerifyChainFrom(ctx, q, guard.Genesis())
		if err != nil || !st.Intact {
			return st, pin, err
		}
	}
	return guard.VerifyChainFrom(ctx, q, pin)
}

// lastDeadMan is the latest DEAD_MAN row of the past guardmodel.DeadManAfter,
// and false when there is none.
func lastDeadMan(ctx context.Context, q guard.Querier, now time.Time) (deadMan, bool, error) {
	sql, args, err := psql.Select("at", "coalesce(detail->>'lastHeartbeat', '')",
		"coalesce((detail->>'silentHours')::bigint, 0)").
		From("basalt_meta.agent_ledger").
		Where("kind = ?", string(guard.EventDeadMan)).
		Where("at > ?", now.Add(-guardmodel.DeadManAfter)).
		OrderBy("seq DESC").Limit(1).ToSql()
	if err != nil {
		return deadMan{}, false, err
	}
	var d deadMan
	err = q.QueryRow(ctx, sql, args...).Scan(&d.At, &d.LastHeartbeat, &d.SilentHours)
	if errors.Is(err, pgx.ErrNoRows) {
		return deadMan{}, false, nil
	}
	return d, err == nil, err
}
