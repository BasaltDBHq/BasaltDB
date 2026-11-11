package ledger

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// DeadManAfter is how long without an engine heartbeat before basalt log
// warns that the engine stopped checking in (D14), and how long it keeps
// showing the DEAD_MAN row the engine wrote when it came back. Nothing
// gets disabled.
const DeadManAfter = 7 * 24 * time.Hour

// HealthOptions chooses how CheckHealth verifies the chain.
type HealthOptions struct {
	// Pin is the head this reader verified last time; nil verifies from
	// the genesis (the full check).
	Pin *guard.ChainHead
	// Full recomputes the whole chain from the anchor even with a pin.
	Full bool
}

// DeadMan is the last DEAD_MAN row: the engine checked in after a silence
// longer than DeadManAfter.
type DeadMan struct {
	At            time.Time
	LastHeartbeat string
	SilentHours   int64
}

// Health is what basalt log warns about.
type Health struct {
	Chain guard.ChainStatus
	// Head is the head the check verified, to pin for the next check. It
	// is the pin passed in when the chain is broken.
	Head      guard.ChainHead
	Uncovered []guard.Uncovered
	// LastHeartbeat is zero when the agent never sent one.
	LastHeartbeat  time.Time
	HeartbeatStale bool
	// DeadMan is the last DEAD_MAN row of the past DeadManAfter, or nil.
	DeadMan *DeadMan
}

// CheckHealth verifies the chain (incrementally from opts.Pin), lists
// unguarded tables, and finds the agent's last heartbeat and recent
// dead-man row. now is the caller's clock.
func CheckHealth(ctx context.Context, q guard.Querier, now time.Time, opts HealthOptions) (Health, error) {
	var h Health
	var err error
	if h.Chain, h.Head, err = verify(ctx, q, opts); err != nil {
		return Health{}, err
	}
	if h.Uncovered, err = guard.UncoveredTables(ctx, q); err != nil {
		return Health{}, err
	}
	sql, args, err := psql.Select("max(at)").From("basalt_meta.agent_ledger").
		Where("kind = ?", string(guard.EventHeartbeat)).ToSql()
	if err != nil {
		return Health{}, err
	}
	var last *time.Time
	if err := q.QueryRow(ctx, sql, args...).Scan(&last); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Health{}, err
	}
	if last != nil {
		h.LastHeartbeat = *last
		h.HeartbeatStale = now.Sub(*last) > DeadManAfter
	}
	dm, found, err := lastDeadMan(ctx, q, now)
	if err != nil {
		return Health{}, err
	}
	if found {
		h.DeadMan = &dm
	}
	return h, nil
}

// verify runs the full check from the genesis when there is no pin or
// opts.Full, and the incremental check from the pin when there is one.
func verify(ctx context.Context, q guard.Querier, opts HealthOptions) (guard.ChainStatus, guard.ChainHead, error) {
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

// lastDeadMan is the latest DEAD_MAN row of the past DeadManAfter, and
// false when there is none.
func lastDeadMan(ctx context.Context, q guard.Querier, now time.Time) (DeadMan, bool, error) {
	sql, args, err := psql.Select("at", "coalesce(detail->>'lastHeartbeat', '')",
		"coalesce((detail->>'silentHours')::bigint, 0)").
		From("basalt_meta.agent_ledger").
		Where("kind = ?", string(guard.EventDeadMan)).
		Where("at > ?", now.Add(-DeadManAfter)).
		OrderBy("seq DESC").Limit(1).ToSql()
	if err != nil {
		return DeadMan{}, false, err
	}
	var d DeadMan
	err = q.QueryRow(ctx, sql, args...).Scan(&d.At, &d.LastHeartbeat, &d.SilentHours)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeadMan{}, false, nil
	}
	return d, err == nil, err
}
