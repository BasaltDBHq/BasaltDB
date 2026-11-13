// Package upkeep is the engine's timer for one agent: a heartbeat in the
// ledger and a DEAD_MAN row after a long silence (the dead-man switch,
// owner decision #14), retention (decision #10), the coverage check
// (unguarded tables, recorded when the set changes), a warning for tables
// row-level security hides from the agent, and incremental
// verification of the ledger chain from a head pinned outside the
// database, so a rewrite of history is noticed even across restarts.
package upkeep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

// DefaultInterval is how often the engine checks in. Far below
// ledger.DeadManAfter, so a running engine never looks silent.
const DefaultInterval = time.Hour

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// Pins keeps the last verified chain head per agent (chainpin.File in the
// engine's state directory).
type Pins interface {
	Load(name string) (guard.ChainHead, bool, error)
	Save(name string, h guard.ChainHead) error
}

// Upkeep runs the timer work for one agent on its own credential: the
// guard's functions take the agent from session_user, so each agent
// checks in for itself.
type Upkeep struct {
	agent   string
	version string
	// operatedBy is engine.json operatedBy, recorded in every heartbeat
	// (CO-15).
	operatedBy string
	db         guard.Querier
	log        *slog.Logger
	now        func() time.Time
	pins       Pins
	rls        Refresher
	pii        PIICheck
	// admit gates every tick (WithGate); it admits every tick when unset.
	admit func(ctx context.Context) error

	started bool
	head    *guard.ChainHead
	// startBroken is where the full check on start found the chain broken;
	// it is reported on every tick until the engine restarts.
	startBroken *int64

	coverageKnown bool
	uncovered     []guard.Uncovered
}

// New returns the upkeep for one agent, pinning chain heads in memory
// until WithPins. It panics on a missing dependency.
func New(agent, version string, db guard.Querier, log *slog.Logger, now func() time.Time) *Upkeep {
	if agent == "" || db == nil || log == nil || now == nil {
		panic("upkeep: agent, db, logger and clock required")
	}
	return &Upkeep{
		agent: agent, version: version, operatedBy: operatedByPerson, db: db, log: log, now: now,
		pins: &chainpin.Memory{}, rls: noRefresh{}, pii: noPII{}, admit: admitAll,
	}
}

// operatedByPerson is the heartbeat's operatedBy until WithOperatedBy.
const operatedByPerson = "PERSON"

// WithOperatedBy records operatedBy (PERSON or AGENT) in every heartbeat's
// detail, so the ledger shows when enforcement was guard-only (CO-15); an
// empty value is PERSON, as in engine.json.
func (u *Upkeep) WithOperatedBy(operatedBy string) *Upkeep {
	if operatedBy != "" {
		u.operatedBy = operatedBy
	}
	return u
}

func admitAll(context.Context) error { return nil }

// Refresher forgets what it learned about row-level security, so the next
// statement asks the database again.
type Refresher interface {
	Refresh()
}

type noRefresh struct{}

func (noRefresh) Refresh() {}

// PIICheck is the hourly PII classification check (piidict.Watch): it
// reloads the classification map when it moved and warns about
// unclassified columns.
type PIICheck interface {
	Tick(ctx context.Context) error
}

type noPII struct{}

func (noPII) Tick(context.Context) error { return nil }

// WithPII has every tick run p.
func (u *Upkeep) WithPII(p PIICheck) *Upkeep {
	if p == nil {
		panic("upkeep: nil pii check")
	}
	u.pii = p
	return u
}

// WithRLSCache has every cycle refresh r, the engine's cache of the tables
// row-level security hides from the agent (the RLS_HIDES_ROWS warning).
func (u *Upkeep) WithRLSCache(r Refresher) *Upkeep {
	if r == nil {
		panic("upkeep: nil refresher")
	}
	u.rls = r
	return u
}

// WithGate has every tick ask admit first and skip all its work when it
// refuses: on a guard that is missing or misses a breaking migration the
// engine writes nothing to the ledger, verifies nothing and pins no chain
// head from that schema. The first tick after the guard serves the agent
// runs the full check on start.
func (u *Upkeep) WithGate(admit func(ctx context.Context) error) *Upkeep {
	if admit == nil {
		panic("upkeep: nil gate")
	}
	u.admit = admit
	return u
}

// WithPins keeps verified chain heads in p, so the check survives restarts.
func (u *Upkeep) WithPins(p Pins) *Upkeep {
	if p == nil {
		panic("upkeep: nil pins")
	}
	u.pins = p
	return u
}

// Run ticks now and then every interval until ctx is done. Errors are
// logged; the next tick tries again.
func (u *Upkeep) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := u.Tick(ctx); err != nil && ctx.Err() == nil {
			u.log.Error("upkeep", "agent", u.agent, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick verifies the chain from the pinned head, writes a DEAD_MAN row when
// the last heartbeat is older than ledger.DeadManAfter, writes a heartbeat,
// records the unguarded tables when they changed, and prunes old values.
func (u *Upkeep) Tick(ctx context.Context) error {
	if err := u.admit(ctx); err != nil {
		return fmt.Errorf("skipped: the guard does not serve this agent: %w", err)
	}
	detail := map[string]any{"engineVersion": u.version, "operatedBy": u.operatedBy}
	var errs []error

	st, err := u.checkChain(ctx)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("verify chain: %w", err))
	case !st.Intact:
		detail["chainBrokenAt"] = st.BrokenAt
		u.log.Error("ledger chain broken: rows were changed or removed outside basalt", "agent", u.agent,
			"seq", st.BrokenAt)
	}
	if err := u.checkDeadMan(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := guard.Heartbeat(ctx, u.db, detail); err != nil {
		errs = append(errs, fmt.Errorf("heartbeat: %w", err))
	}
	if err := u.checkCoverage(ctx); err != nil {
		errs = append(errs, fmt.Errorf("coverage: %w", err))
	}
	if err := u.checkRLSBlind(ctx); err != nil {
		errs = append(errs, fmt.Errorf("row-level security: %w", err))
	}
	if err := u.pii.Tick(ctx); err != nil {
		errs = append(errs, fmt.Errorf("pii: %w", err))
	}
	if res, err := guard.Prune(ctx, u.db); err != nil {
		errs = append(errs, fmt.Errorf("prune: %w", err))
	} else if res.ValuesPruned+res.RowsDeleted > 0 {
		u.log.Info("pruned the ledger", "agent", u.agent, "valuesPruned", res.ValuesPruned, "rowsDeleted", res.RowsDeleted)
	}
	return errors.Join(errs...)
}

// checkChain verifies the ledger. On the first tick with a saved pin it
// runs the full check too: the pin catches a consistent rewrite made while
// the engine was stopped, the full check an edit behind the pin. Later
// ticks verify from the last pin only. On a break the old pin is kept, so
// the break is reported on every tick until a person looks.
func (u *Upkeep) checkChain(ctx context.Context) (guard.ChainStatus, error) {
	if !u.started {
		if err := u.start(ctx); err != nil {
			return guard.ChainStatus{}, err
		}
	}
	if u.startBroken != nil {
		return guard.ChainStatus{BrokenAt: *u.startBroken}, nil
	}
	from := guard.Genesis()
	if u.head != nil {
		from = *u.head
	}
	st, head, err := guard.VerifyChainFrom(ctx, u.db, from)
	if err != nil || !st.Intact {
		return st, err
	}
	u.head = &head
	if err := u.pins.Save(u.agent, head); err != nil {
		return guard.ChainStatus{}, fmt.Errorf("save the chain head: %w", err)
	}
	return st, nil
}

func (u *Upkeep) start(ctx context.Context) error {
	pin, ok, err := u.pins.Load(u.agent)
	if err != nil {
		return fmt.Errorf("load the chain head: %w", err)
	}
	if ok {
		full, err := guard.VerifyChain(ctx, u.db)
		if err != nil {
			return err
		}
		if !full.Intact {
			u.startBroken = &full.BrokenAt
		}
		u.head = &pin
	}
	u.started = true
	return nil
}

// checkDeadMan writes the DEAD_MAN row (D14) when the engine checks in
// after more than ledger.DeadManAfter without a heartbeat. Nothing is
// disabled; basalt log shows the row.
func (u *Upkeep) checkDeadMan(ctx context.Context) error {
	last, err := u.lastHeartbeat(ctx)
	if err != nil {
		return fmt.Errorf("last heartbeat: %w", err)
	}
	silence := u.now().Sub(last)
	if last.IsZero() || silence <= ledger.DeadManAfter {
		return nil
	}
	u.log.Warn("engine was silent past the dead-man limit", "agent", u.agent, "lastHeartbeat", last)
	err = guard.RecordEvent(ctx, u.db, guard.EventDeadMan, map[string]any{
		"engineVersion": u.version,
		"lastHeartbeat": last.UTC().Format(time.RFC3339),
		"silentHours":   int64(silence.Hours()),
	})
	if err != nil {
		return fmt.Errorf("dead-man row: %w", err)
	}
	return nil
}

// checkCoverage warns about every unguarded table on every tick, and
// records an UNCOVERED_TABLES row when the set changed since the last tick
// (on start, only when the set is not empty).
func (u *Upkeep) checkCoverage(ctx context.Context) error {
	tables, err := guard.UncoveredTables(ctx, u.db)
	if err != nil {
		return err
	}
	for _, t := range tables {
		u.log.Warn("table is not guarded; run basalt init again", "agent", u.agent, "table", t.Table, "why", t.Why)
	}
	unchanged := slices.Equal(tables, u.uncovered) || (!u.coverageKnown && len(tables) == 0)
	if unchanged {
		u.coverageKnown, u.uncovered = true, tables
		return nil
	}
	list := make([]map[string]any, 0, len(tables))
	for _, t := range tables {
		list = append(list, map[string]any{"table": t.Table, "why": t.Why})
	}
	if err := guard.RecordEvent(ctx, u.db, guard.EventUncoveredTables, map[string]any{"tables": list}); err != nil {
		return err
	}
	u.coverageKnown, u.uncovered = true, tables
	return nil
}

// checkRLSBlind warns on every tick about each table the agent can SELECT
// where row-level security hides every row from it (Supabase can turn RLS
// on for new tables). Basalt never adds a policy for the agent (N12-7).
func (u *Upkeep) checkRLSBlind(ctx context.Context) error {
	u.rls.Refresh()
	tables, err := guard.RLSBlindTables(ctx, u.db, "", nil)
	if err != nil {
		return err
	}
	for _, t := range tables {
		u.log.Warn("row-level security hides every row of this table from the agent; add a policy for its role or disable RLS",
			"agent", u.agent, "table", t)
	}
	return nil
}

// lastHeartbeat is the agent's latest HEARTBEAT, zero when none.
func (u *Upkeep) lastHeartbeat(ctx context.Context) (time.Time, error) {
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

// Head returns the head pinned on the last tick (tests).
func (u *Upkeep) Head() (guard.ChainHead, bool) {
	if u.head == nil {
		return guard.ChainHead{}, false
	}
	return guard.ChainHead{Seq: u.head.Seq, Hash: bytes.Clone(u.head.Hash)}, true
}
