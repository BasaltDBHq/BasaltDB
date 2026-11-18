package ledger

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
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
	// PinInstall is the guard install Pin was verified on (guard.InstallID);
	// uuid.Nil for a pin saved before install ids, taken as another
	// install's. A pin of another install is moved, or reported and set
	// aside (SettlePin), never checked against the current chain.
	PinInstall uuid.UUID
	// SetAside is the reader's kept copy of the pins it set aside, shown in
	// the notice with what the ledger records.
	SetAside []guard.SetAside
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
	Head guard.ChainHead
	// Install is the guard install checked (guard.InstallID), to pin with
	// Head.
	Install uuid.UUID
	// PinSetAside is set when the pin was of another install, was not on
	// the current chain, and was reported with record_pin_set_aside on the
	// agent's credential: the new chain was checked from its start.
	PinSetAside bool
	// PinMoved is set when the pin was of another install and still
	// verified on the current chain (the same ledger under a new install
	// id): it moved to
	// Install and nothing was recorded.
	PinMoved bool
	// Reinstalls are the reinstalls the ledger and the reader's kept copy
	// record, for the notice.
	Reinstalls guard.Reinstalls
	Uncovered  []guard.Uncovered
	// RLSBlind are tables the agent can SELECT where row-level security
	// hides every row from it (schema.table).
	RLSBlind []string
	// LastHeartbeat is zero when the agent never sent one.
	LastHeartbeat  time.Time
	HeartbeatStale bool
	// DeadMan is the last DEAD_MAN row of the past DeadManAfter, or nil.
	DeadMan *DeadMan
	// PII is the classification summary; nil before guard version 15.
	PII *PIIHealth
	// Plugins are the plugin entries the agent's ledger records as served
	// (latest event PLUGIN_ENABLED or PLUGIN_CHANGED), in name and instance
	// order; Plugins is nil when it records no plugin event at all.
	Plugins []PluginHealth
}

// PluginHealth is one plugin served to the agent, as its ledger records it
// (basalt log's Plugins line).
type PluginHealth struct {
	Name, Instance, Version, SignerKeyID string
	// Endpoint is LOCAL or REMOTE; Host is a REMOTE endpoint's host:port.
	Endpoint, Host string
	// Files and Network are a LOCAL entry's isolation, "" for REMOTE.
	Files, Network string
}

// checkPlugins reads the plugin entries the agent's ledger records as
// served: an empty, non-nil list when it records only disabled ones, nil
// when it records no plugin event.
func checkPlugins(ctx context.Context, q guard.Querier) ([]PluginHealth, error) {
	recs, err := guard.ReadPluginRecords(ctx, q)
	if err != nil || len(recs.Entries) == 0 {
		return nil, err
	}
	out := []PluginHealth{}
	for _, d := range recs.EnabledPlugins() {
		p := PluginHealth{
			Name: d.Name, Instance: d.Instance, Version: d.Version, SignerKeyID: d.SignerKeyID,
			Endpoint: d.Endpoint.Kind, Host: d.Endpoint.Host,
		}
		if d.Isolation != nil {
			p.Files, p.Network = d.Isolation.Files, d.Isolation.Network
		}
		out = append(out, p)
	}
	return out, nil
}

// MaxPIINames is how many column names the PII summary carries per list;
// basalt log prints them, then "…".
const MaxPIINames = 10

// PIIHealth is what basalt log's PII line and warnings say (CONTRACT.md, PII
// classification, basalt log). Names are not PII; no value is read.
type PIIHealth struct {
	// Classified counts the agent's rows of agent_pii_columns with a class
	// other than UNCLASSIFIED.
	Classified int
	// Unclassified counts pii_unclassified() rows of why NEW or
	// UNCLASSIFIED; UnclassifiedNames are the first MaxPIINames of them.
	Unclassified      int
	UnclassifiedNames []string
	// Review counts the columns whose type changed or that need a review;
	// ReviewNames are the first MaxPIINames of them.
	Review      int
	ReviewNames []string
	// Dictionary is the engine's dictionary, nil when it is not known here
	// (basalt log then reads status.json, or says it is not built yet).
	Dictionary *DictionaryHealth
}

// DictionaryHealth is the dictionary part of the PII line.
type DictionaryHealth struct {
	Values     uint64
	LastScanAt *time.Time
}

// checkPII reads the PII summary, or nil when the guard has no PII
// classification (before version 15).
func checkPII(ctx context.Context, q guard.Querier) (*PIIHealth, error) {
	var has bool
	// Plain SQL: a catalog lookup of the version 15 function.
	if err := q.QueryRow(ctx, `SELECT to_regprocedure('basalt_meta.pii_unclassified()') IS NOT NULL`).Scan(&has); err != nil {
		return nil, err
	}
	if !has {
		return nil, nil //nolint:nilnil // before version 15 there is no summary, and no error
	}
	classified, flagged, err := guard.PIIClassCounts(ctx, q)
	if err != nil {
		return nil, err
	}
	cols, err := guard.PIIUnclassified(ctx, q)
	if err != nil {
		return nil, err
	}
	h := &PIIHealth{Classified: classified}
	review := map[string]bool{}
	var reviewNames []string
	for _, c := range cols {
		if c.Unclassified() {
			h.Unclassified++
			h.UnclassifiedNames = appendName(h.UnclassifiedNames, c.Name())
			continue
		}
		review[c.Name()] = true
		reviewNames = append(reviewNames, c.Name())
	}
	for _, n := range flagged {
		if !review[n] {
			review[n] = true
			reviewNames = append(reviewNames, n)
		}
	}
	slices.Sort(reviewNames)
	h.Review = len(reviewNames)
	h.ReviewNames = reviewNames[:min(len(reviewNames), MaxPIINames)]
	return h, nil
}

func appendName(names []string, n string) []string {
	if len(names) >= MaxPIINames {
		return names
	}
	return append(names, n)
}

// CheckHealth verifies the chain (incrementally from opts.Pin), lists
// unguarded tables and tables row-level security hides from the agent, and finds the agent's last heartbeat and recent
// dead-man row. now is the caller's clock.
func CheckHealth(ctx context.Context, q guard.Querier, now time.Time, opts HealthOptions) (Health, error) {
	var h Health
	var err error
	if h.Install, err = guard.InstallID(ctx, q); err != nil {
		return Health{}, fmt.Errorf("guard install: %w", err)
	}
	kept := false
	if opts.Pin != nil && opts.PinInstall != h.Install {
		if kept, err = settle(ctx, q, &h, &opts); err != nil {
			return Health{}, err
		}
	}
	if !kept {
		if h.Chain, h.Head, err = verify(ctx, q, opts); err != nil {
			return Health{}, err
		}
	}
	if h.Reinstalls, err = guard.ReadReinstalls(ctx, q, opts.SetAside); err != nil {
		return Health{}, fmt.Errorf("reinstalls: %w", err)
	}
	if h.Uncovered, err = guard.UncoveredTables(ctx, q); err != nil {
		return Health{}, err
	}
	if h.RLSBlind, err = guard.RLSBlindTables(ctx, q, "", nil); err != nil {
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
	if h.PII, err = checkPII(ctx, q); err != nil {
		return Health{}, err
	}
	if h.Plugins, err = checkPlugins(ctx, q); err != nil {
		return Health{}, fmt.Errorf("plugins: %w", err)
	}
	return h, nil
}

// settle handles a pin of another install (SettlePin) and sets the pin to
// verify from: the moved head, or none after a set-aside (the full check).
// A pin that could not be reported is kept (true): it is never verified
// from, since verify_chain_from accepts any pin before the anchor, and the
// chain is reported broken at it (step 3), so the caller saves no new pin.
func settle(ctx context.Context, q guard.Querier, h *Health, opts *HealthOptions) (bool, error) {
	s, err := SettlePin(ctx, q, *opts.Pin, opts.PinInstall)
	if err != nil {
		return false, err
	}
	switch s.Fate {
	case PinMoved:
		h.PinMoved, opts.Pin = true, &s.Head
	case PinSetAside:
		h.PinSetAside, opts.Pin = true, nil
	case PinKept:
		h.Chain, h.Head = guard.ChainStatus{BrokenAt: opts.Pin.Seq}, *opts.Pin
		return true, nil
	}
	return false, nil
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
