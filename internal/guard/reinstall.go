package guard

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Reinstalls on the record (basalt_meta version 36, CONTRACT.md "Version 36:
// reinstalls on the record"). A witness, an engine or basalt log, pins the
// chain head it verified with the install it verified it on (InstallID).
// When the install changed, the pin names a ledger that no longer exists,
// unless the same ledger is still there under a new install id (the
// install row deleted and written again, or a pin saved before install
// ids): PinStillOnChain tells the two apart, and a pin that is not
// on the current chain is reported with RecordPinSetAside before it is set
// aside, so a reinstall is never silent.

// SetAside is one pin a witness set aside after a reinstall and reported
// with RecordPinSetAside. The witness keeps each in its own pin file, so
// deleting the ledger rows does not hide what it saw.
type SetAside struct {
	PinnedSeq  int64
	PinnedHash []byte
	// PinnedInstall is the install the pin was verified on, Install the one
	// it was set aside on.
	PinnedInstall uuid.UUID
	Install       uuid.UUID
	At            time.Time
}

// ReinstallReport is one agent credential's report of a reinstall: its
// earliest, and More further reports of the same install.
type ReinstallReport struct {
	Agent      string
	At         time.Time
	PinnedSeq  int64
	PinnedHash []byte
	More       int
}

// Reinstall is one install the ledger (or the reader's kept copy) records
// pins set aside on. InstalledAt is nil when installs had no row for it:
// basalt_meta was recreated or restored outside basalt init.
type Reinstall struct {
	Install     uuid.UUID
	InstalledAt *time.Time
	InstalledBy string
	VaultUser   string
	// Reports are the reader's own report when there is one, otherwise the
	// earliest, then the other agents' earliest reports, oldest first, at
	// most MaxReinstallAgents of them; MoreAgents counts the rest.
	Reports    []ReinstallReport
	MoreAgents int
}

// FirstReportedAt is the earliest report's time: the first report or the
// earliest of the others, which are oldest first.
func (r Reinstall) FirstReportedAt() time.Time {
	var first time.Time
	for _, rep := range r.Reports {
		if first.IsZero() || rep.At.Before(first) {
			first = rep.At
		}
	}
	return first
}

// Reinstalls are the reinstalls to show, newest first, at most
// MaxReinstalls; Earlier counts the rest.
type Reinstalls struct {
	List    []Reinstall
	Earlier int
}

const (
	// MaxReinstalls is how many reinstalls a notice shows.
	MaxReinstalls = 3
	// MaxReinstallAgents is how many other agents a reinstall's notice
	// names, after the first report.
	MaxReinstallAgents = 5
)

// PinOnChain reports basalt_meta.pin_on_chain: whether the row at head.Seq,
// after the anchor, still holds head.Hash and recomputes to it, or head is
// the anchor.
func PinOnChain(ctx context.Context, q Querier, head ChainHead) (bool, error) {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.pin_on_chain(?, ?)", head.Seq, head.Hash)).ToSql()
	if err != nil {
		return false, err
	}
	var ok bool
	err = q.QueryRow(ctx, sql, args...).Scan(&ok)
	return ok, err
}

// PinStillOnChain reports whether a pin of another install is still on the
// current chain, the first condition for moving it across a restore: true
// when pin_on_chain holds through the pinned row, or through the anchor
// only while the anchor is the genesis (seq 0). A pin at a later anchor
// means the history before it was cut, which a legitimate restore never
// does (a pin is at most an hour old, retention deletes rows after a year).
//
// Agents cannot read chain_anchor: the anchor is the genesis when the
// genesis is on the chain, and a pin at seq n is the anchor itself when
// check_head accepts seq n-1 with a hash no row has, which it does only
// for a seq before the anchor (or seq 0).
func PinStillOnChain(ctx context.Context, q Querier, head ChainHead) (bool, error) {
	on, err := PinOnChain(ctx, q, head)
	if err != nil || !on {
		return false, err
	}
	genesis, err := PinOnChain(ctx, q, Genesis())
	if err != nil || genesis {
		return genesis, err
	}
	if head.Seq <= 1 {
		// The anchor is past the genesis, and the pin at or after it.
		return false, nil
	}
	beforeAnchor, err := CheckHead(ctx, q, ChainHead{Seq: head.Seq - 1, Hash: make([]byte, hashBytes)})
	if err != nil {
		return false, err
	}
	return !beforeAnchor, nil
}

// RecordPinSetAside reports with basalt_meta.record_pin_set_aside that the
// pin head, verified on install, is set aside. It returns false when this
// role made the same report before. A guard older than version 36 fails.
func RecordPinSetAside(ctx context.Context, q Querier, head ChainHead, install uuid.UUID) (bool, error) {
	sql, args, err := psql.Select().
		Column(sq.Expr("basalt_meta.record_pin_set_aside(?, ?, ?)", head.Seq, head.Hash, install)).ToSql()
	if err != nil {
		return false, err
	}
	var appended bool
	err = q.QueryRow(ctx, sql, args...).Scan(&appended)
	return appended, err
}

// reportRow is one agent's earliest report of one install, with how many
// it made.
type reportRow struct {
	Install uuid.UUID
	Agent   string
	At      time.Time
	Seq     int64
	Hash    []byte
	Count   int
}

// installRecord is the install's row as the earliest report that had one
// copied it.
type installRecord struct {
	At        time.Time
	By        string
	VaultUser string
}

// ReadReinstalls reads agent_reinstalls and merges kept, the reader's own
// kept copy, into the reinstalls to show. A guard without agent_reinstalls
// (older than version 36) adds nothing to kept.
func ReadReinstalls(ctx context.Context, q Querier, kept []SetAside) (Reinstalls, error) {
	var self string
	sql, args, err := psql.Select("session_user::text").ToSql()
	if err != nil {
		return Reinstalls{}, err
	}
	if err := q.QueryRow(ctx, sql, args...).Scan(&self); err != nil {
		return Reinstalls{}, err
	}
	var has bool
	sql, args, err = psql.Select("to_regclass('basalt_meta.agent_reinstalls') IS NOT NULL").ToSql()
	if err != nil {
		return Reinstalls{}, err
	}
	if err := q.QueryRow(ctx, sql, args...).Scan(&has); err != nil {
		return Reinstalls{}, err
	}
	if !has {
		return assembleReinstalls(self, nil, nil, kept), nil
	}
	rows, err := readReportRows(ctx, q)
	if err != nil {
		return Reinstalls{}, err
	}
	recs, err := readInstallRecords(ctx, q)
	if err != nil {
		return Reinstalls{}, err
	}
	return assembleReinstalls(self, rows, recs, kept), nil
}

// readReportRows is each agent's earliest report of each install. One row
// per install and agent role, however many reports a role made.
func readReportRows(ctx context.Context, q Querier) ([]reportRow, error) {
	sql, args, err := psql.Select("r.install", "r.agent::text", "r.at", "r.pinned_seq", "r.pinned_hash",
		"(count(r.pinned_seq) OVER (PARTITION BY r.install, r.agent))::int").
		Options("DISTINCT ON (r.install, r.agent)").
		From("basalt_meta.agent_reinstalls r").
		OrderBy("r.install", "r.agent", "r.at", "r.pinned_seq").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (reportRow, error) {
		var r reportRow
		err := row.Scan(&r.Install, &r.Agent, &r.At, &r.Seq, &r.Hash, &r.Count)
		return r, err
	})
}

// readInstallRecords is each install's row, from its earliest report that
// copied one.
func readInstallRecords(ctx context.Context, q Querier) (map[uuid.UUID]installRecord, error) {
	sql, args, err := psql.Select("r.install", "r.installed_at", "coalesce(r.installed_by, '')", "coalesce(r.vault_user, '')").
		Options("DISTINCT ON (r.install)").
		From("basalt_meta.agent_reinstalls r").
		Where(sq.NotEq{"r.installed_at": nil}).
		OrderBy("r.install", "r.at").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]installRecord{}
	for rows.Next() {
		var install uuid.UUID
		var r installRecord
		if err := rows.Scan(&install, &r.At, &r.By, &r.VaultUser); err != nil {
			return nil, err
		}
		out[install] = r
	}
	return out, rows.Err()
}

// assembleReinstalls groups the reports by install, adds the reader's kept
// copy to its own reports, and orders and bounds what the notice shows.
func assembleReinstalls(self string, rows []reportRow, recs map[uuid.UUID]installRecord, kept []SetAside) Reinstalls {
	byInstall := map[uuid.UUID][]reportRow{}
	for _, r := range rows {
		byInstall[r.Install] = append(byInstall[r.Install], r)
	}
	for install, own := range keptReports(self, kept) {
		byInstall[install] = mergeOwn(byInstall[install], own)
	}
	list := make([]Reinstall, 0, len(byInstall))
	for install, reports := range byInstall {
		list = append(list, buildReinstall(self, install, reports, recs))
	}
	slices.SortFunc(list, func(a, b Reinstall) int {
		if c := reinstallTime(b).Compare(reinstallTime(a)); c != 0 {
			return c
		}
		return bytes.Compare(b.Install[:], a.Install[:])
	})
	out := Reinstalls{List: list}
	if len(list) > MaxReinstalls {
		out.List, out.Earlier = list[:MaxReinstalls], len(list)-MaxReinstalls
	}
	return out
}

// reinstallTime orders reinstalls: the install's time when recorded, else
// its first report.
func reinstallTime(r Reinstall) time.Time {
	if r.InstalledAt != nil {
		return *r.InstalledAt
	}
	return r.FirstReportedAt()
}

// keptReports is the kept copy as the reader's earliest report per install.
func keptReports(self string, kept []SetAside) map[uuid.UUID]reportRow {
	out := map[uuid.UUID]reportRow{}
	for _, k := range kept {
		r, ok := out[k.Install]
		r.Count++
		if !ok || k.At.Before(r.At) {
			r.Install, r.Agent, r.At, r.Seq, r.Hash = k.Install, self, k.At, k.PinnedSeq, k.PinnedHash
		}
		out[k.Install] = r
	}
	return out
}

// mergeOwn puts the reader's kept report into an install's reports: the
// earlier of it and the ledger's, with the larger count.
func mergeOwn(reports []reportRow, own reportRow) []reportRow {
	i := slices.IndexFunc(reports, func(r reportRow) bool { return r.Agent == own.Agent })
	if i < 0 {
		return append(reports, own)
	}
	count := max(reports[i].Count, own.Count)
	if own.At.Before(reports[i].At) {
		reports[i] = own
	}
	reports[i].Count = count
	return reports
}

func buildReinstall(self string, install uuid.UUID, reports []reportRow, recs map[uuid.UUID]installRecord) Reinstall {
	slices.SortFunc(reports, func(a, b reportRow) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return cmp.Compare(a.Agent, b.Agent)
	})
	first := slices.IndexFunc(reports, func(r reportRow) bool { return r.Agent == self })
	if first < 0 {
		first = 0
	}
	out := Reinstall{Install: install}
	if rec, ok := recs[install]; ok {
		at := rec.At
		out.InstalledAt, out.InstalledBy, out.VaultUser = &at, rec.By, rec.VaultUser
	}
	out.Reports = append(out.Reports, toReport(reports[first]))
	others := slices.Delete(slices.Clone(reports), first, first+1)
	for i, r := range others {
		if i == MaxReinstallAgents {
			out.MoreAgents = len(others) - MaxReinstallAgents
			break
		}
		out.Reports = append(out.Reports, toReport(r))
	}
	return out
}

func toReport(r reportRow) ReinstallReport {
	return ReinstallReport{Agent: r.Agent, At: r.At, PinnedSeq: r.Seq, PinnedHash: r.Hash, More: r.Count - 1}
}
