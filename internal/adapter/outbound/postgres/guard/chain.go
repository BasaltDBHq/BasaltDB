package guard

import (
	"context"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ChainStatus is the result of VerifyChain.
type ChainStatus struct {
	Intact bool
	// BrokenAt is the first seq that does not verify (or is missing).
	BrokenAt int64
}

// ChainHead is the last appended ledger row.
type ChainHead struct {
	Seq  int64
	Hash []byte
}

// hashBytes is the length of a ledger hash (sha256).
const hashBytes = 32

// Genesis is the pin before the first ledger row. Verifying from it is the
// full check.
func Genesis() ChainHead { return ChainHead{Seq: 0, Hash: make([]byte, hashBytes)} }

// ErrNoInstall is InstallID's error when basalt_meta has no install row:
// it was recreated outside the install, or the row deleted. basalt init
// writes a new one, a new install.
var ErrNoInstall = errors.New("basalt_meta has no install record; run basalt init again with the admin connection string")

// InstallID identifies this install of the guard: the random id the
// install wrote (basalt_meta.install_id), which no other install has, a new
// install after a removal or DROP SCHEMA included, and which a copy
// of basalt_meta keeps. A chain pin carries it, so a pin of an earlier
// install is set aside instead of checked against a new ledger.
func InstallID(ctx context.Context, q Querier) (uuid.UUID, error) {
	sql, args, err := psql.Select("basalt_meta.install_id()").ToSql()
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.NullUUID
	if err := q.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
		return uuid.Nil, err
	}
	if !id.Valid {
		return uuid.Nil, ErrNoInstall
	}
	return id.UUID, nil
}

// VerifyChain recomputes the ledger hash chain from its anchor (D8).
func VerifyChain(ctx context.Context, q Querier) (ChainStatus, error) {
	sql, args, err := psql.Select("basalt_meta.verify_chain()").ToSql()
	if err != nil {
		return ChainStatus{}, err
	}
	var broken *int64
	if err := q.QueryRow(ctx, sql, args...).Scan(&broken); err != nil {
		return ChainStatus{}, err
	}
	if broken == nil {
		return ChainStatus{Intact: true}, nil
	}
	return ChainStatus{BrokenAt: *broken}, nil
}

// VerifyChainFrom verifies the chain from a head pinned earlier: the
// pinned row must still carry its hash, and every later row is recomputed
// up to the current head. It returns the head it verified, to pin next;
// when the chain is broken it returns from unchanged. Rows before the pin
// are not recomputed (VerifyChain does that), but a consistent rewrite of
// them changes the pinned row's hash and is caught here.
func VerifyChainFrom(ctx context.Context, q Querier, from ChainHead) (ChainStatus, ChainHead, error) {
	sql, args, err := psql.Select("broken_at", "seq", "hash").
		From("basalt_meta.verify_chain_from($1, $2)").ToSql()
	if err != nil {
		return ChainStatus{}, ChainHead{}, err
	}
	args = append(args, from.Seq, from.Hash)
	var broken *int64
	var head ChainHead
	if err := q.QueryRow(ctx, sql, args...).Scan(&broken, &head.Seq, &head.Hash); err != nil {
		return ChainStatus{}, ChainHead{}, err
	}
	if broken != nil {
		return ChainStatus{BrokenAt: *broken}, from, nil
	}
	return ChainStatus{Intact: true}, head, nil
}

// CheckHead reports false when the ledger no longer agrees with a head
// seen earlier: the row at that seq changed, or the chain got shorter. A
// consistent rewrite of the whole chain passes VerifyChain but not this.
func CheckHead(ctx context.Context, q Querier, last ChainHead) (bool, error) {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.check_head(?, ?)", last.Seq, last.Hash)).ToSql()
	if err != nil {
		return false, err
	}
	var ok bool
	err = q.QueryRow(ctx, sql, args...).Scan(&ok)
	return ok, err
}

// UncoveredTables lists agent-writable tables and cascade targets that do
// not carry the guard (new since the last basalt init).
func UncoveredTables(ctx context.Context, q Querier) ([]Uncovered, error) {
	sql, args, err := psql.Select("table_oid::text", "why").From("basalt_meta.uncovered_tables()").OrderBy("1").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Uncovered, error) {
		var u Uncovered
		err := row.Scan(&u.Table, &u.Why)
		return u, err
	})
}
