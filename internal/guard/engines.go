package guard

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// maxEngines bounds an engine list: a database records a handful.
const maxEngines = 100

// Detail values of a BS008 refusal by record_engine and revoke_engine
// (CONTRACT.md, basalt_meta "Version 33").
const (
	EngineRefusedKey     = "ENGINE_KEY"
	EngineRefusedRevoked = "ENGINE_REVOKED"
	EngineRefusedUnknown = "ENGINE_UNKNOWN"
)

// RecordedEngine is a row of basalt_meta.engines: an engine's public
// identity and whether it is revoked. Never key material beyond the public
// key.
type RecordedEngine struct {
	ID         string
	PublicKey  []byte
	RecordedAt time.Time
	RevokedAt  *time.Time
}

// RecordEngine records an engine's signing key (its SPKI DER) with the
// admin connection and returns its engine id. Postgres refuses a malformed
// key and a revoked engine (BS008, details above) and appends
// ENGINE_RECORDED when it inserts a key. Kept for tests, which run
// record_engine through it; basalt init runs RecordEngineStatement.
func RecordEngine(ctx context.Context, q Querier, publicKey []byte) (string, error) {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.record_engine(?::bytea)", publicKey)).ToSql()
	if err != nil {
		return "", err
	}
	var id string
	err = q.QueryRow(ctx, sql, args...).Scan(&id)
	return id, err
}

// RevokeEngine revokes an engine with the admin connection and returns how
// many engines remain not revoked. No command or page calls it: it is kept
// for tests of revoke_engine, which the guard still has. Postgres refuses an unknown or already
// revoked id alike (BS008, ENGINE_UNKNOWN) and appends ENGINE_REVOKED.
func RevokeEngine(ctx context.Context, q Querier, engineID string) (int, error) {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.revoke_engine(?::text)", engineID)).ToSql()
	if err != nil {
		return 0, err
	}
	var remaining int
	err = q.QueryRow(ctx, sql, args...).Scan(&remaining)
	return remaining, err
}

// Engines lists the recorded engines, newest first, at most maxEngines:
// with the admin connection from basalt_meta.engines, with an agent's
// connection from basalt_meta.agent_engines (the same columns).
func Engines(ctx context.Context, q Querier, admin bool) ([]RecordedEngine, error) {
	from := "basalt_meta.agent_engines"
	if admin {
		from = "basalt_meta.engines"
	}
	sql, args, err := psql.Select("engine_id", "public_key", "recorded_at", "revoked_at").
		From(from).
		OrderBy("recorded_at DESC", "engine_id").
		Limit(maxEngines).
		ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (RecordedEngine, error) {
		var e RecordedEngine
		err := row.Scan(&e.ID, &e.PublicKey, &e.RecordedAt, &e.RevokedAt)
		return e, err
	})
}

// RecordEngineStatement is record_engine as a statement of the install
// transaction basalt init --setup-code runs (before record_setup), for a
// guard migrated up to guardVersion.
func RecordEngineStatement(publicKey []byte, guardVersion int) Statement {
	key := hex.EncodeToString(publicKey)
	if guardVersion < EngineAddressRemovedVersion {
		// A guard installed only up to an earlier version still has the
		// two-argument function; NULL records no address.
		return Statement{SQL: fmt.Sprintf("\nSELECT basalt_meta.record_engine('\\x%s'::bytea, NULL::text);", key)}
	}
	return Statement{SQL: fmt.Sprintf("\nSELECT basalt_meta.record_engine('\\x%s'::bytea);", key)}
}

// EngineRecord is engineID's row in basalt_meta.agent_engines, read with an
// agent's connection: nil when the database does not record it.
func EngineRecord(ctx context.Context, q Querier, engineID string) (*RecordedEngine, error) {
	sql, args, err := psql.Select("engine_id", "public_key", "recorded_at", "revoked_at").
		From("basalt_meta.agent_engines").
		Where(sq.Eq{"engine_id": engineID}).
		ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (RecordedEngine, error) {
		var e RecordedEngine
		err := row.Scan(&e.ID, &e.PublicKey, &e.RecordedAt, &e.RevokedAt)
		return e, err
	})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}
