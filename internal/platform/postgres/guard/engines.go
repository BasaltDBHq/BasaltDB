package guard

import (
	"context"
	"encoding/hex"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
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

// Engines lists the recorded engines, newest first, at most maxEngines:
// with the admin connection from basalt_meta.engines, with an agent's
// connection from basalt_meta.agent_engines (the same columns).
func Engines(ctx context.Context, q Querier, admin bool) ([]guardmodel.RecordedEngine, error) {
	from := "basalt_meta.agent_engines"
	if admin {
		from = "basalt_meta.engines"
	}
	sql, args, err := sqlport.Builder.Select("engine_id", "public_key", "recorded_at", "revoked_at").
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
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (guardmodel.RecordedEngine, error) {
		var e guardmodel.RecordedEngine
		err := row.Scan(&e.ID, &e.PublicKey, &e.RecordedAt, &e.RevokedAt)
		return e, err
	})
}

// RecordEngineStatement is record_engine as a statement of the install
// transaction a setup runs (before record_setup), for a
// guard migrated up to guardVersion.
func RecordEngineStatement(publicKey []byte, guardVersion int) guardmodel.Statement {
	key := hex.EncodeToString(publicKey)
	if guardVersion < EngineAddressRemovedVersion {
		// A guard installed only up to an earlier version still has the
		// two-argument function; NULL records no address.
		return guardmodel.Statement{SQL: fmt.Sprintf("\nSELECT basalt_meta.record_engine('\\x%s'::bytea, NULL::text);", key)}
	}
	return guardmodel.Statement{SQL: fmt.Sprintf("\nSELECT basalt_meta.record_engine('\\x%s'::bytea);", key)}
}

// EngineRecord is engineID's row in basalt_meta.agent_engines, read with an
// agent's connection: nil when the database does not record it.
func EngineRecord(ctx context.Context, q Querier, engineID string) (*guardmodel.RecordedEngine, error) {
	sql, args, err := sqlport.Builder.Select("engine_id", "public_key", "recorded_at", "revoked_at").
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
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (guardmodel.RecordedEngine, error) {
		var e guardmodel.RecordedEngine
		err := row.Scan(&e.ID, &e.PublicKey, &e.RecordedAt, &e.RevokedAt)
		return e, err
	})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}
