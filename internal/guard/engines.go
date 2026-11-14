package guard

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// maxEngines bounds an engine list (basalt engine list): a database records
// a handful.
const maxEngines = 100

// Detail values of a BS008 refusal by record_engine and revoke_engine
// (CONTRACT.md, basalt_meta "Version 33").
const (
	EngineRefusedKey     = "ENGINE_KEY"
	EngineRefusedURL     = "ENGINE_URL"
	EngineRefusedRevoked = "ENGINE_REVOKED"
	EngineRefusedUnknown = "ENGINE_UNKNOWN"
)

// RecordedEngine is a row of basalt_meta.engines: an engine's public
// identity and the address the person pinned. Never key material beyond
// the public key.
type RecordedEngine struct {
	ID         string
	PublicKey  []byte
	URL        *string
	RecordedAt time.Time
	RevokedAt  *time.Time
}

// RecordEngine records an engine's signing key (its SPKI DER) with the
// admin connection and returns its engine id. A nil url keeps the address
// already recorded. Postgres refuses a malformed key or address and a
// revoked engine (BS008, details above) and appends ENGINE_RECORDED when
// it inserts a key or changes its address.
func RecordEngine(ctx context.Context, q Querier, publicKey []byte, url *string) (string, error) {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.record_engine(?::bytea, ?::text)", publicKey, url)).ToSql()
	if err != nil {
		return "", err
	}
	var id string
	err = q.QueryRow(ctx, sql, args...).Scan(&id)
	return id, err
}

// RevokeEngine revokes an engine with the admin connection and returns how
// many engines remain not revoked. Postgres refuses an unknown or already
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
	sql, args, err := psql.Select("engine_id", "public_key", "url", "recorded_at", "revoked_at").
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
		err := row.Scan(&e.ID, &e.PublicKey, &e.URL, &e.RecordedAt, &e.RevokedAt)
		return e, err
	})
}

// RecordEngineStatement is record_engine as a statement of the install
// transaction basalt init --setup-code runs (before record_setup). A nil
// url keeps the recorded address.
func RecordEngineStatement(publicKey []byte, url *string) Statement {
	u := "NULL"
	if url != nil {
		u = quoteLiteral(*url)
	}
	return Statement{SQL: fmt.Sprintf("\nSELECT basalt_meta.record_engine('\\x%s'::bytea, %s::text);", hex.EncodeToString(publicKey), u)}
}

// RevokeEngineStatement is revoke_engine as a statement of the same
// transaction, for an engine the person chose to revoke at setup.
func RevokeEngineStatement(engineID string) Statement {
	return Statement{SQL: fmt.Sprintf("\nSELECT basalt_meta.revoke_engine(%s::text);", quoteLiteral(engineID))}
}
