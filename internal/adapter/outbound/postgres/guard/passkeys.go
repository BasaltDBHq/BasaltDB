package guard

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// maxPasskeys bounds a passkey list; a database has a handful.
const maxPasskeys = 100

// ActivePasskeys lists the active passkeys with the admin connection
// (basalt passkey remove), oldest first.
func ActivePasskeys(ctx context.Context, q Querier) ([]guardmodel.RegisteredPasskey, error) {
	sql, args, err := psql.Select("credential_id", "label", "rp_id", "origin", "user_handle", "created_at", "last_used_at").
		From("basalt_meta.passkeys").
		Where(sq.Eq{"revoked_at": nil}).
		OrderBy("created_at", "credential_id").
		Limit(maxPasskeys).
		ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (guardmodel.RegisteredPasskey, error) {
		var k guardmodel.RegisteredPasskey
		err := row.Scan(&k.ID, &k.Label, &k.RPID, &k.Origin, &k.UserHandle, &k.CreatedAt, &k.LastUsedAt)
		return k, err
	})
}

// RevokePasskey revokes a passkey with the admin connection and returns
// how many active passkeys remain. Postgres refuses the last one unless
// force (NOT_ALLOWED) and records a PASSKEY_REVOKED ledger row.
func RevokePasskey(ctx context.Context, q Querier, credentialID []byte, force bool) (int, error) {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.revoke_passkey(?::bytea, ?)", credentialID, force)).ToSql()
	if err != nil {
		return 0, err
	}
	var remaining int
	err = q.QueryRow(ctx, sql, args...).Scan(&remaining)
	return remaining, err
}
