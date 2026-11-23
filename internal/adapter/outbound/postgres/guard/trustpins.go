package guard

import (
	"context"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// sqlstateUndefinedTable is a view that does not exist: a guard below
// TrustPinsVersion.
const sqlstateUndefinedTable = "42P01"

// RecordTrustPin records, on the admin connection, the pin of host:port to
// the certificate whose DER SHA-256 (lowercase hex) is sha256: a
// TRUST_PIN_RECORDED ledger row. Needs TrustPinsVersion.
func RecordTrustPin(ctx context.Context, q Querier, host string, port int, sha256 string) error {
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.record_trust_pin(?::text, ?::int, ?::text)", host, port, sha256)).ToSql()
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, sql, args...)
	return err
}

// RecordedTrustPin is the fingerprint the ledger records for host:port,
// read on the agent's connection from agent_trust_pins: false when none is
// recorded or the guard is older than TrustPinsVersion.
func RecordedTrustPin(ctx context.Context, q Querier, host string, port int) (string, bool, error) {
	sql, args, err := psql.Select("sha256").From("basalt_meta.agent_trust_pins").
		Where(sq.Eq{"host": host, "port": port}).ToSql()
	if err != nil {
		return "", false, err
	}
	var sha string
	err = q.QueryRow(ctx, sql, args...).Scan(&sha)
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows), errors.As(err, &pg) && pg.Code == sqlstateUndefinedTable:
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return sha, true, nil
}

// RecordedTrustPinTx is RecordedTrustPin read in tx with the admin
// connection, as the guard role: the admin may not read agent_trust_pins.
func RecordedTrustPinTx(ctx context.Context, tx pgx.Tx, n guardmodel.Names, host string, port int) (sha string, ok bool, err error) {
	err = asGuard(ctx, tx, n, func() error {
		var err error
		sha, ok, err = RecordedTrustPin(ctx, tx, host, port)
		return err
	})
	return sha, ok, err
}
