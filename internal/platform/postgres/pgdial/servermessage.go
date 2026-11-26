package pgdial

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// ServerMessage is the message of the Postgres server error err wraps;
// false when err is no server error.
func ServerMessage(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", false
	}
	return pg.Message, true
}
