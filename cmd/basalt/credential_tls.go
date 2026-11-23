package main

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// probeLogin tries a login with dsn and closes it: the error says how far
// it got (setup.HardenedCredential).
func probeLogin(c *cli.IO) func(context.Context, string) error {
	return func(ctx context.Context, dsn string) error {
		ctx, cancel := context.WithTimeout(ctx, setup.LoginTimeout)
		defer cancel()
		conn, err := c.Dial(ctx, dsn)
		if err != nil {
			return err
		}
		return conn.Close(ctx)
	}
}

// pgErrors is setup.DBErrors on pgx's server errors.
type pgErrors struct{}

func (pgErrors) SQLState(err error) (string, string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", "", false
	}
	return pg.Code, pg.Message, true
}
