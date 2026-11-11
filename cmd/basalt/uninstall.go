package main

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// runUninstall: basalt uninstall. Drops basalt_meta (the guard, its
// triggers and the ledger) and the roles, with the admin connection string.
func runUninstall(c *cliIO, args []string) int {
	fs := c.flags("uninstall")
	prefix := fs.String("prefix", guard.DefaultPrefix, "role name prefix")
	yes := fs.Bool("yes", false, "do not ask before dropping")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	names := guard.Names{Prefix: *prefix}
	if err := names.Validate(); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	admin, err := c.adminURL()
	if err != nil {
		return c.fail(err)
	}
	if !*yes {
		ok, err := c.confirm(fmt.Sprintf("Drop basalt_meta, the ledger and every %s_* role?", names.Prefix))
		if err != nil {
			return c.fail(err)
		}
		if !ok {
			return c.fail(errors.New("uninstall canceled; nothing changed"))
		}
	}

	ctx := c.ctx
	conn, err := connect(ctx, admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(ctx)
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return guard.Uninstall(ctx, tx, names) }); err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, "basalt: guard uninstalled; credential files of its agents no longer work")
	return exitOK
}
