package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/demo"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The sample database of basalt init --demo (CONTRACT.md, CLI).
const (
	demoSchemaName = demo.Schema
	// demoComment marks a schema init --demo made, so uninstall drops only that.
	demoComment = demo.Comment
	// demoAgent is the demo's agent unless --agent names another.
	demoAgent = demo.Agent
)

// demoTables are the sample tables, as --write takes them.
var demoTables = strings.Join(demo.Tables, ",")

// demoCounts is the row count of each sample table.
func demoCounts(ctx context.Context, q guard.Querier) (leads, notes int, err error) {
	return demo.Counts(ctx, q)
}

// dropDemo drops basalt_demo when init --demo made it (it carries the
// comment), without CASCADE, so a view, foreign key or table of the
// person's is never dropped. When a drop fails it rolls back only the
// demo's three statements and returns the reason in kept; err is for any
// other failure.
func dropDemo(ctx context.Context, q pgx.Tx) (dropped bool, kept string, err error) {
	var made bool
	err = q.QueryRow(ctx, `SELECT coalesce(pg_catalog.obj_description(n.oid, 'pg_namespace') = $2, false)
		FROM pg_catalog.pg_namespace n WHERE n.nspname = $1`, demoSchemaName, demoComment).Scan(&made)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if !made {
		return false, "", nil
	}
	sub, err := q.Begin(ctx)
	if err != nil {
		return false, "", err
	}
	for _, sql := range []string{`DROP TABLE basalt_demo.lead_notes`, `DROP TABLE basalt_demo.leads`, `DROP SCHEMA basalt_demo`} {
		if _, err := sub.Exec(ctx, sql); err != nil {
			_ = sub.Rollback(ctx)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) {
				return false, "", err
			}
			kept = pg.Message
			if pg.Detail != "" {
				kept += " (" + pg.Detail + ")"
			}
			return false, kept, nil
		}
	}
	return true, "", sub.Commit(ctx)
}

// planDemoTx opens the transaction init plans in, seeds the sample schema in
// it and returns it as the Querier to plan with, the sample SQL to show, and
// the rollback to defer. It prints the note when the demo already exists.
func planDemoTx(c *cliIO, conn *pgx.Conn) (q guard.Querier, shown string, rollback func(), err error) {
	tx, err := conn.Begin(c.ctx)
	if err != nil {
		return nil, "", nil, err
	}
	rollback = func() { _ = tx.Rollback(c.ctx) }
	plan, err := demo.Seed(c.ctx, tx)
	if err != nil {
		rollback()
		return nil, "", nil, err
	}
	if plan.Exists() {
		fmt.Fprintln(c.stderr, "basalt: sample schema basalt_demo already exists; its rows are left as they are")
	} else {
		shown = plan.Shown() + "\n"
	}
	return tx, shown, rollback, nil
}

// applyDemo seeds the sample schema again, in a fresh transaction, and
// applies the install in it (the schema may have changed while the person
// decided; checkCovered catches drift).
func applyDemo(ctx context.Context, conn *pgx.Conn, script guard.Script) error {
	return withGuardDetail(pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := demo.Seed(ctx, tx); err != nil {
			return err
		}
		return applyInitTx(ctx, tx, script)
	}))
}
