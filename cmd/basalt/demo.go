package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/demo"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The sample database of basalt init --demo (CONTRACT.md, CLI).
const (
	// demoAgent is the demo's agent unless --agent names another.
	demoAgent = demo.Agent
)

// demoTables are the sample tables, as --write takes them.
var demoTables = strings.Join(demo.Tables, ",")

// demoCounts is the row count of each sample table.
func demoCounts(ctx context.Context, q guard.Querier) (leads, notes int, err error) {
	return demo.Counts(ctx, q)
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
