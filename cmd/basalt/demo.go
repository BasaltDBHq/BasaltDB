package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The sample database of basalt init --demo (CONTRACT.md, CLI).
const (
	demoSchemaName = "basalt_demo"
	// demoComment marks a schema init --demo made, so uninstall drops only that.
	demoComment = "BasaltDB demo data"
	// demoAgent is the demo's agent unless --agent names another.
	demoAgent  = "demo_bot"
	demoTables = "basalt_demo.leads,basalt_demo.lead_notes"
)

//go:embed demo_schema.sql
var demoSchemaSQL string

//go:embed demo_leads.sql
var demoLeadsSQL string

//go:embed demo_notes.sql
var demoNotesSQL string

// demoPlan is what seeding the sample schema will run.
type demoPlan struct {
	// sql is what runs, in order; empty when the demo already exists.
	sql []string
}

// shown is the SQL the person reads before confirming.
func (p demoPlan) shown() string {
	out := ""
	for _, s := range p.sql {
		out += s + "\n"
	}
	return out
}

// planDemo reads what exists and plans only what is missing: the schema, and
// each table with its rows. A table that exists is not touched (no row,
// index or row-level security change).
func planDemo(ctx context.Context, q guard.Querier) (demoPlan, error) {
	var schema, leads, notes bool
	err := q.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace($1) IS NOT NULL,
		pg_catalog.to_regclass($2) IS NOT NULL, pg_catalog.to_regclass($3) IS NOT NULL`,
		demoSchemaName, demoSchemaName+".leads", demoSchemaName+".lead_notes").Scan(&schema, &leads, &notes)
	if err != nil {
		return demoPlan{}, err
	}
	var p demoPlan
	if leads && notes {
		return p, nil
	}
	if !schema {
		p.sql = append(p.sql, demoSchemaSQL)
	}
	if !leads {
		p.sql = append(p.sql, demoLeadsSQL)
	}
	if !notes {
		p.sql = append(p.sql, demoNotesSQL)
	}
	return p, nil
}

// apply runs the plan on tx.
func (p demoPlan) apply(ctx context.Context, tx pgx.Tx) error {
	for _, s := range p.sql {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("sample data: %w", err)
		}
	}
	return nil
}

// demoCounts is the row count of each sample table.
func demoCounts(ctx context.Context, q guard.Querier) (leads, notes int, err error) {
	// Plain SQL: counts of fixed demo tables.
	err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM basalt_demo.leads)::int,
		(SELECT count(*) FROM basalt_demo.lead_notes)::int`).Scan(&leads, &notes)
	return leads, notes, err
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
	plan, err := planDemo(c.ctx, tx)
	if err == nil {
		err = plan.apply(c.ctx, tx)
	}
	if err != nil {
		rollback()
		return nil, "", nil, err
	}
	if len(plan.sql) == 0 {
		fmt.Fprintln(c.stderr, "basalt: sample schema basalt_demo already exists; its rows are left as they are")
	} else {
		shown = plan.shown() + "\n"
	}
	return tx, shown, rollback, nil
}

// applyDemo seeds the sample schema again, in a fresh transaction, and
// applies the install in it (the schema may have changed while the person
// decided; checkCovered catches drift).
func applyDemo(ctx context.Context, conn *pgx.Conn, script guard.Script) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		plan, err := planDemo(ctx, tx)
		if err != nil {
			return err
		}
		if err := plan.apply(ctx, tx); err != nil {
			return err
		}
		return applyInitTx(ctx, tx, script)
	})
}
