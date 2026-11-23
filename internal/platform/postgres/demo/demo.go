// Package demo is the sample database of basalt init --demo and of the
// local setup page's sample-database install (CONTRACT.md, CLI, The sample
// database): the schema basalt_demo with leads and lead_notes, from SQL
// embedded in the binary.
package demo

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The sample database's names.
const (
	Schema = "basalt_demo"
	// Comment marks a schema the demo made, so removal drops only that.
	Comment = "BasaltDB demo data"
)

// Tables are the sample tables the demo's agent writes.
var Tables = []string{Schema + ".leads", Schema + ".lead_notes"}

//go:embed schema.sql
var schemaSQL string

//go:embed leads.sql
var leadsSQL string

//go:embed notes.sql
var notesSQL string

// Read reads what exists and plans only what is missing: the schema, and
// each table with its rows. A table that exists is not touched (no row,
// index or row-level security change).
func Read(ctx context.Context, q guard.Querier) (guardmodel.DemoPlan, error) {
	var schema, leads, notes bool
	// Plain SQL: catalog lookups of fixed names.
	err := q.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace($1) IS NOT NULL,
		pg_catalog.to_regclass($2) IS NOT NULL, pg_catalog.to_regclass($3) IS NOT NULL`,
		Schema, Schema+".leads", Schema+".lead_notes").Scan(&schema, &leads, &notes)
	if err != nil {
		return guardmodel.DemoPlan{}, err
	}
	var p guardmodel.DemoPlan
	if leads && notes {
		return p, nil
	}
	if !schema {
		p.SQL = append(p.SQL, schemaSQL)
	}
	if !leads {
		p.SQL = append(p.SQL, leadsSQL)
	}
	if !notes {
		p.SQL = append(p.SQL, notesSQL)
	}
	return p, nil
}

// applyPlan runs the plan on tx.
func applyPlan(ctx context.Context, tx pgx.Tx, p guardmodel.DemoPlan) error {
	for _, s := range p.SQL {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("sample data: %w", err)
		}
	}
	return nil
}

// Seed reads and applies the plan on tx.
func Seed(ctx context.Context, tx pgx.Tx) (guardmodel.DemoPlan, error) {
	p, err := Read(ctx, tx)
	if err != nil {
		return guardmodel.DemoPlan{}, err
	}
	return p, applyPlan(ctx, tx, p)
}

// Counts is the row count of each sample table.
func Counts(ctx context.Context, q guard.Querier) (leads, notes int, err error) {
	// Plain SQL: counts of fixed demo tables.
	err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM basalt_demo.leads)::int,
		(SELECT count(*) FROM basalt_demo.lead_notes)::int`).Scan(&leads, &notes)
	return leads, notes, err
}

// dropSQL drops the sample schema without CASCADE, so a view, foreign key
// or table of the person's that depends on it stops the drop instead of
// going with it.
var dropSQL = []string{`DROP TABLE basalt_demo.lead_notes`, `DROP TABLE basalt_demo.leads`, `DROP SCHEMA basalt_demo`}

// PlanDrop is the SQL that removes the sample schema when the demo made it
// (the schema carries Comment), and nothing otherwise. It reads the
// catalog only.
func PlanDrop(ctx context.Context, q guard.Querier) ([]string, error) {
	var made bool
	// Plain SQL: catalog lookup of a fixed name.
	err := q.QueryRow(ctx, `SELECT coalesce(pg_catalog.obj_description(n.oid, 'pg_namespace') = $2, false)
		FROM pg_catalog.pg_namespace n WHERE n.nspname = $1`, Schema, Comment).Scan(&made)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !made) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return append([]string{}, dropSQL...), nil
}

// ApplyDrop runs drops (PlanDrop) in a savepoint of tx: when one fails,
// only they roll back and kept is true, so the sample schema stays and the
// rest of tx goes on. err is for a failure of the savepoint itself.
func ApplyDrop(ctx context.Context, tx pgx.Tx, drops []string) (kept bool, err error) {
	if len(drops) == 0 {
		return false, nil
	}
	sub, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	for _, sql := range drops {
		if _, err := sub.Exec(ctx, sql); err != nil {
			return true, sub.Rollback(ctx)
		}
	}
	return false, sub.Commit(ctx)
}
