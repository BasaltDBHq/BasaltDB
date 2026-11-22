// Package demo is the sample database of basalt init --demo and of the
// local setup page's sample-database install (CONTRACT.md, CLI, The sample
// database): the schema basalt_demo with leads and lead_notes, from SQL
// embedded in the binary.
package demo

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The sample database's names.
const (
	Schema = "basalt_demo"
	// Comment marks a schema the demo made, so removal drops only that.
	Comment = "BasaltDB demo data"
	// Agent is the demo's agent unless one is named.
	Agent = "demo_bot"
)

// Tables are the sample tables the demo's agent writes.
var Tables = []string{Schema + ".leads", Schema + ".lead_notes"}

//go:embed schema.sql
var schemaSQL string

//go:embed leads.sql
var leadsSQL string

//go:embed notes.sql
var notesSQL string

// Plan is what seeding the sample schema will run.
type Plan struct {
	// SQL is what runs, in order; empty when the demo already exists.
	SQL []string
}

// Shown is the SQL the person reads before confirming.
func (p Plan) Shown() string {
	var b strings.Builder
	for _, s := range p.SQL {
		b.WriteString(s + "\n")
	}
	return b.String()
}

// Exists: both sample tables are there, and nothing is seeded.
func (p Plan) Exists() bool { return len(p.SQL) == 0 }

// Read reads what exists and plans only what is missing: the schema, and
// each table with its rows. A table that exists is not touched (no row,
// index or row-level security change).
func Read(ctx context.Context, q guard.Querier) (Plan, error) {
	var schema, leads, notes bool
	// Plain SQL: catalog lookups of fixed names.
	err := q.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace($1) IS NOT NULL,
		pg_catalog.to_regclass($2) IS NOT NULL, pg_catalog.to_regclass($3) IS NOT NULL`,
		Schema, Schema+".leads", Schema+".lead_notes").Scan(&schema, &leads, &notes)
	if err != nil {
		return Plan{}, err
	}
	var p Plan
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

// Apply runs the plan on tx.
func (p Plan) Apply(ctx context.Context, tx pgx.Tx) error {
	for _, s := range p.SQL {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("sample data: %w", err)
		}
	}
	return nil
}

// Seed reads and applies the plan on tx.
func Seed(ctx context.Context, tx pgx.Tx) (Plan, error) {
	p, err := Read(ctx, tx)
	if err != nil {
		return Plan{}, err
	}
	return p, p.Apply(ctx, tx)
}

// Counts is the row count of each sample table.
func Counts(ctx context.Context, q guard.Querier) (leads, notes int, err error) {
	// Plain SQL: counts of fixed demo tables.
	err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM basalt_demo.leads)::int,
		(SELECT count(*) FROM basalt_demo.lead_notes)::int`).Scan(&leads, &notes)
	return leads, notes, err
}
