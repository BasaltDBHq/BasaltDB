package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// Catalog reads the database's structure for describe on the agent's own
// credential: each call in a read-only transaction within the statement
// timeout, as a query runs (agent.Catalog). It reads the catalog and the
// statistics counters only, never a row.
type Catalog struct {
	pool     Pool
	limits   sqlguard.Limits
	database string
	host     string
}

// NewCatalog returns the catalog on pool with limits; database is the name
// the pool connects to. It panics on a nil pool.
func NewCatalog(pool Pool, limits sqlguard.Limits, database string) *Catalog {
	if pool == nil {
		panic("postgres: pool required")
	}
	return &Catalog{pool: pool, limits: limits, database: database}
}

// WithHost sets the host the pool connects to, which describe's overview
// names with the database. It returns c.
func (c *Catalog) WithHost(host string) *Catalog {
	c.host = host
	return c
}

// read runs fn in a read-only transaction within the time limit. It is
// REPEATABLE READ, so every statement fn runs reads one snapshot; a
// read-only transaction never fails to serialize.
func (c *Catalog) read(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	// Read-only: nothing to commit.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := setTimeout(ctx, tx, c.limits); err != nil {
		return err
	}
	return fn(tx)
}

// relationsRaw is Relations before MapError.
func (c *Catalog) relationsRaw(ctx context.Context) (visible []pgcatalog.Relation, notGranted int, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		visible, notGranted, err = pgcatalog.Relations(ctx, tx)
		return err
	})
	return visible, notGranted, err
}

// findRaw is Find before MapError.
func (c *Catalog) findRaw(ctx context.Context, schema, name string) (r pgcatalog.Relation, ok bool, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		r, ok, err = pgcatalog.FindRelation(ctx, tx, schema, name)
		return err
	})
	return r, ok, err
}

// describeRaw is Describe before MapError.
func (c *Catalog) describeRaw(ctx context.Context, oid uint32) (d pgcatalog.Detail, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		d, err = pgcatalog.DescribeRelation(ctx, tx, oid)
		return err
	})
	return d, err
}

// guardedRaw is Guarded before MapError.
func (c *Catalog) guardedRaw(ctx context.Context, oid uint32) (guarded bool, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		// Plain SQL: the guard's own view, read on the agent's credential.
		var view *string
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regclass('basalt_meta.agent_guarded_tables')::text`).Scan(&view); err != nil {
			return err
		}
		if view == nil {
			return nil
		}
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM basalt_meta.agent_guarded_tables WHERE table_oid = $1)`, oid).Scan(&guarded)
	})
	return guarded, err
}

// searchRaw is Search before MapError.
func (c *Catalog) searchRaw(ctx context.Context, q string, exclude []pgcatalog.ColumnKey, after *pgcatalog.SearchCursor, limit int) (m []pgcatalog.Match, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		m, err = pgcatalog.Search(ctx, tx, q, exclude, after, limit)
		return err
	})
	return m, err
}

// structureRaw is Structure before MapError.
func (c *Catalog) structureRaw(ctx context.Context) (lines []string, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		lines, err = pgcatalog.StructureLines(ctx, tx)
		return err
	})
	return lines, err
}

// Database is the database the pool connects to.
func (c *Catalog) Database() string { return c.database }

// Host is the host the pool connects to.
func (c *Catalog) Host() string { return c.host }

// Limits are the limits each call runs within.
func (c *Catalog) Limits() action.Limits { return action.Limits(c.limits) }
