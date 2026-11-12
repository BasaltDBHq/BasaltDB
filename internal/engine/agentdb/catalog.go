package agentdb

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// Catalog reads the database's structure for describe on the agent's own
// credential: each call in a read-only transaction within the statement
// timeout, as a query runs (agent.Catalog). It reads the catalog and the
// statistics counters only, never a row.
type Catalog struct {
	pool     Pool
	limits   sqlguard.Limits
	database string
}

// NewCatalog returns the catalog on pool with limits; database is the name
// the pool connects to. It panics on a nil pool.
func NewCatalog(pool Pool, limits sqlguard.Limits, database string) *Catalog {
	if pool == nil {
		panic("agentdb: pool required")
	}
	return &Catalog{pool: pool, limits: limits, database: database}
}

// read runs fn in a read-only transaction within the time limit.
func (c *Catalog) read(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
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

// Relations is pgcatalog.Relations.
func (c *Catalog) Relations(ctx context.Context) (visible []pgcatalog.Relation, notGranted int, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		visible, notGranted, err = pgcatalog.Relations(ctx, tx)
		return err
	})
	return visible, notGranted, err
}

// Find is pgcatalog.FindRelation.
func (c *Catalog) Find(ctx context.Context, schema, name string) (r pgcatalog.Relation, ok bool, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		r, ok, err = pgcatalog.FindRelation(ctx, tx, schema, name)
		return err
	})
	return r, ok, err
}

// Describe is pgcatalog.DescribeRelation, every read of it in one snapshot.
func (c *Catalog) Describe(ctx context.Context, oid uint32) (d pgcatalog.Detail, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		d, err = pgcatalog.DescribeRelation(ctx, tx, oid)
		return err
	})
	return d, err
}

// Search is pgcatalog.Search.
func (c *Catalog) Search(ctx context.Context, q string, exclude []pgcatalog.ColumnKey, after *pgcatalog.SearchCursor, limit int) (m []pgcatalog.Match, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		m, err = pgcatalog.Search(ctx, tx, q, exclude, after, limit)
		return err
	})
	return m, err
}

// Structure is pgcatalog.StructureLines.
func (c *Catalog) Structure(ctx context.Context) (lines []string, err error) {
	err = c.read(ctx, func(tx pgx.Tx) error {
		lines, err = pgcatalog.StructureLines(ctx, tx)
		return err
	})
	return lines, err
}

// Database is the database the pool connects to.
func (c *Catalog) Database() string { return c.database }

// Limits are the limits each call runs within.
func (c *Catalog) Limits() sqlguard.Limits { return c.limits }
