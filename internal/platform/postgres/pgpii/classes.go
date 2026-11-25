package pgpii

import (
	"bytes"
	"context"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/agentcatalog"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// Querier is a pool, a connection or a transaction, on the agent's
// credential.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Pool is the agent's pool: it can also begin a transaction of its own.
type Pool interface {
	Querier
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// ClassStore reads one agent's classes (pii.Classes).
type ClassStore struct {
	db Querier
	// pool is db when it can open a snapshot of its own; nil inside a
	// caller's transaction.
	pool Pool
	// between runs between a snapshot's two reads (tests); a no-op otherwise.
	between func()
}

// Classes reads through the agent's pool: each snapshot in a repeatable-read,
// read-only transaction of its own, so the classes and their marks come from
// one snapshot. Loads through it are shared. It panics on a nil pool.
func Classes(pool Pool) *ClassStore {
	if pool == nil {
		panic("pgpii: pool required")
	}
	return &ClassStore{db: pool, pool: pool, between: func() {}}
}

// ClassesInTx reads inside the caller's transaction (a write's RETURNING),
// on its connection, so a full pool cannot wedge it. Loads through it are
// not shared. It panics on a nil transaction.
func ClassesInTx(tx Querier) *ClassStore {
	if tx == nil {
		panic("pgpii: transaction required")
	}
	return &ClassStore{db: tx, between: func() {}}
}

// Shared is true for the pool, false inside a transaction.
func (c *ClassStore) Shared() bool { return c.pool != nil }

// ResourceOf is the table of a field ref: its oid, the part before the "/".
func (c *ClassStore) ResourceOf(ref agentstore.FieldRef) agentstore.ResourceRef {
	return resourceOf(ref)
}

func resourceOf(ref agentstore.FieldRef) agentstore.ResourceRef {
	table, _, _ := strings.Cut(string(ref), "/")
	return agentstore.ResourceRef(table)
}

// Snapshot reads the marks, then the classes, ordered by table oid and
// attribute number.
func (c *ClassStore) Snapshot(ctx context.Context) (piistore.Snapshot, error) {
	return withSnapshot(ctx, c, func(ctx context.Context, q Querier) (piistore.Snapshot, error) {
		return readSnapshot(ctx, q, c.between)
	})
}

// Marks reads pii_fingerprint() and the agent_pii_catalog row.
func (c *ClassStore) Marks(ctx context.Context) (piistore.Marks, error) {
	return withSnapshot(ctx, c, readMarks)
}

// Unclassified reads basalt_meta.pii_unclassified() as the login role.
func (c *ClassStore) Unclassified(ctx context.Context) ([]piistore.Unclassified, error) {
	rows, err := c.db.Query(ctx, "SELECT table_schema, table_name, column_name, data_type, why FROM basalt_meta.pii_unclassified()")
	if err != nil {
		return nil, err
	}
	// Collected as pgx.CollectRows does: an empty answer is an empty slice,
	// and any error drops what was read.
	out := []piistore.Unclassified{}
	var col guardmodel.UnclassifiedColumn
	if err := forEachRow(rows, []any{&col.Schema, &col.Table, &col.Column, &col.DataType, &col.Why}, func() error {
		out = append(out, piistore.Unclassified{Name: col.Name(), DataType: col.DataType, Changed: !col.Unclassified()})
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// withSnapshot runs read in one repeatable-read, read-only transaction when
// c is the pool, so the map and its marks come from one snapshot; inside a
// caller's transaction (a write's RETURNING) it runs there.
func withSnapshot[T any](ctx context.Context, c *ClassStore, read func(context.Context, Querier) (T, error)) (T, error) {
	if c.pool == nil {
		return read(ctx, c.db)
	}
	var out T
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	return read(ctx, tx)
}

// readSnapshot reads the marks first, then the classes. Inside a write's
// read-committed transaction the two are separate statements, and a basalt
// classify may commit between them: marks read first are then the older
// ones, so the next hourly tick sees the catalog move and reloads. (Read
// the other way round, old classes would be kept with new marks and never
// reloaded.) between runs between the two reads (tests).
func readSnapshot(ctx context.Context, db Querier, between func()) (piistore.Snapshot, error) {
	mk, err := readMarks(ctx, db)
	if err != nil {
		return piistore.Snapshot{}, err
	}
	between()
	q, args, err := psql.Select("table_oid", "attnum", "table_schema", "table_name", "column_name",
		"class", "coalesce(entity_type, '')", "coalesce(phone_region, '')").
		From("basalt_meta.agent_pii_columns").OrderBy("table_oid", "attnum").ToSql()
	if err != nil {
		return piistore.Snapshot{}, err
	}
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return piistore.Snapshot{}, err
	}
	s := piistore.Snapshot{Marks: mk}
	var (
		oid    uint32
		attnum int16
		f      piistore.FieldClass
	)
	err = forEachRow(rows, []any{&oid, &attnum, &f.Namespace, &f.ResourceName, &f.Field, &f.Class, &f.EntityType, &f.PhoneRegion}, func() error {
		f.Ref = agentcatalog.FieldRef(oid, attnum)
		f.Resource = resourceOf(f.Ref)
		s.Fields = append(s.Fields, f)
		return nil
	})
	if err != nil {
		return piistore.Snapshot{}, err
	}
	return s, nil
}

// readMarks reads pii_fingerprint() and the agent_pii_catalog row (none
// before the first basalt classify).
func readMarks(ctx context.Context, db Querier) (piistore.Marks, error) {
	var mk piistore.Marks
	q, args, err := psql.Select("basalt_meta.pii_fingerprint()").ToSql()
	if err != nil {
		return mk, err
	}
	if err := db.QueryRow(ctx, q, args...).Scan(&mk.Fingerprint); err != nil {
		return mk, err
	}
	q, args, err = psql.Select("fingerprint", "classified_at").From("basalt_meta.agent_pii_catalog").ToSql()
	if err != nil {
		return mk, err
	}
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return mk, err
	}
	var (
		fp []byte
		at time.Time
	)
	err = forEachRow(rows, []any{&fp, &at}, func() error {
		classified := at
		mk.CatalogPrint, mk.ClassifiedAt = bytes.Clone(fp), &classified
		return nil
	})
	return mk, err
}

// forEachRow scans each row of rows into scans and calls fn after each, then
// closes rows and returns their error.
func forEachRow(rows pgx.Rows, scans []any, fn func() error) error {
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(scans...); err != nil {
			return err
		}
		if err := fn(); err != nil {
			return err
		}
	}
	return rows.Err()
}
