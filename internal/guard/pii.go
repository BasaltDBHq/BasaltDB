package guard

import (
	"context"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// PII classes (CONTRACT.md, PII classification).
const (
	ClassPublic       = "PUBLIC"
	ClassIdentifier   = "IDENTIFIER"
	ClassFreeText     = "FREE_TEXT"
	ClassSecret       = "SECRET"
	ClassUnclassified = "UNCLASSIFIED"
)

// Entity types of an IDENTIFIER column.
const (
	EntityEmail      = "EMAIL"
	EntityPhone      = "PHONE"
	EntityPersonName = "PERSON_NAME"
	EntityAddress    = "ADDRESS"
	EntityOther      = "OTHER"
)

// piiUpsertBatch is the number of columns per INSERT: at most 13 parameters each,
// well under Postgres' 65535 bind parameters.
const piiUpsertBatch = 1000

// PIIColumn is one row of basalt_meta.pii_columns that basalt classify
// writes. Empty strings are stored as NULL. A column of any class but
// UNCLASSIFIED is stamped confirmed by the login role at Classification.At.
type PIIColumn struct {
	Schema, Table, Column string
	// DataType is format_type without the modifier, as
	// pii_readable_columns() reports it.
	DataType            string
	Class               string
	EntityType          string
	SuggestedClass      string
	SuggestedEntityType string
	// Reason holds names and counts only, never a value.
	Reason      string
	NeedsReview bool
	PhoneRegion string
}

// Classification is one write of basalt classify.
type Classification struct {
	// Columns are upserted; columns not listed keep their row.
	Columns []PIIColumn
	// At stamps confirmed_at and classified_at.
	At time.Time
}

// WriteClassification writes c in tx as the guard role, the owner of
// basalt_meta (SET LOCAL ROLE, as the migrations do): upserts c.Columns,
// deletes the rows of columns that no longer exist (a confirmed class
// survives a revoked grant: owner decision OR-1), and sets pii_catalog to
// pii_fingerprint(). The login role (session_user) must have been granted
// the guard role, which basalt init does. The caller commits.
func WriteClassification(ctx context.Context, tx pgx.Tx, n Names, c Classification) error {
	return asGuard(ctx, tx, n, func() error {
		for start := 0; start < len(c.Columns); start += piiUpsertBatch {
			end := min(start+piiUpsertBatch, len(c.Columns))
			if err := upsertPIIColumns(ctx, tx, c.Columns[start:end], c.At); err != nil {
				return err
			}
		}
		// The NOT EXISTS is a raw predicate: squirrel has no anti-join over
		// the catalog, and the whole subquery is constant text. A column
		// exists when a relation of a readable kind holds it by these
		// names, whoever may read it.
		stale := psql.Delete("basalt_meta.pii_columns p").Where(`NOT EXISTS (SELECT 1
			FROM pg_catalog.pg_namespace ns
			JOIN pg_catalog.pg_class c ON c.relnamespace = ns.oid
			JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
			WHERE ns.nspname::text = p.table_schema AND c.relname::text = p.table_name
			  AND a.attname::text = p.column_name AND a.attnum > 0 AND NOT a.attisdropped
			  AND c.relkind IN ('r', 'p', 'v', 'm', 'f'))`)
		if err := execBuilt(ctx, tx, stale); err != nil {
			return fmt.Errorf("delete stale classes: %w", err)
		}
		catalog := psql.Insert("basalt_meta.pii_catalog").
			Columns("id", "fingerprint", "classified_at", "classified_by").
			Values(true, sq.Expr("basalt_meta.pii_fingerprint()"), c.At, sq.Expr("session_user")).
			Suffix(`ON CONFLICT (id) DO UPDATE SET fingerprint = EXCLUDED.fingerprint,
				classified_at = EXCLUDED.classified_at, classified_by = EXCLUDED.classified_by`)
		if err := execBuilt(ctx, tx, catalog); err != nil {
			return fmt.Errorf("set the classification catalog: %w", err)
		}
		return nil
	})
}

// asGuard runs fn in tx as the guard role with search_path pg_catalog, then
// puts the caller's role and search_path back, transaction-local as they
// were (SET LOCAL ones included).
func asGuard(ctx context.Context, tx pgx.Tx, n Names, fn func() error) error {
	if err := n.Validate(); err != nil {
		return err
	}
	var role, searchPath string
	saved := psql.Select().Column("current_setting('role')").Column("current_setting('search_path')")
	if err := queryBuilt(ctx, tx, saved).Scan(&role, &searchPath); err != nil {
		return err
	}
	// Plain SQL: role and setting changes on a validated role name.
	if _, err := tx.Exec(ctx, n.render(`SET LOCAL ROLE {{guard}}; SET LOCAL search_path = pg_catalog`)); err != nil {
		return fmt.Errorf("act as the guard role: %w", err)
	}
	if err := fn(); err != nil {
		return err
	}
	// The search_path first: setting role 'none' as the guard role is allowed.
	restore := psql.Select().
		Column(sq.Expr("set_config('search_path', ?, true)", searchPath)).
		Column(sq.Expr("set_config('role', ?, true)", role))
	return execBuilt(ctx, tx, restore)
}

// ReadableColumn is one row of pii_readable_columns().
type ReadableColumn struct {
	TableOID              uint32
	Attnum                int16
	Schema, Table, Column string
	DataType              string
}

// ColumnKey names a column: schema, table and column.
type ColumnKey struct{ Schema, Table, Column string }

// ClassificationState is what basalt classify reads before it suggests:
// the readable columns, the stored classes and both fingerprints.
type ClassificationState struct {
	// Readable is pii_readable_columns(), by schema, table and attnum.
	Readable []ReadableColumn
	// Stored are the rows of pii_columns.
	Stored map[ColumnKey]PIIColumn
	// Fingerprint is pii_fingerprint() now.
	Fingerprint []byte
	// Previous is pii_catalog.fingerprint, nil before the first classify.
	Previous []byte
}

// ReadClassification reads the classification state in tx as the guard
// role (the admin may not read basalt_meta's tables or run its functions
// itself), as WriteClassification writes it.
func ReadClassification(ctx context.Context, tx pgx.Tx, n Names) (ClassificationState, error) {
	st := ClassificationState{Stored: map[ColumnKey]PIIColumn{}}
	err := asGuard(ctx, tx, n, func() error {
		var err error
		if st.Readable, err = readableColumns(ctx, tx); err != nil {
			return err
		}
		if err := readStored(ctx, tx, st.Stored); err != nil {
			return err
		}
		if err := queryBuilt(ctx, tx, psql.Select("basalt_meta.pii_fingerprint()")).Scan(&st.Fingerprint); err != nil {
			return fmt.Errorf("read the fingerprint: %w", err)
		}
		err = queryBuilt(ctx, tx, psql.Select("fingerprint").From("basalt_meta.pii_catalog")).Scan(&st.Previous)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return st, err
}

func readableColumns(ctx context.Context, tx pgx.Tx) ([]ReadableColumn, error) {
	sql, args, err := psql.Select("table_oid", "attnum", "table_schema", "table_name", "column_name", "data_type").
		From("basalt_meta.pii_readable_columns()").
		OrderBy(`table_schema COLLATE "C"`, `table_name COLLATE "C"`, "attnum").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("read the readable columns: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReadableColumn, error) {
		var c ReadableColumn
		err := r.Scan(&c.TableOID, &c.Attnum, &c.Schema, &c.Table, &c.Column, &c.DataType)
		return c, err
	})
}

func readStored(ctx context.Context, tx pgx.Tx, into map[ColumnKey]PIIColumn) error {
	sql, args, err := psql.Select("table_schema", "table_name", "column_name", "data_type", "class",
		"coalesce(entity_type, '')", "coalesce(suggested_class, '')", "coalesce(suggested_entity_type, '')",
		"coalesce(reason, '')", "needs_review", "coalesce(phone_region, '')").
		From("basalt_meta.pii_columns").ToSql()
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("read the stored classes: %w", err)
	}
	var c PIIColumn
	_, err = pgx.ForEachRow(rows, []any{&c.Schema, &c.Table, &c.Column, &c.DataType, &c.Class, &c.EntityType,
		&c.SuggestedClass, &c.SuggestedEntityType, &c.Reason, &c.NeedsReview, &c.PhoneRegion}, func() error {
		into[ColumnKey{c.Schema, c.Table, c.Column}] = c
		return nil
	})
	return err
}

func upsertPIIColumns(ctx context.Context, tx pgx.Tx, cols []PIIColumn, at time.Time) error {
	ins := psql.Insert("basalt_meta.pii_columns").Columns(
		"table_schema", "table_name", "column_name", "data_type", "class", "entity_type",
		"suggested_class", "suggested_entity_type", "reason", "needs_review", "phone_region",
		"confirmed_at", "confirmed_by").
		Suffix(`ON CONFLICT (table_schema, table_name, column_name) DO UPDATE SET
			data_type = EXCLUDED.data_type, class = EXCLUDED.class, entity_type = EXCLUDED.entity_type,
			suggested_class = EXCLUDED.suggested_class, suggested_entity_type = EXCLUDED.suggested_entity_type,
			reason = EXCLUDED.reason, needs_review = EXCLUDED.needs_review, phone_region = EXCLUDED.phone_region,
			confirmed_at = EXCLUDED.confirmed_at, confirmed_by = EXCLUDED.confirmed_by`)
	for _, col := range cols {
		var confirmedAt, confirmedBy any // NULL for UNCLASSIFIED
		if col.Class != ClassUnclassified {
			confirmedAt, confirmedBy = at, sq.Expr("session_user")
		}
		ins = ins.Values(col.Schema, col.Table, col.Column, col.DataType, col.Class, nullString(col.EntityType),
			nullString(col.SuggestedClass), nullString(col.SuggestedEntityType), nullString(col.Reason),
			col.NeedsReview, nullString(col.PhoneRegion), confirmedAt, confirmedBy)
	}
	if err := execBuilt(ctx, tx, ins); err != nil {
		return fmt.Errorf("write classes: %w", err)
	}
	return nil
}

func execBuilt(ctx context.Context, q Querier, b sq.Sqlizer) error {
	sql, args, err := b.ToSql()
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, sql, args...)
	return err
}

func queryBuilt(ctx context.Context, q Querier, b sq.Sqlizer) pgx.Row {
	sql, args, err := b.ToSql()
	if err != nil {
		return errRow{err}
	}
	return q.QueryRow(ctx, sql, args...)
}

// errRow is a pgx.Row that fails Scan with err.
type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

// Why a column needs a person (pii_unclassified().why).
const (
	UnclassifiedNew         = "NEW"
	UnclassifiedClass       = "UNCLASSIFIED"
	UnclassifiedTypeChanged = "TYPE_CHANGED"
)

// UnclassifiedColumn is one row of pii_unclassified(): a column the login
// role can read that needs a person.
type UnclassifiedColumn struct {
	Schema, Table, Column, DataType string
	// Why is UnclassifiedNew, UnclassifiedClass or UnclassifiedTypeChanged.
	Why string
}

// Name is schema.table.column.
func (c UnclassifiedColumn) Name() string { return c.Schema + "." + c.Table + "." + c.Column }

// Unclassified reports whether the column has no class yet (NEW or
// UNCLASSIFIED); a TYPE_CHANGED column keeps its class and needs a review.
func (c UnclassifiedColumn) Unclassified() bool {
	return c.Why == UnclassifiedNew || c.Why == UnclassifiedClass
}

// PIIUnclassified calls pii_unclassified() as the login role (version 15).
func PIIUnclassified(ctx context.Context, q Querier) ([]UnclassifiedColumn, error) {
	sql, args, err := psql.Select("table_schema", "table_name", "column_name", "data_type", "why").
		From("basalt_meta.pii_unclassified()").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (UnclassifiedColumn, error) {
		var c UnclassifiedColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType, &c.Why)
		return c, err
	})
}

// PIIClassCounts reads the login role's rows of agent_pii_columns: how
// many are classified (any class but UNCLASSIFIED), and the names of those
// a classify run flagged for review (needs_review), in name order.
func PIIClassCounts(ctx context.Context, q Querier) (classified int, review []string, err error) {
	sql, args, err := psql.Select("table_schema || '.' || table_name || '.' || column_name", "class", "needs_review").
		From("basalt_meta.agent_pii_columns").
		OrderBy(`table_schema COLLATE "C"`, `table_name COLLATE "C"`, `column_name COLLATE "C"`).ToSql()
	if err != nil {
		return 0, nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return 0, nil, err
	}
	var (
		name, class string
		needsReview bool
	)
	_, err = pgx.ForEachRow(rows, []any{&name, &class, &needsReview}, func() error {
		if class != ClassUnclassified {
			classified++
		}
		if needsReview {
			review = append(review, name)
		}
		return nil
	})
	return classified, review, err
}

// nullString maps "" to SQL NULL.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
