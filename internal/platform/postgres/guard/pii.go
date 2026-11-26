package guard

import (
	"context"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// piiUpsertBatch is the number of columns per INSERT: at most 13 parameters each,
// well under Postgres' 65535 bind parameters.
const piiUpsertBatch = 1000

// WriteClassification writes c in tx as the guard role, the owner of
// basalt_meta (SET LOCAL ROLE, as the migrations do): upserts c.Columns,
// deletes the rows of columns that no longer exist (a confirmed class
// survives a revoked grant: owner decision OR-1), and sets pii_catalog to
// pii_fingerprint(). The login role (session_user) must have been granted
// the guard role, which basalt init does. The caller commits.
func WriteClassification(ctx context.Context, tx pgx.Tx, n guardmodel.Names, c guardmodel.Classification) error {
	return asGuard(ctx, tx, n, func() error {
		for start := 0; start < len(c.Columns); start += piiUpsertBatch {
			end := min(start+piiUpsertBatch, len(c.Columns))
			if err := upsertPIIColumns(ctx, tx, c.Columns[start:end], c.At); err != nil {
				return err
			}
		}
		if err := deleteStaleClasses(ctx, tx); err != nil {
			return err
		}
		return setPIICatalog(ctx, tx, c.At)
	})
}

// asGuard runs fn in tx as the guard role with search_path pg_catalog,
// pg_temp (pg_temp last, so no temporary table shadows the catalog), then
// puts the caller's role and search_path back, transaction-local as they
// were (SET LOCAL ones included).
func asGuard(ctx context.Context, tx pgx.Tx, n guardmodel.Names, fn func() error) error {
	if err := n.Validate(); err != nil {
		return err
	}
	var role, searchPath string
	saved := psql.Select().Column("current_setting('role')").Column("current_setting('search_path')")
	if err := queryBuilt(ctx, tx, saved).Scan(&role, &searchPath); err != nil {
		return err
	}
	// Plain SQL: role and setting changes on a validated role name.
	if _, err := tx.Exec(ctx, renderSQL(n, `SET LOCAL ROLE {{guard}}; SET LOCAL search_path = pg_catalog, pg_temp`)); err != nil {
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

// ReadClassification reads the classification state in tx as the guard
// role (the admin may not read basalt_meta's tables or run its functions
// itself), as WriteClassification writes it.
func ReadClassification(ctx context.Context, tx pgx.Tx, n guardmodel.Names) (guardmodel.ClassificationState, error) {
	st := guardmodel.ClassificationState{Stored: map[guardmodel.ColumnKey]guardmodel.PIIColumn{}}
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

func readableColumns(ctx context.Context, tx pgx.Tx) ([]guardmodel.ReadableColumn, error) {
	sql, args, err := psql.Select("table_schema", "table_name", "column_name", "data_type").
		From("basalt_meta.pii_readable_columns()").
		OrderBy(`table_schema COLLATE "C"`, `table_name COLLATE "C"`, "attnum").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("read the readable columns: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.ReadableColumn, error) {
		var c guardmodel.ReadableColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		return c, err
	})
}

func readStored(ctx context.Context, tx pgx.Tx, into map[guardmodel.ColumnKey]guardmodel.PIIColumn) error {
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
	var c guardmodel.PIIColumn
	_, err = pgx.ForEachRow(rows, []any{
		&c.Schema, &c.Table, &c.Column, &c.DataType, &c.Class, &c.EntityType,
		&c.SuggestedClass, &c.SuggestedEntityType, &c.Reason, &c.NeedsReview, &c.PhoneRegion,
	}, func() error {
		into[guardmodel.ColumnKey{Schema: c.Schema, Table: c.Table, Column: c.Column}] = c
		return nil
	})
	return err
}

func upsertPIIColumns(ctx context.Context, tx pgx.Tx, cols []guardmodel.PIIColumn, at time.Time) error {
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
		if col.Class != guardmodel.ClassUnclassified {
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

// PIIUnclassified calls pii_unclassified() as the login role (version 15).
func PIIUnclassified(ctx context.Context, q Querier) ([]guardmodel.UnclassifiedColumn, error) {
	sql, args, err := psql.Select("table_schema", "table_name", "column_name", "data_type", "why").
		From("basalt_meta.pii_unclassified()").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.UnclassifiedColumn, error) {
		var c guardmodel.UnclassifiedColumn
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
		if class != guardmodel.ClassUnclassified {
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
