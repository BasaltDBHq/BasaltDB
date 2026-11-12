package guard

import (
	"context"
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
// deletes the rows of columns that no longer exist or no agent can read,
// and sets pii_catalog to pii_fingerprint(). The login role (session_user)
// must have been granted the guard role, which basalt init does. The
// caller commits.
func WriteClassification(ctx context.Context, tx pgx.Tx, n Names, c Classification) error {
	if err := n.Validate(); err != nil {
		return err
	}
	// Keep the caller's role and search_path (SET LOCAL ones included) to
	// put back after the write.
	var role, searchPath string
	saved := psql.Select().Column("current_setting('role')").Column("current_setting('search_path')")
	if err := queryBuilt(ctx, tx, saved).Scan(&role, &searchPath); err != nil {
		return err
	}
	// Plain SQL: role and setting changes on a validated role name.
	if _, err := tx.Exec(ctx, n.render(`SET LOCAL ROLE {{guard}}; SET LOCAL search_path = pg_catalog`)); err != nil {
		return fmt.Errorf("classify as the guard role: %w", err)
	}
	for start := 0; start < len(c.Columns); start += piiUpsertBatch {
		end := min(start+piiUpsertBatch, len(c.Columns))
		if err := upsertPIIColumns(ctx, tx, c.Columns[start:end], c.At); err != nil {
			return err
		}
	}
	// The NOT EXISTS is a raw predicate: squirrel has no anti-join over a
	// set-returning function, and the whole subquery is constant text.
	stale := psql.Delete("basalt_meta.pii_columns p").Where(`NOT EXISTS (SELECT 1
		FROM basalt_meta.pii_readable_columns() r
		WHERE r.table_schema = p.table_schema AND r.table_name = p.table_name AND r.column_name = p.column_name)`)
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
	// Back to the caller's settings, transaction-local as they were. The
	// search_path first: setting role 'none' as the guard role is allowed.
	restore := psql.Select().
		Column(sq.Expr("set_config('search_path', ?, true)", searchPath)).
		Column(sq.Expr("set_config('role', ?, true)", role))
	return execBuilt(ctx, tx, restore)
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
