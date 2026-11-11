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
	// Plain SQL: back to the login role for the rest of the transaction.
	_, err := tx.Exec(ctx, `RESET search_path; RESET ROLE`)
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

// nullString maps "" to SQL NULL.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
