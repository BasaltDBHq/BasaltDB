package guard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// The column labels of the connect page (CONTRACT.md, Connect, Column
// labels on the connect page): the classes CheckSetup shows for the
// columns of the tables an agent will get, and the classes the person set,
// written in the setup's transaction as basalt classify writes them.

// Label is a column's class as the connect page shows and sets it.
type Label struct {
	Class, EntityType, PhoneRegion string
}

// unlabeled is the class of a column with no row in pii_columns.
var unlabeled = Label{Class: ClassUnclassified}

// ColumnLabel is one column of a table and its class now.
type ColumnLabel struct {
	// Table is schema.table.
	Table, Column string
	Label
}

// LabelChange is a class the person set on a column, with the class it had
// when it was shown (Was).
type LabelChange struct {
	Table, Column string
	Label
	Was Label
}

// ErrClassesChanged is a change whose column's class stored now is not its
// Was, or whose column is gone: someone classified or changed the table
// since the person saw it. Nothing is written.
var ErrClassesChanged = errors.New("a column's class or the column itself changed since it was shown")

// tableColumn is a column of a listed table, with its type as
// pii_readable_columns() reports it.
type tableColumn struct {
	table, column, dataType string
}

// tableColumns reads the ordinary columns of tables (schema.table), by
// table in the order given and then column order.
func tableColumns(ctx context.Context, q Querier, tables []string) ([]tableColumn, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	const sql = `SELECT n.nspname::text || '.' || c.relname::text, a.attname::text, pg_catalog.format_type(a.atttypid, NULL)
		  FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS t(name, ord)
		  JOIN pg_catalog.pg_namespace n ON n.nspname::text = pg_catalog.split_part(t.name, '.', 1)
		  JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname::text = pg_catalog.split_part(t.name, '.', 2)
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
		 WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p')
		 ORDER BY t.ord, a.attnum`
	args := []any{tables}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("read the tables' columns: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (tableColumn, error) {
		var c tableColumn
		err := r.Scan(&c.table, &c.column, &c.dataType)
		return c, err
	})
}

// storedLabels reads, as the guard role, the rows of pii_columns for
// tables (FOR UPDATE when lock), by schema.table and column.
func storedLabels(ctx context.Context, tx pgx.Tx, tables []string, lock bool) (map[[2]string]PIIColumn, error) {
	b := psql.Select("table_schema", "table_name", "column_name", "data_type", "class",
		"coalesce(entity_type, '')", "coalesce(suggested_class, '')", "coalesce(suggested_entity_type, '')",
		"coalesce(reason, '')", "needs_review", "coalesce(phone_region, '')").
		From("basalt_meta.pii_columns").
		Where("(table_schema || '.' || table_name) = ANY(?::text[])", tables)
	if lock {
		b = b.Suffix("FOR UPDATE")
	}
	sql, args, err := b.ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("read the stored classes: %w", err)
	}
	out := map[[2]string]PIIColumn{}
	var c PIIColumn
	_, err = pgx.ForEachRow(rows, []any{
		&c.Schema, &c.Table, &c.Column, &c.DataType, &c.Class, &c.EntityType,
		&c.SuggestedClass, &c.SuggestedEntityType, &c.Reason, &c.NeedsReview, &c.PhoneRegion,
	}, func() error {
		out[[2]string{c.Schema + "." + c.Table, c.Column}] = c
		return nil
	})
	return out, err
}

func (c PIIColumn) label() Label {
	return Label{Class: c.Class, EntityType: c.EntityType, PhoneRegion: c.PhoneRegion}
}

// ReadLabels is every ordinary column of tables (schema.table), by table in
// the order given and then column order, with its class in pii_columns:
// UNCLASSIFIED for a column with no row, and for every column when the
// database has no guard yet. It reads in a transaction of its own, as the
// guard role, and changes nothing.
func ReadLabels(ctx context.Context, conn *pgx.Conn, n Names, tables []string) ([]ColumnLabel, error) {
	cols, err := tableColumns(ctx, conn, tables)
	if err != nil {
		return nil, err
	}
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT pg_catalog.to_regclass('basalt_meta.pii_columns') IS NOT NULL").Scan(&exists); err != nil {
		return nil, err
	}
	stored := map[[2]string]PIIColumn{}
	if exists {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		err = asGuard(ctx, tx, n, func() error {
			var err error
			stored, err = storedLabels(ctx, tx, tables, false)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]ColumnLabel, 0, len(cols))
	for _, c := range cols {
		l := unlabeled
		if s, ok := stored[[2]string{c.table, c.column}]; ok {
			l = s.label()
		}
		out = append(out, ColumnLabel{Table: c.table, Column: c.column, Label: l})
	}
	return out, nil
}

// WriteLabels writes the person's labels in tx, the setup's transaction,
// as the guard role, as basalt classify writes classes: for each change,
// the column must exist and its class stored now (UNCLASSIFIED with no
// row) must be its Was (ErrClassesChanged otherwise, nothing written); it
// is written with its data type from the catalog, confirmed now by the
// login role, its suggestion, reason and needs_review kept. With
// restPublic, every other column of tables with no class (no row, or
// UNCLASSIFIED) is written PUBLIC the same way. When anything was written,
// pii_catalog is set to pii_fingerprint(), so a running engine reloads its
// classes. It reports how many columns it wrote.
func WriteLabels(ctx context.Context, tx pgx.Tx, n Names, tables []string, changes []LabelChange, restPublic bool, at time.Time) (int, error) {
	if len(changes) == 0 && !restPublic {
		return 0, nil
	}
	cols, err := tableColumns(ctx, tx, tables)
	if err != nil {
		return 0, err
	}
	types := make(map[[2]string]string, len(cols))
	for _, c := range cols {
		types[[2]string{c.table, c.column}] = c.dataType
	}
	written := 0
	err = asGuard(ctx, tx, n, func() error {
		stored, err := storedLabels(ctx, tx, tables, true)
		if err != nil {
			return err
		}
		var out []PIIColumn
		changed := map[[2]string]bool{}
		for _, ch := range changes {
			key := [2]string{ch.Table, ch.Column}
			dataType, ok := types[key]
			if !ok {
				return ErrClassesChanged
			}
			now, prev := unlabeled, PIIColumn{}
			if s, ok := stored[key]; ok {
				now, prev = s.label(), s
			}
			if now != ch.Was {
				return ErrClassesChanged
			}
			out = append(out, labeled(ch.Table, ch.Column, dataType, ch.Label, prev))
			changed[key] = true
		}
		if restPublic {
			for _, c := range cols {
				key := [2]string{c.table, c.column}
				s, ok := stored[key]
				if changed[key] || (ok && s.Class != ClassUnclassified) {
					continue
				}
				out = append(out, labeled(c.table, c.column, c.dataType, Label{Class: ClassPublic}, s))
			}
		}
		if len(out) == 0 {
			return nil
		}
		for start := 0; start < len(out); start += piiUpsertBatch {
			if err := upsertPIIColumns(ctx, tx, out[start:min(start+piiUpsertBatch, len(out))], at); err != nil {
				return err
			}
		}
		catalog := psql.Insert("basalt_meta.pii_catalog").
			Columns("id", "fingerprint", "classified_at", "classified_by").
			Values(true, sq.Expr("basalt_meta.pii_fingerprint()"), at, sq.Expr("session_user")).
			Suffix(`ON CONFLICT (id) DO UPDATE SET fingerprint = EXCLUDED.fingerprint,
				classified_at = EXCLUDED.classified_at, classified_by = EXCLUDED.classified_by`)
		if err := execBuilt(ctx, tx, catalog); err != nil {
			return fmt.Errorf("set the classification catalog: %w", err)
		}
		written = len(out)
		return nil
	})
	return written, err
}

// labeled is the pii_columns row for table.column with label l, keeping
// prev's suggestion, reason and needs_review.
func labeled(table, column, dataType string, l Label, prev PIIColumn) PIIColumn {
	schema, rel, _ := strings.Cut(table, ".")
	return PIIColumn{
		Schema: schema, Table: rel, Column: column, DataType: dataType,
		Class: l.Class, EntityType: l.EntityType, PhoneRegion: l.PhoneRegion,
		SuggestedClass: prev.SuggestedClass, SuggestedEntityType: prev.SuggestedEntityType,
		Reason: prev.Reason, NeedsReview: prev.NeedsReview,
	}
}

// LabelClasses are the classes the connect page sets.
var LabelClasses = []string{ClassPublic, ClassIdentifier, ClassSecret}

// EntityTypes are the entity types of an IDENTIFIER column.
var EntityTypes = []string{EntityEmail, EntityPhone, EntityPersonName, EntityAddress, EntityOther}

// ValidLabel reports whether l is a class the connect page may set:
// PUBLIC, IDENTIFIER with an entity type, or SECRET; a phone region, upper
// case ISO 3166-1 alpha-2, with PHONE only and required there.
func ValidLabel(l Label) bool {
	return slices.Contains(LabelClasses, l.Class) && validEntity(l, true)
}

// ValidWas reports whether l is a class a column can have now: any of the
// five, with the same entity type rule, and a region with PHONE only, when
// one is stored.
func ValidWas(l Label) bool {
	return slices.Contains([]string{ClassPublic, ClassIdentifier, ClassFreeText, ClassSecret, ClassUnclassified}, l.Class) && validEntity(l, false)
}

func validEntity(l Label, regionRequired bool) bool {
	if l.Class != ClassIdentifier {
		return l.EntityType == "" && l.PhoneRegion == ""
	}
	if !slices.Contains(EntityTypes, l.EntityType) {
		return false
	}
	if l.EntityType != EntityPhone {
		return l.PhoneRegion == ""
	}
	if l.PhoneRegion == "" && !regionRequired {
		return true
	}
	return len(l.PhoneRegion) == 2 && l.PhoneRegion[0] >= 'A' && l.PhoneRegion[0] <= 'Z' && l.PhoneRegion[1] >= 'A' && l.PhoneRegion[1] <= 'Z'
}
