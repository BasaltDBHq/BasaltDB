package guard

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The labels of the Update check's LABELS fix (CONTRACT.md, Setup page, The
// Update check): the columns one agent role may read that have no class,
// read and written with the admin connection, as the guard role.

// agentReadableSQL is pii_readable_columns() with the privileges of one
// agent role, as pii_unclassified() filters them for its login role, and in
// its order. Plain SQL: it calls a set-returning function of the guard with
// privilege checks on a named role, which squirrel cannot express.
const agentReadableSQL = `SELECT r.table_schema, r.table_name, r.column_name, r.data_type
  FROM basalt_meta.pii_readable_columns() r
 WHERE coalesce(pg_catalog.has_schema_privilege($1::text, r.table_schema, 'USAGE'), false)
   AND coalesce(pg_catalog.has_column_privilege($1::text, r.table_oid, r.attnum, 'SELECT'), false)
 ORDER BY r.table_schema COLLATE "C", r.table_name COLLATE "C", r.column_name COLLATE "C"`

// agentColumns reads the columns role may read with their class (no row is
// UNCLASSIFIED), and every stored row. The caller acts as the guard role.
func agentColumns(ctx context.Context, tx pgx.Tx, role string) ([]guardmodel.AgentColumn, map[guardmodel.ColumnKey]guardmodel.PIIColumn, error) {
	rows, err := tx.Query(ctx, agentReadableSQL, role)
	if err != nil {
		return nil, nil, fmt.Errorf("read the agent's readable columns: %w", err)
	}
	readable, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.ReadableColumn, error) {
		var c guardmodel.ReadableColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		return c, err
	})
	if err != nil {
		return nil, nil, err
	}
	stored := map[guardmodel.ColumnKey]guardmodel.PIIColumn{}
	if err := readStored(ctx, tx, stored); err != nil {
		return nil, nil, err
	}
	out := make([]guardmodel.AgentColumn, len(readable))
	for i, c := range readable {
		out[i] = guardmodel.AgentColumn{ReadableColumn: c, Label: unlabeled}
		if s, ok := stored[guardmodel.ColumnKey{Schema: c.Schema, Table: c.Table, Column: c.Column}]; ok {
			out[i].Label = labelOf(s)
		}
	}
	return out, stored, nil
}

// AgentUnlabeled is every column role may read whose class is UNCLASSIFIED
// (no row, or a row of that class), in pii_unclassified()'s order. It reads
// in tx as the guard role and changes nothing.
func AgentUnlabeled(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error) {
	var out []guardmodel.AgentColumn
	err := asGuard(ctx, tx, n, func() error {
		cols, _, err := agentColumns(ctx, tx, role)
		if err != nil {
			return err
		}
		for _, c := range cols {
			if c.Class == guardmodel.ClassUnclassified {
				out = append(out, c)
			}
		}
		return nil
	})
	return out, err
}

// WriteAgentLabels writes the person's labels for role's unlabeled columns
// in tx, as WriteLabels does for an install: each change must name a column
// role may read whose class is UNCLASSIFIED (ErrLabelNotListed otherwise;
// ErrClassesChanged for a column that is gone or whose class stored now is
// not its Was). With restPublic, every other column role may read that has
// no class is written PUBLIC. When anything was written, the rows of columns
// that no longer exist are deleted and pii_catalog is set, so a running
// engine reloads its classes. It reports how many columns it wrote.
func WriteAgentLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error) {
	if len(changes) == 0 && !restPublic {
		return 0, nil
	}
	written := 0
	err := asGuard(ctx, tx, n, func() error {
		if _, err := tx.Exec(ctx, "LOCK TABLE basalt_meta.pii_columns IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return fmt.Errorf("lock the stored classes: %w", err)
		}
		cols, stored, err := agentColumns(ctx, tx, role)
		if err != nil {
			return err
		}
		prev := func(c guardmodel.AgentColumn) guardmodel.PIIColumn {
			return stored[guardmodel.ColumnKey{Schema: c.Schema, Table: c.Table, Column: c.Column}]
		}
		byKey := make(map[[2]string]guardmodel.AgentColumn, len(cols))
		for _, c := range cols {
			byKey[[2]string{c.TableName(), c.Column}] = c
		}
		var out []guardmodel.PIIColumn
		changed := map[[2]string]bool{}
		for _, ch := range changes {
			key := [2]string{ch.Table, ch.Column}
			c, ok := byKey[key]
			if !ok {
				gone, err := columnGone(ctx, tx, ch.Table, ch.Column)
				if err != nil {
					return err
				}
				if gone {
					return guardmodel.ErrClassesChanged
				}
				return guardmodel.ErrLabelNotListed
			}
			if c.Label != ch.Was {
				return guardmodel.ErrClassesChanged
			}
			out = append(out, labeled(ch.Table, ch.Column, c.DataType, ch.Label, prev(c)))
			changed[key] = true
		}
		if restPublic {
			for _, c := range cols {
				key := [2]string{c.TableName(), c.Column}
				if changed[key] || c.Class != guardmodel.ClassUnclassified {
					continue
				}
				out = append(out, labeled(key[0], c.Column, c.DataType, guardmodel.Label{Class: guardmodel.ClassPublic}, prev(c)))
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
		if err := deleteStaleClasses(ctx, tx); err != nil {
			return err
		}
		if err := setPIICatalog(ctx, tx, at); err != nil {
			return err
		}
		written = len(out)
		return nil
	})
	return written, err
}

// columnGone: no relation of a readable kind holds table.column now.
func columnGone(ctx context.Context, tx pgx.Tx, table, column string) (bool, error) {
	// Plain SQL: a catalog lookup by names, as tableColumns reads them.
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1
		  FROM pg_catalog.pg_namespace n
		  JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
		 WHERE n.nspname::text = pg_catalog.split_part($1, '.', 1) AND c.relname::text = pg_catalog.split_part($1, '.', 2)
		   AND a.attname::text = $2 AND a.attnum > 0 AND NOT a.attisdropped
		   AND c.relkind IN ('r', 'p', 'v', 'm', 'f'))`, table, column).Scan(&exists)
	return !exists, err
}

// deleteStaleClasses deletes the rows of columns that no longer exist: a
// confirmed class survives a revoked grant (owner decision OR-1). The
// caller acts as the guard role.
func deleteStaleClasses(ctx context.Context, tx pgx.Tx) error {
	// The NOT EXISTS is a raw predicate: squirrel has no anti-join over the
	// catalog, and the whole subquery is constant text. A column exists when
	// a relation of a readable kind holds it by these names, whoever may
	// read it.
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
	return nil
}

// setPIICatalog sets pii_catalog to pii_fingerprint(), at and the login
// role, so a running engine reloads its classes. The caller acts as the
// guard role.
func setPIICatalog(ctx context.Context, tx pgx.Tx, at time.Time) error {
	catalog := psql.Insert("basalt_meta.pii_catalog").
		Columns("id", "fingerprint", "classified_at", "classified_by").
		Values(true, sq.Expr("basalt_meta.pii_fingerprint()"), at, sq.Expr("session_user")).
		Suffix(`ON CONFLICT (id) DO UPDATE SET fingerprint = EXCLUDED.fingerprint,
			classified_at = EXCLUDED.classified_at, classified_by = EXCLUDED.classified_by`)
	if err := execBuilt(ctx, tx, catalog); err != nil {
		return fmt.Errorf("set the classification catalog: %w", err)
	}
	return nil
}
