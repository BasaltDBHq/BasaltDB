package pgpii

import (
	"context"
	"errors"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// refsSQL finds the table oid and attribute number of each listed column by
// its schema, table and column name. Every role may read the catalog.
const refsSQL = `SELECT l.ord::int4, a.attrelid, a.attnum
  FROM ROWS FROM (pg_catalog.unnest($1::text[]), pg_catalog.unnest($2::text[]), pg_catalog.unnest($3::text[]))
       WITH ORDINALITY AS l(nsp, rel, att, ord)
  JOIN pg_catalog.pg_namespace n ON n.nspname::text = l.nsp
  JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname::text = l.rel
  JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attname::text = l.att
 WHERE a.attnum > 0 AND NOT a.attisdropped`

// Columns fills each listed column (by namespace, resource, name and data
// type) with its Kind, Key and Generated from q's catalog. A domain's kind
// is the kind of the type it is built on. It always returns len(listed)
// columns with a Kind: a failed catalog read only leaves Key, Generated and
// the domain's base type unread, and is returned as the error.
func Columns(ctx context.Context, q sqlport.Port, listed []piistore.Column) ([]piistore.Column, error) {
	out := make([]piistore.Column, len(listed))
	copy(out, listed)
	refs, refErr := columnRefs(ctx, q, listed)
	var keys map[KeyRef]KeyKind
	var bases map[KeyRef]string
	var keyErr, baseErr error
	if refErr == nil {
		keys, keyErr = KeyColumns(ctx, q)
		bases, baseErr = BaseTypes(ctx, q)
	}
	for i := range out {
		typ := out[i].DataType
		if ref, ok := refs[i]; ok {
			out[i].Key, out[i].Generated = keys[ref].Key, keys[ref].Generated
			if base := bases[ref]; base != "" {
				typ = base
			}
		}
		out[i].Kind = KindOf(typ)
	}
	return out, errors.Join(refErr, keyErr, baseErr)
}

// columnRefs maps the index of each listed column found in the catalog to
// its table oid and attribute number.
func columnRefs(ctx context.Context, q sqlport.Port, listed []piistore.Column) (map[int]KeyRef, error) {
	nsp := make([]string, len(listed))
	rel := make([]string, len(listed))
	att := make([]string, len(listed))
	for i, c := range listed {
		nsp[i], rel[i], att[i] = c.Namespace, c.Resource, c.Name
	}
	rows, err := q.Query(ctx, refsSQL, nsp, rel, att)
	if err != nil {
		return nil, fmt.Errorf("read column refs: %w", err)
	}
	out := map[int]KeyRef{}
	var (
		ord int32
		ref KeyRef
	)
	err = forEachSampleRow(rows, []any{&ord, &ref.TableOID, &ref.Attnum}, func() error {
		out[int(ord)-1] = ref
		return nil
	})
	return out, err
}
