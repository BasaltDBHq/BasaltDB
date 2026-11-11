package pagination

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
)

// ApplyStringKeyset adds a keyset predicate on a string column (ASC lists use > cursor).
func ApplyStringKeyset(b sq.SelectBuilder, column string, desc bool, cursor string) (sq.SelectBuilder, error) {
	if cursor == "" {
		return b, nil
	}
	val, err := DecodeNameCursor(cursor)
	if err != nil {
		// id cursors also use Name field in legacy mix — try id decode for link id sorts
		id, idErr := DecodeIDCursor(cursor)
		if idErr != nil {
			return b, err
		}
		val = id
	}
	if desc {
		return b.Where(fmt.Sprintf("%s < ?", column), val), nil
	}
	return b.Where(fmt.Sprintf("%s > ?", column), val), nil
}

// ApplyIDKeyset adds a keyset predicate on id (UUID text).
func ApplyIDKeyset(b sq.SelectBuilder, column string, desc bool, cursor string) (sq.SelectBuilder, error) {
	if cursor == "" {
		return b, nil
	}
	id, err := DecodeIDCursor(cursor)
	if err != nil {
		return b, err
	}
	if desc {
		return b.Where(fmt.Sprintf("%s < ?", column), id), nil
	}
	return b.Where(fmt.Sprintf("%s > ?", column), id), nil
}

// ApplySeqKeyset adds a keyset predicate on monotonic seq (ASC).
func ApplySeqKeyset(b sq.SelectBuilder, column string, desc bool, cursor string) (sq.SelectBuilder, error) {
	if cursor == "" {
		return b, nil
	}
	seq, err := DecodeSeqCursor(cursor)
	if err != nil {
		return b, err
	}
	if desc {
		return b.Where(fmt.Sprintf("%s < ?", column), seq), nil
	}
	return b.Where(fmt.Sprintf("%s > ?", column), seq), nil
}
