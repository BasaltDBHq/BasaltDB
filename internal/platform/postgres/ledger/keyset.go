package ledger

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// applyIDKeyset adds a keyset predicate on id (UUID text).
func applyIDKeyset(b sq.SelectBuilder, column string, desc bool, cursor string) (sq.SelectBuilder, error) {
	if cursor == "" {
		return b, nil
	}
	id, err := pagination.DecodeIDCursor(cursor)
	if err != nil {
		return b, err
	}
	if desc {
		return b.Where(fmt.Sprintf("%s < ?", column), id.String()), nil
	}
	return b.Where(fmt.Sprintf("%s > ?", column), id.String()), nil
}

// applySeqKeyset adds a keyset predicate on monotonic seq (ASC).
func applySeqKeyset(b sq.SelectBuilder, column string, desc bool, cursor string) (sq.SelectBuilder, error) {
	if cursor == "" {
		return b, nil
	}
	seq, err := pagination.DecodeSeqCursor(cursor)
	if err != nil {
		return b, err
	}
	if desc {
		return b.Where(fmt.Sprintf("%s < ?", column), seq), nil
	}
	return b.Where(fmt.Sprintf("%s > ?", column), seq), nil
}
