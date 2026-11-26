package setup

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// ColumnSuggestion is the classifier's suggestion for one column.
type ColumnSuggestion struct {
	Column                                 piistore.Column
	Class, EntityType, PhoneRegion, Reason string
}

// SampleFunc reads one column's sample.
type SampleFunc func(ctx context.Context, col piistore.Column) (piistore.Sample, error)
