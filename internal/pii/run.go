package pii

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Result is one column's suggestion.
type Result struct {
	Column     Column
	Suggestion Suggestion
}

// SampleFunc reads one column's sample (the store adapter's sampler
// outside tests).
type SampleFunc func(ctx context.Context, col Column) (Sample, error)

// SuggestAll samples and scores every column. Phone-like columns are scored
// last, so the +cc prefixes of the whole database weight their region. A
// column's values are dropped as soon as it is scored.
func SuggestAll(ctx context.Context, cols []Column, sample SampleFunc, opts Options) ([]Result, error) {
	db := map[int32]int{}
	opts.CallingCodes = db
	out := make([]Result, len(cols))
	var phones []int
	phoneValues := map[int][]string{}
	for i, col := range cols {
		out[i].Column = col
		if !Sampled(col.Kind) {
			out[i].Suggestion = Suggest(col, Sample{}, opts)
			continue
		}
		s, err := sample(ctx, col)
		if err != nil {
			return nil, err
		}
		CallingCodes(s.Values, db)
		if phoneLike(col, s.Values) {
			phoneValues[i] = s.Values
			phones = append(phones, i)
			continue
		}
		out[i].Suggestion = Suggest(col, s, opts)
	}
	for _, i := range phones {
		out[i].Suggestion = Suggest(out[i].Column, Sample{Values: phoneValues[i]}, opts)
		delete(phoneValues, i)
	}
	return out, nil
}

// phoneLike is a column whose region inference may run: named as a phone,
// or holding mostly phone-shaped values, bare runs of digits included.
func phoneLike(col Column, values []string) bool {
	if hit, ok := matchName(col.Name, col.Kind); ok && hit.entity == guardmodel.EntityPhone {
		return true
	}
	c := 0
	for _, v := range values {
		if _, ok := shapePhone(v, true); ok {
			c++
		}
	}
	return len(values) > 0 && c*percent >= sampleShare*len(values)
}
