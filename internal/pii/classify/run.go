package classify

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// Result is one column's suggestion. It may hold the column's sampled
// values, in memory only, for Check; nothing prints them.
type Result struct {
	Column     Column
	Suggestion Suggestion
	values     []string
}

// SampleFunc reads one column's sample (Sampler.Sample outside tests).
type SampleFunc func(ctx context.Context, col Column) (Sample, error)

// SuggestAll samples and scores every column. Phone-like columns are scored
// last, so the +cc prefixes of the whole database weight their region. keep
// says which columns keep their values for Check; the others' values are
// dropped as soon as the column is scored.
func SuggestAll(ctx context.Context, cols []Column, sample SampleFunc, opts Options, keep func(Column, Suggestion) bool) ([]Result, error) {
	db := map[int32]int{}
	opts.CallingCodes = db
	out := make([]Result, len(cols))
	var phones []int
	for i, col := range cols {
		out[i].Column = col
		if !Sampled(col.SampleType()) {
			out[i].Suggestion = Suggest(col, Sample{}, opts)
			continue
		}
		s, err := sample(ctx, col)
		if err != nil {
			return nil, err
		}
		CallingCodes(s.Values, db)
		if phoneLike(col, s.Values) {
			out[i].values = s.Values
			phones = append(phones, i)
			continue
		}
		out[i].Suggestion = Suggest(col, s, opts)
		if keep(col, out[i].Suggestion) {
			out[i].values = s.Values
		}
	}
	for _, i := range phones {
		out[i].Suggestion = Suggest(out[i].Column, Sample{Values: out[i].values}, opts)
		if !keep(out[i].Column, out[i].Suggestion) {
			out[i].values = nil
		}
	}
	return out, nil
}

// phoneLike is a column whose region inference may run: named as a phone,
// or holding mostly phone-shaped values, bare runs of digits included.
func phoneLike(col Column, values []string) bool {
	if hit, ok := matchName(col.Name, kindOf(col.SampleType())); ok && hit.entity == guard.EntityPhone {
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
