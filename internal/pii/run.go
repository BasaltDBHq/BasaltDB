package pii

import (
	"context"
	"crypto/rand"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
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
	if hit, ok := matchName(col.Name, kindOf(col.SampleType())); ok && hit.entity == guardmodel.EntityPhone {
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

// CheckTarget is how a column's values are tokenized in the round trip.
type CheckTarget struct {
	EntityType  string
	PhoneRegion string
}

// CheckResult is the round trip of one column's sample (CONTRACT.md,
// basalt classify --check): counts only.
type CheckResult struct {
	Sampled           int
	RoundTripFailures int
	// CommonWordRule is how many failures are single common words, which
	// free text never matches alone (owner decision DD-1).
	CommonWordRule int
}

// masterKeyBytes is the size of pii's master key.
const masterKeyBytes = 32

// Check runs the round trip, in memory, for every result target accepts:
// each value's token is made, the token restored to the value, and the
// restored text tokenized again by the default detectors over a dictionary
// of every checked value; a value fails when that does not give back exactly
// its token. The keys are random and used for this run only. Keyed by
// Column.FullName.
func Check(results []Result, target func(Result) (CheckTarget, bool)) (map[string]CheckResult, error) {
	master := make([]byte, masterKeyBytes)
	if _, err := rand.Read(master); err != nil {
		return nil, err
	}
	keys, err := corepii.NewKeys(master)
	if err != nil {
		return nil, err
	}
	dict := newMemDict()
	type checked struct {
		r Result
		t CheckTarget
	}
	var todo []checked
	for _, r := range results {
		t, ok := target(r)
		if !ok {
			continue
		}
		todo = append(todo, checked{r, t})
		for _, v := range r.values {
			dict.add(keys, corepii.EntityType(t.EntityType), v, t.PhoneRegion)
		}
	}
	out := map[string]CheckResult{}
	for _, c := range todo {
		dd := corepii.NewDictionaryDetector(keys, dict, c.t.PhoneRegion)
		tz := corepii.NewTokenizer(keys, c.t.PhoneRegion, append(corepii.PatternDetectors(), dd)...)
		res := CheckResult{Sampled: len(c.r.values)}
		for _, v := range c.r.values {
			if roundTrips(keys, tz, corepii.EntityType(c.t.EntityType), v, c.t.PhoneRegion) {
				continue
			}
			res.RoundTripFailures++
			if len(strings.Fields(v)) == 1 && corepii.IsCommonWord(v) {
				res.CommonWordRule++
			}
		}
		out[c.r.Column.FullName()] = res
	}
	return out, nil
}

// roundTrips reports whether value, restored into text from its token,
// tokenizes back to exactly that token.
func roundTrips(keys *corepii.Keys, tz *corepii.Tokenizer, t corepii.EntityType, value, region string) bool {
	want, err := keys.MakeToken(t, value, region)
	if err != nil {
		return false
	}
	_, reps, err := tz.Tokenize(value)
	if err != nil || len(reps) != 1 || reps[0].Token != want {
		return false
	}
	return strings.TrimSpace(value[:reps[0].Start]) == "" && strings.TrimSpace(value[reps[0].End:]) == ""
}

// memDict is an exact in-memory corepii.Dictionary of the checked values: the
// same hashes the engine's dictionary holds.
type memDict struct {
	generic map[corepii.Hash]corepii.EntityType
	typed   map[corepii.EntityType]map[corepii.Hash]bool
}

func newMemDict() *memDict {
	return &memDict{generic: map[corepii.Hash]corepii.EntityType{}, typed: make(map[corepii.EntityType]map[corepii.Hash]bool)}
}

func (d *memDict) add(k *corepii.Keys, t corepii.EntityType, value, region string) {
	for _, h := range k.GenericHashes(t, value) {
		if _, ok := d.generic[h]; !ok {
			d.generic[h] = t
		}
	}
	if d.typed[t] == nil {
		d.typed[t] = map[corepii.Hash]bool{}
	}
	d.typed[t][k.TypedHash(t, value, region)] = true
}

func (d *memDict) Lookup(h corepii.Hash) (corepii.EntityType, bool) {
	t, ok := d.generic[h]
	return t, ok
}

func (d *memDict) Contains(t corepii.EntityType, h corepii.Hash) bool { return d.typed[t][h] }
