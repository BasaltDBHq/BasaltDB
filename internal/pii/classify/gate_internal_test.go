package classify

import (
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// TestLongValuesGateBeforeEveryPublicRule: a column where at least 10% of
// the values are phones is an identifier to review whatever fills the rest.
func TestLongValuesGateBeforeEveryPublicRule(t *testing.T) {
	t.Parallel()
	col := Column{Schema: "public", Table: "t", Name: "ref", DataType: "text"}
	a := make([]string, 0, 10)
	for i := range 7 {
		a = append(a, "+62812"+strconv.Itoa(30000000+i*7919))
	}
	// (a) 70% +62812… and 30% decimals.
	a = append(a, "12.5", "3.75", "0.5")
	got := Suggest(col, Sample{Values: a}, Options{})
	require.Equal(t, []any{guard.ClassIdentifier, guard.EntityPhone, true}, []any{got.Class, got.EntityType, got.NeedsReview}, got.Reason)
	// (b) 30% bare phones and 70% words.
	b := []string{"6281234567801", "6281299991234", "6281355512345", "apple", "pear", "plum", "fig", "kiwi", "lime", "date"}
	got = Suggest(col, Sample{Values: b}, Options{})
	require.Equal(t, []any{guard.ClassIdentifier, true}, []any{got.Class, got.NeedsReview}, got.Reason)
	// Small amounts alone stay PUBLIC.
	require.Equal(t, guard.ClassPublic, Suggest(Column{Name: "amount", DataType: "numeric"},
		Sample{Values: []string{"1125.00", "3.75", "12.50"}}, Options{}).Class)
}

// TestPhonesInAnyFillerAreNeverPublic is a property test: random mixes of at
// least 10% phones with any filler never come out PUBLIC.
func TestPhonesInAnyFillerAreNeverPublic(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(77, 260))
	phoneForms := []func(int) string{
		func(i int) string { return "+62812" + strconv.Itoa(30000000+i) },
		func(i int) string { return "62813" + strconv.Itoa(40000000+i) },
		func(i int) string { return "0812-" + strconv.Itoa(4000+i%5000) + "-" + strconv.Itoa(1000+i%9000) },
		func(i int) string { return "+44 20 7946 " + strconv.Itoa(1000+i%9000) },
	}
	fillers := []func(int) string{
		func(i int) string { return []string{"apple", "pear", "plum", "verified", "pending"}[i%5] },
		func(i int) string { return strconv.Itoa(i%400) + "." + strconv.Itoa(i%100) },
		func(i int) string { return strconv.Itoa(i % 9000) },
		func(i int) string { return "A-" + strconv.Itoa(100+i%50) },
		func(i int) string { return "-" + strconv.Itoa(i%300) + ".5" },
	}
	for range 120 {
		n := 10 + rng.IntN(200)
		phonesN := max(1, (n*(10+rng.IntN(91))+99)/100)
		values := make([]string, 0, n)
		form := phoneForms[rng.IntN(len(phoneForms))]
		for i := range phonesN {
			values = append(values, form(rng.IntN(1000000)+i))
		}
		for i := phonesN; i < n; i++ {
			values = append(values, fillers[rng.IntN(len(fillers))](rng.IntN(100000)+i))
		}
		rng.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })
		for _, typ := range []string{"text", "character varying"} {
			got := Suggest(Column{Schema: "public", Table: "t", Name: "ref", DataType: typ}, Sample{Values: values}, Options{})
			require.NotEqual(t, guard.ClassPublic, got.Class, "%d of %d phones: %s", phonesN, n, got.Reason)
		}
	}
}
