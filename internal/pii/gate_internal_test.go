package pii

import (
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// TestLongValuesGateBeforeEveryPublicRule: a column where at least 10% of
// the values are phones is an identifier to review whatever fills the rest.
func TestLongValuesGateBeforeEveryPublicRule(t *testing.T) {
	t.Parallel()
	col := Column{Namespace: "public", Resource: "t", Name: "ref", Kind: piistore.KindText, DataType: "text"}
	a := make([]string, 0, 10)
	for i := range 7 {
		a = append(a, "+62812"+strconv.Itoa(30000000+i*7919))
	}
	// (a) 70% +62812… and 30% decimals.
	a = append(a, "12.5", "3.75", "0.5")
	got := Suggest(col, Sample{Values: a}, Options{})
	require.Equal(t, []any{guardmodel.ClassIdentifier, guardmodel.EntityPhone, true}, []any{got.Class, got.EntityType, got.NeedsReview}, got.Reason)
	// (b) 30% bare phones and 70% words.
	b := []string{"6281234567801", "6281299991234", "6281355512345", "apple", "pear", "plum", "fig", "kiwi", "lime", "date"}
	got = Suggest(col, Sample{Values: b}, Options{})
	require.Equal(t, []any{guardmodel.ClassIdentifier, true}, []any{got.Class, got.NeedsReview}, got.Reason)
	// Small amounts alone stay PUBLIC.
	require.Equal(t, guardmodel.ClassPublic, Suggest(Column{Name: "amount", Kind: piistore.KindNumeric, DataType: "numeric"},
		Sample{Values: []string{"1125.00", "3.75", "12.50"}}, Options{}).Class)
}

// TestConsecutivePhonesAreNoSequence: a block of consecutive MSISDNs, every
// second one, or five in a row are phones to review, as bigint and as text;
// only short sequences, or a key, are ids.
func TestConsecutivePhonesAreNoSequence(t *testing.T) {
	t.Parallel()
	block := func(start, step, n int) []string {
		out := make([]string, 0, n)
		for i := range n {
			out = append(out, strconv.Itoa(start+i*step))
		}
		return out
	}
	for _, vs := range [][]string{
		block(6281200000001, 1, 200),
		block(6281200000001, 2, 200),
		block(6281200000001, 1, 5),
	} {
		for typ, k := range map[string]piistore.Kind{"bigint": piistore.KindInt, "text": piistore.KindText} {
			got := Suggest(Column{Namespace: "public", Resource: "t", Name: "ref", Kind: k, DataType: typ}, Sample{Values: vs}, Options{})
			require.Equal(t, []any{guardmodel.ClassIdentifier, guardmodel.EntityPhone, "ID", true},
				[]any{got.Class, got.EntityType, got.PhoneRegion, got.NeedsReview}, "%s %d values: %s", typ, len(vs), got.Reason)
		}
	}
	require.Equal(t, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonSequential},
		Suggest(Column{Name: "order_number", Kind: piistore.KindInt, DataType: "bigint"}, Sample{Values: block(1000, 1, 50)}, Options{}))
	// A key holding MSISDNs is a phone to review; an identity is an id.
	require.Equal(t, guardmodel.EntityPhone, Suggest(Column{Name: "ref", Kind: piistore.KindInt, DataType: "bigint", Key: true},
		Sample{Values: block(6281200000001, 1, 50)}, Options{}).EntityType)
	// An identity filled with MSISDNs meets the gate too.
	require.Equal(t, guardmodel.EntityPhone, Suggest(Column{Name: "ref", Kind: piistore.KindInt, DataType: "bigint", Key: true, Generated: true},
		Sample{Values: block(6281200000001, 1, 50)}, Options{}).EntityType)
}

// TestKeysAreJudgedLikeAnyColumn: only identity and serial columns, uuid
// columns and integer keys of short values are ids; any other key goes
// through the validators and the gate.
func TestKeysAreJudgedLikeAnyColumn(t *testing.T) {
	t.Parallel()
	msisdns := make([]string, 0, 50)
	accounts := make([]string, 0, 50)
	for i := range 50 {
		msisdns = append(msisdns, strconv.Itoa(6281200000001+i))
		accounts = append(accounts, strconv.Itoa(9900000000000000+i*7919*13))
	}
	for _, tc := range []struct {
		name   string
		col    Column
		values []string
	}{
		{"text PK of 628… numbers", Column{Name: "id", Kind: piistore.KindText, DataType: "text", Key: true}, msisdns},
		{"FK to users(phone)", Column{Name: "user_ref", Kind: piistore.KindInt, DataType: "bigint", Key: true}, msisdns},
		{"text PK of 16-digit accounts", Column{Name: "id", Kind: piistore.KindText, DataType: "text", Key: true}, accounts},
		{"consecutive MSISDN bigint PK", Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true}, msisdns},
	} {
		got := Suggest(tc.col, Sample{Values: tc.values}, Options{})
		require.Equal(t, []any{guardmodel.ClassIdentifier, true}, []any{got.Class, got.NeedsReview}, "%s: %s", tc.name, got.Reason)
	}
	require.Equal(t, guardmodel.ClassPublic, Suggest(Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true, Generated: true},
		Sample{Values: []string{"3", "17", "1200", "9"}}, Options{}).Class, "identity")
	require.Equal(t, guardmodel.ClassPublic, Suggest(Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true, Generated: true},
		Sample{}, Options{}).Class, "empty identity")
	// The exemption never overrides a name rule, a validator or the gate.
	for _, tc := range []struct {
		col    Column
		values []string
		class  string
		entity string
	}{
		{Column{Name: "zip", Kind: piistore.KindInt, DataType: "integer", Key: true}, []string{"40115", "10110", "80361"}, guardmodel.ClassIdentifier, guardmodel.EntityAddress},
		{Column{Name: "pin", Kind: piistore.KindInt, DataType: "integer", Key: true}, []string{"4821", "1093", "7710"}, guardmodel.ClassSecret, ""},
		{Column{Name: "phone", Kind: piistore.KindInt, DataType: "bigint", Key: true, Generated: true}, msisdns, guardmodel.ClassIdentifier, guardmodel.EntityPhone},
		{Column{Name: "contact", Kind: piistore.KindText, DataType: "text", Generated: true}, []string{"a@example.com", "b@example.org"}, guardmodel.ClassIdentifier, guardmodel.EntityEmail},
	} {
		got := Suggest(tc.col, Sample{Values: tc.values}, Options{})
		require.Equal(t, []string{tc.class, tc.entity}, []string{got.Class, got.EntityType}, "%s: %s", tc.col.Name, got.Reason)
	}
	require.Equal(t, guardmodel.ClassPublic, Suggest(Column{Name: "id", Kind: piistore.KindOther, DataType: "uuid", Key: true}, Sample{}, Options{}).Class, "uuid")
	require.Equal(t, guardmodel.ClassPublic, Suggest(Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true},
		Sample{Values: []string{"7", "42", "99999"}}, Options{}).Class, "short integer key")
}

// TestRegionTiesGoToTheNumbersOwnCountry: local numbers valid in several
// regions infer ID with no +cc in the database.
func TestRegionTiesGoToTheNumbersOwnCountry(t *testing.T) {
	t.Parallel()
	for _, vs := range [][]string{
		{"081234567801", "081298765432", "081311122233"},
		{"0812-3456-7801", "0857-1234-5678", "0878-1234-5678"},
	} {
		require.Equal(t, "ID", inferRegion(vs, false, "", map[int32]int{}).region, "%v", vs)
	}
	// With the database's +cc dominant, ties go to it.
	require.Equal(t, "ID", inferRegion([]string{"081234567801"}, false, "", map[int32]int{62: 5}).region)
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
	for range sized(120, 15) {
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
			got := Suggest(Column{Namespace: "public", Resource: "t", Name: "ref", Kind: piistore.KindText, DataType: typ}, Sample{Values: values}, Options{})
			require.NotEqual(t, guardmodel.ClassPublic, got.Class, "%d of %d phones: %s", phonesN, n, got.Reason)
		}
	}
}
