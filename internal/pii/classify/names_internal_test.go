package classify

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

func TestSplitName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string][]string{
		"customerEmail":  {"customer", "email"},
		"email_address":  {"email", "address"},
		"HTTPStatusCode": {"http", "status", "code"},
		"e-mail":         {"e", "mail"},
		"msisdn":         {"msisdn"},
		"Phone2":         {"phone2"},
	} {
		require.Equal(t, want, splitName(in), in)
	}
}

func TestMatchName(t *testing.T) {
	t.Parallel()
	type hit struct{ class, entity string }
	for _, tc := range []struct {
		name string
		k    kind
		want *hit
	}{
		{"customerEmail", kindText, &hit{guard.ClassIdentifier, guard.EntityEmail}},
		{"email_address", kindText, &hit{guard.ClassIdentifier, guard.EntityEmail}},
		{"mail_count", kindInt, nil},
		{"email_count", kindText, nil},
		{"email_verified", kindBool, nil},
		{"encrypted_password", kindText, &hit{guard.ClassSecret, ""}},
		{"password_changed_at", kindDate, nil},
		{"token_type", kindText, nil},
		{"password_hash", kindOther, &hit{guard.ClassSecret, ""}},
		{"mobile", kindInt, &hit{guard.ClassIdentifier, guard.EntityPhone}},
		{"name", kindText, &hit{guard.ClassIdentifier, guard.EntityPersonName}},
		{"first_name", kindText, &hit{guard.ClassIdentifier, guard.EntityPersonName}},
		{"contact_name", kindText, &hit{guard.ClassIdentifier, guard.EntityPersonName}},
		{"table_name", kindText, nil},
		{"product_name", kindText, nil},
		{"file_name", kindText, nil},
		{"company_name", kindText, nil},
		{"street_name", kindText, &hit{guard.ClassIdentifier, guard.EntityAddress}},
		{"zip", kindInt, &hit{guard.ClassIdentifier, guard.EntityAddress}},
		{"address", kindInt, nil},
		{"ip_address", kindText, &hit{guard.ClassIdentifier, guard.EntityOther}},
		{"date_of_birth", kindDate, &hit{guard.ClassIdentifier, guard.EntityOther}},
		{"iban", kindText, &hit{guard.ClassIdentifier, guard.EntityOther}},
		{"notes", kindText, &hit{guard.ClassFreeText, ""}},
		{"order_number", kindInt, nil},
		{"status", kindText, nil},
	} {
		got, ok := matchName(tc.name, tc.k)
		if tc.want == nil {
			require.False(t, ok, "%s: %+v", tc.name, got)
			continue
		}
		require.True(t, ok, tc.name)
		require.Equal(t, *tc.want, hit{got.class, got.entity}, tc.name)
	}
}

func TestKindOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]kind{
		"text": kindText, "character varying": kindText, "extensions.citext": kindText, "jsonb": kindText,
		"text[]": kindText, "integer[]": kindOther, "bigint": kindInt, "numeric": kindNumeric,
		"timestamp with time zone": kindDate, "boolean": kindBool, "uuid": kindOther, "bytea": kindOther,
	} {
		require.Equal(t, want, kindOf(in), in)
	}
}

func TestValidators(t *testing.T) {
	t.Parallel()
	require.True(t, validNIK("3174051201900001"))
	require.True(t, validNIK("3174055201900001"), "a woman's day is +40")
	require.False(t, validNIK("9974051201900001"), "no such province")
	require.False(t, validNIK("3174053102900001"), "31 February")
	require.False(t, validNIK("3174051201900000"), "serial 0000")
	require.False(t, validNIK("317405120190000"), "15 digits")
	require.True(t, validIMEI("490154203237518"))
	require.False(t, validIMEI("490154203237519"))
	require.True(t, validCard("4111 1111 1111 1111"))
	require.False(t, validCard("4111 1111 1111 1112"))
	require.True(t, validIBAN("EE38 2200 2210 2014 5685"))
	require.True(t, validEmail("a.b@example.co.id"))
	require.False(t, validEmail("Alice <a@example.com>"))
	require.False(t, validEmail("a@localhost"))
	require.True(t, startsWithFirstName("alice tamm"))
	require.False(t, startsWithFirstName("Blue Widget"))
	require.True(t, codeLike("INV/2026/7"))
	require.False(t, codeLike("call back"))
}

func TestPhoneShape(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		bare bool
		ok   bool
	}{
		{"+62 812-3456-7801", false, true},
		{"0062 812 3456 7801", false, true},
		{"081234567801", false, true},
		{"6281234567801", false, false},
		{"6281234567801", true, true},
		{"12345", true, false},
		{"Alice", false, false},
	} {
		_, ok := phoneShape(tc.in, tc.bare)
		require.Equal(t, tc.ok, ok, tc.in)
	}
	r := inferRegion([]string{"081234567801", "081234567802", "+62 812-3456-7803"}, false, "", map[int32]int{62: 3})
	require.Equal(t, regionResult{region: "ID", valid: 3}, r)
	require.Equal(t, "EE", inferRegion([]string{"+372 5123 4567"}, false, "", nil).region)
	require.Empty(t, inferRegion([]string{"hello"}, false, "", nil).region)
}

func TestSuggestShapes(t *testing.T) {
	t.Parallel()
	col := func(name, typ string) Column { return Column{Schema: "public", Table: "t", Name: name, DataType: typ} }
	seq := make([]string, 0, 50)
	ambiguous := make([]string, 0, 50)
	for i := range 50 {
		seq = append(seq, strconv.Itoa(1000+i))
		ambiguous = append(ambiguous, strconv.Itoa(7300000000+i*7919*13))
	}
	review := Suggestion{Class: guard.ClassIdentifier, EntityType: guard.EntityOther, NeedsReview: true}
	for _, tc := range []struct {
		col    Column
		values []string
		want   Suggestion
	}{
		{col("ref", "bigint"), seq, Suggestion{Class: guard.ClassPublic, Reason: reasonSequential}},
		{col("ref", "text"), ambiguous, review},
		{col("ref", "bigint"), ambiguous, review},
		{col("price", "numeric"), []string{"1.50", "2.00", "-3.10"}, Suggestion{Class: guard.ClassPublic, Reason: reasonDecimals}},
		{col("ref", "text"), nil, review},
		{Column{Name: "id", DataType: "bigint", Key: true}, nil, Suggestion{Class: guard.ClassPublic, Reason: reasonKey}},
		{Column{Name: "id", DataType: "bigint", Key: true}, ambiguous, Suggestion{Class: guard.ClassPublic, Reason: reasonKey}},
		{col("id", "uuid"), nil, Suggestion{Class: guard.ClassPublic, Reason: "TYPE:uuid"}},
		{col("secret_email", "text"), []string{"a@example.com"}, Suggestion{Class: guard.ClassSecret}},
		{col("full_name", "text"), []string{"a long sentence that is not really a name of anyone at all, really"},
			Suggestion{Class: guard.ClassIdentifier, EntityType: guard.EntityPersonName}},
		{col("notes", "text"), []string{"A-1", "B-2"}, Suggestion{Class: guard.ClassPublic}},
		{col("notes", "text"), []string{"call Alice"}, Suggestion{Class: guard.ClassFreeText}},
	} {
		got := Suggest(tc.col, Sample{Values: tc.values}, Options{})
		if tc.want.Reason == "" {
			got.Reason = ""
		}
		require.Equal(t, tc.want, got, "%s %s %v", tc.col.Name, tc.col.DataType, tc.values)
	}
	// Bare numbers that are valid phones are no phone without the name.
	phones := []string{"6281234567801", "6281299991234", "6281355512345"}
	require.Equal(t, guard.EntityOther, Suggest(col("ref", "bigint"), Sample{Values: phones}, Options{}).EntityType)
	require.Equal(t, guard.EntityPhone, Suggest(col("msisdn", "bigint"), Sample{Values: phones}, Options{}).EntityType)
}

func TestProtectedNeverLowersAConfirmedClass(t *testing.T) {
	t.Parallel()
	c := ReviewColumn{
		Result: Result{Column: Column{Schema: "public", Table: "t", Name: "c", DataType: "text"},
			Suggestion: Suggestion{Class: guard.ClassPublic}},
		Stored: &guard.PIIColumn{Class: guard.ClassIdentifier, EntityType: guard.EntityEmail, DataType: "text"},
	}
	require.Equal(t, Decision{Class: guard.ClassIdentifier, EntityType: guard.EntityEmail}, c.Protected())
	c.Suggestion = Suggestion{Class: guard.ClassSecret, NeedsReview: true}
	require.Equal(t, Decision{Class: guard.ClassSecret, NeedsReview: true}, c.Protected())
	require.Equal(t, Decision{Class: guard.ClassSecret}, c.Suggested())
}

func TestRowsKeepConfirmedClasses(t *testing.T) {
	t.Parallel()
	col := func(name string) Column { return Column{Schema: "public", Table: "t", Name: name, DataType: "text"} }
	tables := []ReviewTable{{Table: "public.t", Columns: []ReviewColumn{
		{Result: Result{Column: col("a"), Suggestion: Suggestion{Class: guard.ClassPublic, Reason: "r"}}},
		{Result: Result{Column: col("b"), Suggestion: Suggestion{Class: guard.ClassIdentifier, EntityType: guard.EntityOther, NeedsReview: true}}},
		{Result: Result{Column: col("c"), Suggestion: Suggestion{Class: guard.ClassPublic}},
			Stored: &guard.PIIColumn{Class: guard.ClassSecret, DataType: "text"}},
	}}}
	rows := Rows(tables, map[string]Decision{"public.t.a": {Class: guard.ClassPublic}})
	require.Len(t, rows, 2, "c keeps its confirmed row")
	require.Equal(t, guard.ClassPublic, rows[0].Class)
	require.Equal(t, guard.ClassUnclassified, rows[1].Class)
	require.Equal(t, guard.ClassIdentifier, rows[1].SuggestedClass)
	require.True(t, rows[1].NeedsReview)
}

func TestStatusOf(t *testing.T) {
	t.Parallel()
	col := Column{DataType: "text"}
	s := Suggestion{Class: guard.ClassPublic}
	require.Equal(t, StatusNew, StatusOf(nil, col, s))
	require.Equal(t, StatusUnclassified, StatusOf(&guard.PIIColumn{Class: guard.ClassUnclassified, DataType: "text"}, col, s))
	require.Equal(t, StatusTypeChanged, StatusOf(&guard.PIIColumn{Class: guard.ClassPublic, DataType: "integer"}, col, s))
	require.Equal(t, StatusNeedsReview, StatusOf(&guard.PIIColumn{Class: guard.ClassPublic, DataType: "text", NeedsReview: true}, col, s))
	require.Equal(t, StatusSuggestionDiffers, StatusOf(&guard.PIIColumn{Class: guard.ClassSecret, DataType: "text"}, col, s))
	require.Equal(t, StatusUnchanged, StatusOf(&guard.PIIColumn{Class: guard.ClassPublic, DataType: "text"}, col, s))
}
