package classify

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
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
		{"customerEmail", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityEmail}},
		{"email_address", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityEmail}},
		{"mail_count", kindInt, nil},
		{"email_verified", kindBool, nil},
		{"encrypted_password", kindText, &hit{guardmodel.ClassSecret, ""}},
		{"password_changed_at", kindDate, nil},
		{"password_hash", kindOther, &hit{guardmodel.ClassSecret, ""}},
		{"mobile", kindInt, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPhone}},
		{"name", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPersonName}},
		{"first_name", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPersonName}},
		{"contact_name", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPersonName}},
		{"table_name", kindText, nil},
		{"product_name", kindText, nil},
		{"file_name", kindText, nil},
		{"company_name", kindText, nil},
		{"street_name", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityAddress}},
		{"zip", kindInt, &hit{guardmodel.ClassIdentifier, guardmodel.EntityAddress}},
		{"address", kindInt, nil},
		{"ip_address", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityOther}},
		{"date_of_birth", kindDate, &hit{guardmodel.ClassIdentifier, guardmodel.EntityOther}},
		{"iban", kindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityOther}},
		{"notes", kindText, &hit{guardmodel.ClassFreeText, ""}},
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
	// A qualifier keeps the name only as a floor, marked qualified.
	for _, name := range []string{"email_count", "token_type", "mobile_updated"} {
		got, ok := matchName(name, kindText)
		require.True(t, ok, name)
		require.True(t, got.qualified, name)
	}
	for _, name := range []string{"pin", "otp", "cvc", "cvv", "passcode", "security_code", "card_pin"} {
		got, ok := matchName(name, kindText)
		require.True(t, ok, name)
		require.Equal(t, guardmodel.ClassSecret, got.class, name)
	}
	got, ok := matchName("email_address", kindText)
	require.True(t, ok)
	require.False(t, got.qualified)
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
	require.Equal(t, []int{3}, []int{r.valid})
	require.Equal(t, "ID", r.region)
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
		ambiguous = append(ambiguous, strconv.Itoa(9900000000000000+i*7919*13))
	}
	review := Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, NeedsReview: true}
	for _, tc := range []struct {
		col    Column
		values []string
		want   Suggestion
	}{
		{col("ref", "bigint"), seq, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonSequential}},
		{col("ref", "text"), ambiguous, review},
		{col("ref", "bigint"), ambiguous, review},
		{col("price", "numeric"), []string{"1.50", "2.00", "-3.10"}, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonDecimals}},
		{col("ref", "text"), nil, review},
		{Column{Name: "id", DataType: "bigint", Key: true}, nil, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonKey}},
		{Column{Name: "id", DataType: "bigint", Key: true}, ambiguous, review},
		{Column{Name: "id", DataType: "bigint", Key: true, Generated: true}, ambiguous, review},
		{Column{Name: "id", DataType: "bigint", Key: true, Generated: true}, seq, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonSequential}},
		{col("id", "uuid"), nil, Suggestion{Class: guardmodel.ClassPublic, Reason: "TYPE:uuid"}},
		{col("secret_email", "text"), []string{"a@example.com"}, Suggestion{Class: guardmodel.ClassSecret}},
		{
			col("full_name", "text"),
			[]string{"a long sentence that is not really a name of anyone at all, really"},
			Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPersonName},
		},
		{col("notes", "text"), []string{"A-1", "B-2"}, Suggestion{Class: guardmodel.ClassPublic}},
		{col("notes", "text"), []string{"call Alice"}, Suggestion{Class: guardmodel.ClassFreeText}},
		{col("notes", "text"), []string{"A-1", "B-2", "6281234567801"}, Suggestion{Class: guardmodel.ClassFreeText}},
		{col("email_status", "text"), []string{"verified", "pending"}, Suggestion{Class: guardmodel.ClassPublic}},
		{col("contact_updated", "text"), []string{"short"}, Suggestion{Class: guardmodel.ClassPublic}},
	} {
		got := Suggest(tc.col, Sample{Values: tc.values}, Options{})
		if tc.want.Reason == "" {
			got.Reason = ""
		}
		require.Equal(t, tc.want, got, "%s %s %v", tc.col.Name, tc.col.DataType, tc.values)
	}
	// Bare numbers that are valid phones are phones to review without the
	// name, read with their country code (+62, not a German number).
	phones := []string{"6281234567801", "6281299991234", "6281355512345"}
	unnamed := Suggest(col("ref", "bigint"), Sample{Values: phones}, Options{})
	require.Equal(t, []any{guardmodel.EntityPhone, "ID", true}, []any{unnamed.EntityType, unnamed.PhoneRegion, unnamed.NeedsReview})
	// Real-format Indonesian mobiles written bare, 11 to 13 digits: ID.
	for _, vs := range [][]string{{"628123456789", "628129876543", "628131112223"}, {"6281234567890", "6285712345678", "6287812345678"}} {
		got := Suggest(col("ref", "text"), Sample{Values: vs}, Options{})
		require.Equal(t, []any{guardmodel.EntityPhone, "ID"}, []any{got.EntityType, got.PhoneRegion}, "%v", vs)
	}
	// Long phones among short numbers are not PUBLIC by their length spread.
	mixed := []string{"6281234567801", "6281299991234", "6281355512345", "6281377770000", "6281388881111", "6281399992222", "6281311113333", "123", "4567", "89"}
	got := Suggest(col("ref", "bigint"), Sample{Values: mixed}, Options{})
	require.Equal(t, []any{guardmodel.ClassIdentifier, guardmodel.EntityPhone, true}, []any{got.Class, got.EntityType, got.NeedsReview}, got.Reason)
	// A qualified secret name stays SECRET over short codes.
	require.Equal(t, guardmodel.ClassSecret, Suggest(col("token_sent", "text"), Sample{Values: []string{"a8F3kq92Zx"}}, Options{}).Class)
	require.Equal(t, guardmodel.ClassSecret, Suggest(col("pin", "text"), Sample{Values: []string{"0420", "1234"}}, Options{}).Class)
	require.Equal(t, guardmodel.EntityPhone, Suggest(col("msisdn", "bigint"), Sample{Values: phones}, Options{}).EntityType)
}

func TestProtectedNeverLowersAConfirmedClass(t *testing.T) {
	t.Parallel()
	c := ReviewColumn{
		Result: Result{
			Column:     Column{Schema: "public", Table: "t", Name: "c", DataType: "text"},
			Suggestion: Suggestion{Class: guardmodel.ClassPublic},
		},
		Stored: &guardmodel.PIIColumn{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail, DataType: "text"},
	}
	require.Equal(t, Decision{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail}, c.Protected())
	// An equal rank keeps the person's class too.
	c.Suggestion = Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPersonName}
	require.Equal(t, Decision{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail}, c.Protected())
	c.Suggestion = Suggestion{Class: guardmodel.ClassSecret, NeedsReview: true}
	require.Equal(t, Decision{Class: guardmodel.ClassSecret, NeedsReview: true}, c.Protected())
	require.Equal(t, Decision{Class: guardmodel.ClassSecret}, c.Suggested())
}

func TestRowsKeepConfirmedClasses(t *testing.T) {
	t.Parallel()
	col := func(name string) Column { return Column{Schema: "public", Table: "t", Name: name, DataType: "text"} }
	tables := []ReviewTable{{Table: "public.t", Columns: []ReviewColumn{
		{Result: Result{Column: col("a"), Suggestion: Suggestion{Class: guardmodel.ClassPublic, Reason: "r"}}},
		{Result: Result{Column: col("b"), Suggestion: Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, NeedsReview: true}}},
		{
			Result: Result{Column: col("c"), Suggestion: Suggestion{Class: guardmodel.ClassPublic}},
			Stored: &guardmodel.PIIColumn{Class: guardmodel.ClassSecret, DataType: "text"},
		},
	}}}
	rows := Rows(tables, map[string]Decision{"public.t.a": {Class: guardmodel.ClassPublic}})
	require.Len(t, rows, 2, "c keeps its confirmed row")
	require.Equal(t, guardmodel.ClassPublic, rows[0].Class)
	require.Equal(t, guardmodel.ClassUnclassified, rows[1].Class)
	require.Equal(t, guardmodel.ClassIdentifier, rows[1].SuggestedClass)
	require.True(t, rows[1].NeedsReview)
}

func TestStatusOf(t *testing.T) {
	t.Parallel()
	col := Column{DataType: "text"}
	s := Suggestion{Class: guardmodel.ClassPublic}
	require.Equal(t, StatusNew, StatusOf(nil, col, s))
	require.Equal(t, StatusUnclassified, StatusOf(&guardmodel.PIIColumn{Class: guardmodel.ClassUnclassified, DataType: "text"}, col, s))
	require.Equal(t, StatusTypeChanged, StatusOf(&guardmodel.PIIColumn{Class: guardmodel.ClassPublic, DataType: "integer"}, col, s))
	require.Equal(t, StatusNeedsReview, StatusOf(&guardmodel.PIIColumn{Class: guardmodel.ClassPublic, DataType: "text", NeedsReview: true}, col, s))
	require.Equal(t, StatusSuggestionDiffers, StatusOf(&guardmodel.PIIColumn{Class: guardmodel.ClassSecret, DataType: "text"}, col, s))
	require.Equal(t, StatusUnchanged, StatusOf(&guardmodel.PIIColumn{Class: guardmodel.ClassPublic, DataType: "text"}, col, s))
}
