package pii

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
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
		k    piistore.Kind
		want *hit
	}{
		{"customerEmail", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityEmail}},
		{"email_address", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityEmail}},
		{"mail_count", piistore.KindInt, nil},
		{"email_verified", piistore.KindBool, nil},
		{"encrypted_password", piistore.KindText, &hit{guardmodel.ClassSecret, ""}},
		{"password_changed_at", piistore.KindDate, nil},
		{"password_hash", piistore.KindOther, &hit{guardmodel.ClassSecret, ""}},
		{"mobile", piistore.KindInt, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPhone}},
		{"name", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPersonName}},
		{"first_name", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPersonName}},
		{"contact_name", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityPersonName}},
		{"table_name", piistore.KindText, nil},
		{"product_name", piistore.KindText, nil},
		{"file_name", piistore.KindText, nil},
		{"company_name", piistore.KindText, nil},
		{"street_name", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityAddress}},
		{"zip", piistore.KindInt, &hit{guardmodel.ClassIdentifier, guardmodel.EntityAddress}},
		{"address", piistore.KindInt, nil},
		{"ip_address", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityOther}},
		{"date_of_birth", piistore.KindDate, &hit{guardmodel.ClassIdentifier, guardmodel.EntityOther}},
		{"iban", piistore.KindText, &hit{guardmodel.ClassIdentifier, guardmodel.EntityOther}},
		{"notes", piistore.KindText, &hit{guardmodel.ClassFreeText, ""}},
		{"order_number", piistore.KindInt, nil},
		{"status", piistore.KindText, nil},
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
		got, ok := matchName(name, piistore.KindText)
		require.True(t, ok, name)
		require.True(t, got.qualified, name)
	}
	for _, name := range []string{"pin", "otp", "cvc", "cvv", "passcode", "security_code", "card_pin"} {
		got, ok := matchName(name, piistore.KindText)
		require.True(t, ok, name)
		require.Equal(t, guardmodel.ClassSecret, got.class, name)
	}
	got, ok := matchName("email_address", piistore.KindText)
	require.True(t, ok)
	require.False(t, got.qualified)
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
	kinds := map[string]piistore.Kind{"bigint": piistore.KindInt, "numeric": piistore.KindNumeric, "text": piistore.KindText, "uuid": piistore.KindOther}
	col := func(name, typ string) Column {
		k, ok := kinds[typ]
		require.True(t, ok, typ)
		return Column{Namespace: "public", Resource: "t", Name: name, Kind: k, DataType: typ}
	}
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
		{Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true}, nil, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonKey}},
		{Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true}, ambiguous, review},
		{Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true, Generated: true}, ambiguous, review},
		{Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true, Generated: true}, seq, Suggestion{Class: guardmodel.ClassPublic, Reason: reasonSequential}},
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
