package pii

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// TestSuggestByKind pins the classifier's answers for each Kind: the same
// suggestions it gave when it matched the Postgres type names itself. The
// data type only appears in a TYPE reason; the kind decides.
func TestSuggestByKind(t *testing.T) {
	t.Parallel()
	emails := []string{"ann@example.com", "bob@example.org", "cy@example.net", "dee@example.com", "eve@example.com"}
	ids := []string{"1", "2", "3", "4", "5", "6", "7"}
	phones := []string{"+6281234567890", "+6281234567891", "+6281234567892", "+6281234567893", "+6281234567894"}
	public := func(reason string) Suggestion { return Suggestion{Class: guardmodel.ClassPublic, Reason: reason} }
	review := func(reason string) Suggestion {
		return Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, Reason: reason, NeedsReview: true}
	}
	col := func(name string, k piistore.Kind, dataType string) Column {
		return Column{Namespace: "public", Resource: "t", Name: name, Kind: k, DataType: dataType}
	}
	for _, c := range []struct {
		col  Column
		s    Sample
		want Suggestion
	}{
		{
			col("email", piistore.KindText, "text"),
			Sample{Values: emails},
			Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail, Reason: "NAME:email; SAMPLE:EMAIL 5/5"},
		},
		// A domain over citext: the adapter gives the base type's kind.
		{
			col("contact", piistore.KindText, "public.email_address"),
			Sample{Values: emails},
			Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail, Reason: "SAMPLE:EMAIL 5/5"},
		},
		{col("contact", piistore.KindOther, "public.email_address"), Sample{Values: emails}, public("TYPE:public.email_address")},
		{col("email_verified", piistore.KindBool, "boolean"), Sample{}, public("TYPE:boolean")},
		{col("password_hash", piistore.KindOther, "bytea"), Sample{}, Suggestion{Class: guardmodel.ClassSecret, Reason: "NAME:password_hash"}},
		{col("token", piistore.KindOther, "uuid"), Sample{}, Suggestion{Class: guardmodel.ClassSecret, Reason: "NAME:token"}},
		{col("created_at", piistore.KindDate, "timestamp with time zone"), Sample{}, public("TYPE:timestamp with time zone")},
		{
			col("dob", piistore.KindDate, "date"),
			Sample{},
			Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityOther, Reason: "NAME:dob"},
		},
		{Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Key: true}, Sample{Values: ids}, public(reasonSequential)},
		{Column{Name: "id", Kind: piistore.KindInt, DataType: "bigint", Generated: true}, Sample{}, public(reasonKey)},
		{col("ref", piistore.KindInt, "bigint"), Sample{Values: ids}, public(reasonSequential)},
		{col("amount", piistore.KindNumeric, "numeric"), Sample{Values: []string{"12.50", "-3.10", "99.99", "1.00", "4.25"}}, public(reasonDecimals)},
		{
			col("reach_at", piistore.KindText, "text"),
			Sample{Values: phones},
			Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: "ID", Reason: "SAMPLE:PHONE 5/5, parsed as ID numbers, 100%"},
		},
		{col("tags", piistore.KindText, "text[]"), Sample{Values: []string{"{a,b}", "{c}"}}, public("SAMPLE:no validator matched 2 values")},
		{col("codes", piistore.KindOther, "integer[]"), Sample{}, public("TYPE:integer[]")},
		{col("v", piistore.KindText, "text"), Sample{Unavailable: UnavailableTimeout}, review("SAMPLE:timed out")},
		{col("n", piistore.KindInt, "integer"), Sample{Unavailable: "error 22P02"}, review("SAMPLE:error 22P02")},
		{col("v", piistore.KindText, "text"), Sample{}, review("SAMPLE:no values")},
		{col("notes", piistore.KindText, "text"), Sample{Values: []string{"A1", "B2", "C3"}}, public("NAME:notes; SHAPE:codes only, no spaces")},
		{
			col("mobile", piistore.KindInt, "integer"),
			Sample{},
			Suggestion{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, Reason: "NAME:mobile; SAMPLE:no values"},
		},
	} {
		require.Equal(t, c.want, Suggest(c.col, c.s, Options{}), "%s %s", c.col.Name, c.col.DataType)
	}
}

// TestSampledKinds: text, integer and numeric fields are sampled.
func TestSampledKinds(t *testing.T) {
	t.Parallel()
	for k, want := range map[piistore.Kind]bool{
		piistore.KindText: true, piistore.KindInt: true, piistore.KindNumeric: true,
		piistore.KindOther: false, piistore.KindDate: false, piistore.KindBool: false,
	} {
		require.Equal(t, want, Sampled(k), k)
	}
}
