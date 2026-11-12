package classify_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pii/classify"
)

// want is a column's expected suggestion.
type want struct {
	class, entity, region string
	needsReview           bool
}

var (
	public     = want{class: guard.ClassPublic}
	secret     = want{class: guard.ClassSecret}
	freeText   = want{class: guard.ClassFreeText}
	email      = want{class: guard.ClassIdentifier, entity: guard.EntityEmail}
	idPhone    = want{class: guard.ClassIdentifier, entity: guard.EntityPhone, region: "ID"}
	personName = want{class: guard.ClassIdentifier, entity: guard.EntityPersonName}
	other      = want{class: guard.ClassIdentifier, entity: guard.EntityOther}
)

// fixtureWant is the expected suggestion of every column of
// testdata/schema.sql.
var fixtureWant = map[string]want{
	"public.customers.id":           public,
	"public.customers.password":     secret,
	"public.customers.email":        email,
	"public.customers.phone":        idPhone,
	"public.customers.full_name":    personName,
	"public.customers.address":      {class: guard.ClassIdentifier, entity: guard.EntityAddress},
	"public.customers.dob":          other,
	"public.customers.iban":         other,
	"public.customers.description":  freeText,
	"public.customers.login":        email,
	"public.customers.contact":      idPhone,
	"public.customers.citizen_ref":  secret,
	"public.customers.device_ref":   other,
	"public.customers.payout_ref":   other,
	"public.customers.payment_ref":  secret,
	"public.customers.attendee":     personName,
	"public.customers.feedback":     freeText,
	"public.customers.phone_intl":   idPhone,
	"public.customers.phone_local":  idPhone,
	"public.customers.msisdn":       idPhone,
	"public.customers.member_code":  {class: guard.ClassIdentifier, entity: guard.EntityOther, needsReview: true},
	"public.customers.table_name":   public,
	"public.customers.product_name": public,
	"public.customers.mail_count":   public,
	"public.customers.status":       public,
	"public.customers.notes":        public,
	"public.orders.id":              public,
	"public.orders.customer_id":     public,
	"public.orders.order_number":    public,
	"public.orders.amount":          public,
	"public.orders.quantity":        public,
	"public.orders.product_name":    public,
	"public.orders.created_at":      public,
	"public.orders.paid":            public,
}

// fixtureDB loads the fixture schema and an agent that reads both tables.
func fixtureDB(t *testing.T) *guardtest.DB {
	t.Helper()
	d := guardtest.New(t)
	schema, err := os.ReadFile("testdata/schema.sql")
	require.NoError(t, err)
	d.Exec(t, string(schema))
	d.NewAgent(t, "bot", nil, []string{"public.customers", "public.orders"})
	return d
}

// suggestAll runs the classify pipeline as basalt classify does.
func suggestAll(t *testing.T, d *guardtest.DB, opts classify.Options, keep bool) []classify.Result {
	t.Helper()
	ctx := context.Background()
	var st guard.ClassificationState
	require.NoError(t, pgx.BeginTxFunc(ctx, d.Admin, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		st, err = guard.ReadClassification(ctx, tx, d.Names)
		return err
	}))
	keys, err := classify.KeyColumns(ctx, d.Admin)
	require.NoError(t, err)
	cols := make([]classify.Column, 0, len(st.Readable))
	for _, r := range st.Readable {
		cols = append(cols, classify.Column{Schema: r.Schema, Table: r.Table, Name: r.Column, DataType: r.DataType,
			Key: keys[classify.KeyRef{TableOID: r.TableOID, Attnum: r.Attnum}]})
	}
	sampler := classify.Sampler{Conn: d.Admin, Timeout: 5 * time.Second}
	results, err := classify.SuggestAll(ctx, cols, sampler.Sample, opts,
		func(classify.Column, classify.Suggestion) bool { return keep })
	require.NoError(t, err)
	return results
}

func TestFixtureSchemaSuggestions(t *testing.T) {
	t.Parallel()
	d := fixtureDB(t)
	results := suggestAll(t, d, classify.Options{}, false)
	got := map[string]want{}
	for _, r := range results {
		s := r.Suggestion
		got[r.Column.FullName()] = want{class: s.Class, entity: s.EntityType, region: s.PhoneRegion, needsReview: s.NeedsReview}
		require.NotEmpty(t, s.Reason, r.Column.FullName())
		// Reasons carry names and counts, never a value.
		for _, frag := range []string{"@", "+62", "0812", "Alice", "Jalan", "4111", "DE89", "3174"} {
			require.NotContains(t, s.Reason, frag, r.Column.FullName())
		}
	}
	for name, w := range fixtureWant {
		require.Equal(t, w, got[name], "%s: reason %q", name, reasonOf(results, name))
	}
	require.Len(t, got, len(fixtureWant), "every readable column has an expected suggestion")
}

func reasonOf(results []classify.Result, name string) string {
	for _, r := range results {
		if r.Column.FullName() == name {
			return r.Suggestion.Reason
		}
	}
	return ""
}

func TestFixtureSchemaFixedPhoneRegion(t *testing.T) {
	t.Parallel()
	d := fixtureDB(t)
	for _, r := range suggestAll(t, d, classify.Options{PhoneRegion: "ID"}, false) {
		if r.Suggestion.EntityType == guard.EntityPhone {
			require.Equal(t, "ID", r.Suggestion.PhoneRegion, r.Column.FullName())
		}
	}
}

func TestFixtureSchemaRoundTrip(t *testing.T) {
	t.Parallel()
	d := fixtureDB(t)
	results := suggestAll(t, d, classify.Options{}, true)
	checks, err := classify.Check(results, func(r classify.Result) (classify.CheckTarget, bool) {
		s := r.Suggestion
		return classify.CheckTarget{EntityType: s.EntityType, PhoneRegion: s.PhoneRegion}, s.Class == guard.ClassIdentifier
	})
	require.NoError(t, err)
	for name, w := range fixtureWant {
		ck, ok := checks[name]
		require.Equal(t, w.class == guard.ClassIdentifier, ok, name)
		if !ok || w.entity == guard.EntityOther && strings.HasSuffix(name, "dob") {
			continue
		}
		require.Positive(t, ck.Sampled, name)
		require.Zero(t, ck.RoundTripFailures, name)
	}
}

func TestSampleTimesOutAndIsReviewed(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE VIEW public.slow AS SELECT pg_sleep(2)::text || 'x' AS v FROM generate_series(1, 3)`)
	ctx := context.Background()
	s, err := classify.Sampler{Conn: d.Admin, Timeout: 50 * time.Millisecond}.Sample(ctx,
		classify.Column{Schema: "public", Table: "slow", Name: "v", DataType: "text"})
	require.NoError(t, err)
	require.Equal(t, classify.UnavailableTimeout, s.Unavailable)
	require.Empty(t, s.Values)
	got := classify.Suggest(classify.Column{Schema: "public", Table: "slow", Name: "v", DataType: "text"}, s, classify.Options{})
	require.Equal(t, classify.Suggestion{Class: guard.ClassIdentifier, EntityType: guard.EntityOther, NeedsReview: true,
		Reason: "SAMPLE:timed out"}, got)
}

func TestSampleIsBounded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.big (v text); INSERT INTO public.big SELECT repeat('x', 5000) FROM generate_series(1, 1500)`)
	s, err := classify.Sampler{Conn: d.Admin, Timeout: 5 * time.Second}.Sample(context.Background(),
		classify.Column{Schema: "public", Table: "big", Name: "v", DataType: "text"})
	require.NoError(t, err)
	require.Len(t, s.Values, classify.SampleRows)
	for _, v := range s.Values {
		require.LessOrEqual(t, len(v), 1024)
	}
}
