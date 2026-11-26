package pii_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
)

// want is a column's expected suggestion.
type want struct {
	class, entity, region string
	needsReview           bool
}

var (
	public      = want{class: guardmodel.ClassPublic}
	secret      = want{class: guardmodel.ClassSecret}
	freeText    = want{class: guardmodel.ClassFreeText}
	email       = want{class: guardmodel.ClassIdentifier, entity: guardmodel.EntityEmail}
	idPhone     = want{class: guardmodel.ClassIdentifier, entity: guardmodel.EntityPhone, region: "ID"}
	personName  = want{class: guardmodel.ClassIdentifier, entity: guardmodel.EntityPersonName}
	other       = want{class: guardmodel.ClassIdentifier, entity: guardmodel.EntityOther}
	reviewPhone = want{class: guardmodel.ClassIdentifier, entity: guardmodel.EntityPhone, region: "ID", needsReview: true}
)

// fixtureWant is the expected suggestion of every column of
// testdata/schema.sql.
var fixtureWant = map[string]want{
	"public.customers.id":           public,
	"public.customers.password":     secret,
	"public.customers.email":        email,
	"public.customers.phone":        idPhone,
	"public.customers.full_name":    personName,
	"public.customers.address":      {class: guardmodel.ClassIdentifier, entity: guardmodel.EntityAddress},
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
	"public.customers.member_code":  {class: guardmodel.ClassIdentifier, entity: guardmodel.EntityOther, needsReview: true},
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
	"public.leads.id":               public,
	"public.leads.primary_ref":      email,
	"public.leads.alt_line":         idPhone,
	"public.leads.reach_at":         reviewPhone,
	"public.leads.reach_text":       reviewPhone,
	"public.leads.mobile_updated":   idPhone,
	"public.leads.email_status":     public,
	"public.leads.ref_value":        {class: guardmodel.ClassIdentifier, entity: guardmodel.EntityOther, needsReview: true},
	"public.leads.call_notes":       freeText,
	"public.leads.mixed_ref":        reviewPhone,
	"public.leads.pin":              secret,
	"public.leads.token_sent":       secret,
	"public.leads.line_block":       reviewPhone,
	"public.leads.line_text":        reviewPhone,
	"public.leads.every_second":     reviewPhone,
	"public.orders.ticket_no":       public,
	"public.users.ref":              reviewPhone,
	"public.users.uid":              public,
	"public.sessions.id":            reviewPhone,
	"public.sessions.user_ref":      reviewPhone,
	"public.sessions.seq":           reviewPhone,
	"public.accounts.account_no":    {class: guardmodel.ClassIdentifier, entity: guardmodel.EntityOther, needsReview: true},
	"public.accounts.owner_id":      public,
	"public.bad_cast.id":            public,
	"public.bad_cast.n":             {class: guardmodel.ClassIdentifier, entity: guardmodel.EntityOther, needsReview: true},
}

// fixtureDB loads the fixture schema and an agent that reads both tables.
func fixtureDB(t *testing.T) *guardtest.DB {
	t.Helper()
	d := guardtest.New(t)
	schema, err := os.ReadFile("testdata/schema.sql")
	require.NoError(t, err)
	d.Exec(t, string(schema))
	d.NewAgent(t, "bot", nil, []string{
		"public.customers", "public.orders", "public.leads", "public.bad_cast",
		"public.users", "public.sessions", "public.accounts",
	})
	return d
}

// suggestAll runs the classify pipeline as basalt classify does.
func suggestAll(t *testing.T, d *guardtest.DB, opts pii.Options, keep bool) []pii.Result {
	t.Helper()
	ctx := context.Background()
	var st guardmodel.ClassificationState
	require.NoError(t, pgx.BeginTxFunc(ctx, d.Admin, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		st, err = guard.ReadClassification(ctx, tx, d.Names)
		return err
	}))
	listed := make([]piistore.Column, 0, len(st.Readable))
	for _, r := range st.Readable {
		listed = append(listed, piistore.Column{Namespace: r.Schema, Resource: r.Table, Name: r.Column, DataType: r.DataType})
	}
	cols, err := pgpii.Columns(ctx, pgquerier.Neutralize(d.Admin), listed)
	require.NoError(t, err)
	sampler := pgpii.Sampler{ReadOnly: pgquerier.ReadOnlyTx(d.Admin), Timeout: 5 * time.Second}
	results, err := pii.SuggestAll(ctx, cols, sampler.Sample, opts,
		func(pii.Column, pii.Suggestion) bool { return keep })
	require.NoError(t, err)
	return results
}

func TestFixtureSchemaSuggestions(t *testing.T) {
	t.Parallel()
	d := fixtureDB(t)
	results := suggestAll(t, d, pii.Options{}, false)
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

func reasonOf(results []pii.Result, name string) string {
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
	for _, r := range suggestAll(t, d, pii.Options{PhoneRegion: "ID"}, false) {
		if r.Suggestion.EntityType == guardmodel.EntityPhone {
			require.Equal(t, "ID", r.Suggestion.PhoneRegion, r.Column.FullName())
		}
	}
}

func TestFixtureSchemaRoundTrip(t *testing.T) {
	t.Parallel()
	d := fixtureDB(t)
	results := suggestAll(t, d, pii.Options{}, true)
	checks, err := pii.Check(results, func(r pii.Result) (pii.CheckTarget, bool) {
		s := r.Suggestion
		return pii.CheckTarget{EntityType: s.EntityType, PhoneRegion: s.PhoneRegion}, s.Class == guardmodel.ClassIdentifier
	})
	require.NoError(t, err)
	for name, w := range fixtureWant {
		ck, ok := checks[name]
		require.Equal(t, w.class == guardmodel.ClassIdentifier, ok, name)
		if !ok || name == "public.customers.dob" || name == "public.bad_cast.n" {
			continue
		}
		require.Positive(t, ck.Sampled, name)
		require.Zero(t, ck.RoundTripFailures, name)
	}
}

// TestDomainsAreJudgedByTheirBaseType: a domain over citext, and a domain
// over a domain over text, are sampled as text.
func TestDomainsAreJudgedByTheirBaseType(t *testing.T) {
	t.Parallel()
	d := fixtureDB(t)
	got := map[string]pii.Result{}
	for _, r := range suggestAll(t, d, pii.Options{}, false) {
		got[r.Column.FullName()] = r
	}
	require.Equal(t, "public.email_address", got["public.leads.primary_ref"].Column.DataType)
	require.Equal(t, piistore.KindText, got["public.leads.primary_ref"].Column.Kind)
	require.Equal(t, piistore.KindText, got["public.leads.alt_line"].Column.Kind)
	require.Equal(t, guardmodel.EntityEmail, got["public.leads.primary_ref"].Suggestion.EntityType)
}
