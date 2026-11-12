package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// classifyDB is the classify fixture schema with an agent that reads both
// of its tables.
func classifyDB(t *testing.T, more ...string) *guardtest.DB {
	t.Helper()
	d := guardtest.New(t)
	schema, err := os.ReadFile("../../internal/pii/classify/testdata/schema.sql")
	require.NoError(t, err)
	d.Exec(t, string(schema))
	d.NewAgent(t, "bot", nil, append([]string{"public.customers", "public.orders"}, more...))
	return d
}

// classifyCLI runs basalt classify with the admin connection string in the
// environment, stdin as the person's answers, and a terminal of width
// columns when interactive.
func classifyCLI(t *testing.T, d *guardtest.DB, stdin string, interactive bool, width int, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string {
			if k == envAdminURL {
				return d.URL
			}
			return ""
		})
	c.interactive = interactive
	c.width = func() int { return width }
	code := runClassify(c, args)
	return result{code, stdout.String(), stderr.String()}
}

type storedClass struct {
	class, entity, region string
	needsReview           bool
}

// storedClasses reads pii_columns as table.column → its class.
func storedClasses(t *testing.T, d *guardtest.DB) map[string]storedClass {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(), `SELECT table_name || '.' || column_name, class,
		coalesce(entity_type, ''), coalesce(phone_region, ''), needs_review FROM basalt_meta.pii_columns`)
	require.NoError(t, err)
	out := map[string]storedClass{}
	var (
		name string
		s    storedClass
	)
	_, err = pgx.ForEachRow(rows, []any{&name, &s.class, &s.entity, &s.region, &s.needsReview}, func() error {
		out[name] = s
		return nil
	})
	require.NoError(t, err)
	return out
}

func TestClassifyWithoutATerminalPrintsTheReviewAndWritesNothing(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	r := classifyCLI(t, d, "", false, 0)
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "basalt: no terminal to confirm the classes; pass --yes to accept the suggestions or --set to set columns")
	require.Contains(t, r.stdout, "34 columns to classify in 2 tables")
	require.Contains(t, r.stdout, "SECRET 3  IDENTIFIER 15  FREE_TEXT 2  PUBLIC 14  ⚠ needs review 1")
	require.Contains(t, r.stdout, "⚠ member_code → IDENTIFIER other?")
	require.Empty(t, storedClasses(t, d))
}

func TestClassifyYesTakesTheProtectedSuggestions(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	r := classifyCLI(t, d, "", false, 0, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "basalt: classified 34 columns (14 PUBLIC, 15 IDENTIFIER, 2 FREE_TEXT, 3 SECRET); 0 columns stay UNCLASSIFIED")
	got := storedClasses(t, d)
	require.Equal(t, storedClass{class: guard.ClassIdentifier, entity: guard.EntityOther, needsReview: true}, got["customers.member_code"])
	require.Equal(t, storedClass{class: guard.ClassIdentifier, entity: guard.EntityPhone, region: "ID"}, got["customers.msisdn"])
	require.Equal(t, storedClass{class: guard.ClassSecret}, got["customers.payment_ref"])
	require.Equal(t, storedClass{class: guard.ClassPublic}, got["orders.order_number"])

	// The flagged column stays in the review; the others are settled.
	r = classifyCLI(t, d, "", false, 0, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	review := decodeReview(t, r.stdout)
	require.Len(t, review.Tables, 1)
	require.Len(t, review.Tables[0].Columns, 1)
	require.Equal(t, "member_code", review.Tables[0].Columns[0].Column)
	require.Equal(t, "NEEDS_REVIEW", review.Tables[0].Columns[0].Status)

	// --yes never lowers a class a person confirmed.
	r = classifyCLI(t, d, "", false, 0, "--set", "public.orders.quantity=secret")
	require.Equal(t, exitOK, r.code, r.stderr)
	r = classifyCLI(t, d, "", false, 0, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, guard.ClassSecret, storedClasses(t, d)["orders.quantity"].class)
}

// reviewOut is the --json review as the tests read it.
type reviewOut struct {
	Fingerprint, PreviousFingerprint, Review string
	DryRun, Written                          bool
	Tables                                   []struct {
		Table   string
		Columns []struct {
			Column, DataType, Status, Class, EntityType, SuggestedClass, SuggestedEntityType, Reason, PhoneRegion string
			NeedsReview                                                                                           bool
			Check                                                                                                 *struct{ Sampled, RoundTripFailures, CommonWordRule int }
		}
	}
}

var reviewColumnKeys = []string{"column", "dataType", "status", "class", "entityType", "suggestedClass",
	"suggestedEntityType", "reason", "needsReview", "phoneRegion", "check"}

// decodeReview decodes the --json review and checks it against the rules of
// classify-review.schema.json: known keys only, entityType exactly with
// IDENTIFIER, phoneRegion only for a PHONE column.
func decodeReview(t *testing.T, out string) reviewOut {
	t.Helper()
	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &raw))
	for k := range raw {
		require.Contains(t, []string{"fingerprint", "previousFingerprint", "review", "dryRun", "written", "tables"}, k)
	}
	require.Regexp(t, `^[0-9a-f]{64}$`, raw["fingerprint"])
	for _, tb := range raw["tables"].([]any) {
		for _, c := range tb.(map[string]any)["columns"].([]any) {
			col := c.(map[string]any)
			for k := range col {
				require.Contains(t, reviewColumnKeys, k)
			}
			_, hasEntity := col["entityType"]
			require.Equal(t, col["class"] == "IDENTIFIER", hasEntity, "%v", col)
			_, hasSuggested := col["suggestedEntityType"]
			require.Equal(t, col["suggestedClass"] == "IDENTIFIER", hasSuggested, "%v", col)
			if _, ok := col["phoneRegion"]; ok {
				require.True(t, col["entityType"] == "PHONE" || col["suggestedEntityType"] == "PHONE", "%v", col)
			}
		}
	}
	var r reviewOut
	require.NoError(t, json.Unmarshal([]byte(out), &r))
	return r
}

func TestClassifyJSONAndDryRunWriteNothing(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	for _, args := range [][]string{{"--json"}, {"--json", "--dry-run", "--yes"}, {"--dry-run", "--yes"}} {
		r := classifyCLI(t, d, "", true, 0, args...)
		require.Equal(t, exitOK, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, storedClasses(t, d), "%v", args)
		require.NotContains(t, r.stderr, "Accept", "%v asks nothing", args)
	}
	r := classifyCLI(t, d, "", false, 0, "--json", "--review=all")
	review := decodeReview(t, r.stdout)
	require.Equal(t, "ALL", review.Review)
	require.False(t, review.Written)
	require.Empty(t, review.PreviousFingerprint)
	cols := 0
	for _, tb := range review.Tables {
		cols += len(tb.Columns)
		for _, c := range tb.Columns {
			require.Equal(t, "NEW", c.Status)
			require.Equal(t, "UNCLASSIFIED", c.Class)
			if c.Column == "phone_local" {
				require.Equal(t, "PHONE", c.SuggestedEntityType)
				require.Equal(t, "ID", c.PhoneRegion)
			}
		}
	}
	require.Equal(t, 34, cols)

	r = classifyCLI(t, d, "", false, 0, "--json", "--yes")
	review = decodeReview(t, r.stdout)
	require.True(t, review.Written)
	require.Equal(t, "IDENTIFIER", review.Tables[0].Columns[2].Class)
	r = classifyCLI(t, d, "", false, 0, "--json")
	require.NotEmpty(t, decodeReview(t, r.stdout).PreviousFingerprint)
}

func TestClassifySet(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	r := classifyCLI(t, d, "", false, 0, "--set", "public.customers.status=identifier:other",
		"--set", "public.customers.contact=identifier:phone", "--phone-region=ee")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, map[string]storedClass{
		"customers.status":  {class: guard.ClassIdentifier, entity: guard.EntityOther},
		"customers.contact": {class: guard.ClassIdentifier, entity: guard.EntityPhone, region: "EE"},
	}, storedClasses(t, d), "nothing but the --set columns is written")
	require.Contains(t, r.stderr, "basalt: classified 2 columns")

	for _, tc := range []struct{ arg, msg string }{
		{"public.customers.nope=public", "no agent can read that column"},
		{"public.customers.status=identifier", "identifier needs an entity type"},
		{"public.customers.status=public:email", "only identifier takes an entity type"},
		{"public.customers.status=hidden", `"hidden" is no class`},
		{"customers.status=public", "schema.table.column"},
		{"public.customers.status", "schema.table.column=class"},
	} {
		r := classifyCLI(t, d, "", false, 0, "--set", tc.arg)
		require.Equal(t, exitUsage, r.code, tc.arg)
		require.Contains(t, r.stderr, tc.msg, tc.arg)
	}
	r = classifyCLI(t, d, "", false, 0, "--phone-region=xx")
	require.Equal(t, exitUsage, r.code)
	r = classifyCLI(t, d, "", false, 0, "--review=some")
	require.Equal(t, exitUsage, r.code)
}

func TestClassifyPhoneRegionOverride(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	r := classifyCLI(t, d, "", false, 0, "--yes", "--phone-region=EE")
	require.Equal(t, exitOK, r.code, r.stderr)
	for name, s := range storedClasses(t, d) {
		if s.entity == guard.EntityPhone {
			require.Equal(t, "EE", s.region, name)
		}
	}
}

func TestClassifyCheck(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	r := classifyCLI(t, d, "", true, 0, "--check")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "public.customers.full_name: 200 sampled, 0 do not round-trip")
	require.Contains(t, r.stdout, "public.customers.msisdn: 200 sampled, 0 do not round-trip")
	require.NotContains(t, r.stdout, "public.customers.payment_ref:", "SECRET columns are not checked")
	require.Empty(t, storedClasses(t, d))

	r = classifyCLI(t, d, "", false, 0, "--check", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	checked := 0
	for _, tb := range decodeReview(t, r.stdout).Tables {
		for _, c := range tb.Columns {
			require.Equal(t, c.SuggestedClass == "IDENTIFIER", c.Check != nil, c.Column)
			if c.Check != nil {
				checked++
			}
		}
	}
	require.Equal(t, 15, checked)
	require.Empty(t, storedClasses(t, d))
}

func TestClassifyCheckCountsTheCommonWordRule(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.people (id bigint PRIMARY KEY, first_name text);
		INSERT INTO public.people VALUES (1, 'Hope'), (2, 'Grace'), (3, 'Alice Tamm')`)
	d.NewAgent(t, "bot", nil, []string{"public.people"})
	r := classifyCLI(t, d, "", false, 0, "--check")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "public.people.first_name: 3 sampled, 2 do not round-trip (2 single common words: the common-word rule)")
}

func TestClassifyInteractiveReview(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	// customers: protect member_code, edit status, accept the rest;
	// orders: skip.
	answers := "\n" + "e\nstatus=identifier:other\n" + "y\n" + "s\n"
	r := classifyCLI(t, d, answers, true, 120)
	require.Equal(t, exitOK, r.code, r.stderr)
	prompts := []string{
		"Protect member_code as IDENTIFIER? [Y/n]",
		"Accept the rest for public.customers? [Y/e/s]",
		"Edit (column=class[:entity-type]):",
		"basalt: status set to IDENTIFIER other",
		"Accept the rest for public.customers? [Y/e/s]",
		"Accept the rest for public.orders? [Y/e/s]",
		"basalt: skipped public.orders",
	}
	at := 0
	for _, p := range prompts {
		i := strings.Index(r.stderr[at:], p)
		require.GreaterOrEqual(t, i, 0, "%q after %d in %s", p, at, r.stderr)
		at += i + len(p)
	}
	// Layout C: the summary, then SECRET first within a table, the
	// needs-review column last.
	require.True(t, strings.HasPrefix(r.stdout, "34 columns to classify in 2 tables\n"), r.stdout)
	customers := r.stdout[strings.Index(r.stdout, "public.customers\n"):strings.Index(r.stdout, "public.orders\n")]
	require.Less(t, strings.Index(customers, "SECRET"), strings.Index(customers, "IDENTIFIER"))
	require.Less(t, strings.Index(customers, "IDENTIFIER"), strings.Index(customers, "FREE_TEXT"))
	require.Less(t, strings.Index(customers, "PUBLIC"), strings.Index(customers, "⚠ member_code"))
	require.Contains(t, customers, "phone · ID")

	got := storedClasses(t, d)
	require.Equal(t, storedClass{class: guard.ClassIdentifier, entity: guard.EntityOther}, got["customers.member_code"],
		"a person answered: no longer flagged")
	require.Equal(t, storedClass{class: guard.ClassIdentifier, entity: guard.EntityOther}, got["customers.status"])
	require.Equal(t, storedClass{class: guard.ClassIdentifier, entity: guard.EntityEmail}, got["customers.email"])
	require.Equal(t, guard.ClassUnclassified, got["orders.amount"].class, "a skipped table stays UNCLASSIFIED")
	require.Contains(t, r.stderr, "basalt: classified 26 columns")
	require.Contains(t, r.stderr, "8 columns stay UNCLASSIFIED")
}

func TestClassifyInteractiveDeclineProtection(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	answers := "n\nnope\npublic\n" + "y\n" + "y\n"
	r := classifyCLI(t, d, answers, true, 120)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, `basalt: "nope" is no class`)
	require.Equal(t, storedClass{class: guard.ClassPublic}, storedClasses(t, d)["customers.member_code"])

	// Stdin ending mid-review writes nothing.
	d2 := classifyDB(t)
	r = classifyCLI(t, d2, "\n", true, 120)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "nothing written")
	require.Empty(t, storedClasses(t, d2))
}

func TestClassifyNarrowTerminalPutsTheReasonOnItsOwnLine(t *testing.T) {
	t.Parallel()
	d := classifyDB(t)
	wide := classifyCLI(t, d, "", false, 120, "--dry-run")
	narrow := classifyCLI(t, d, "", false, 80, "--dry-run")
	require.Regexp(t, `(?m)^  SECRET +password +NAME:password$`, wide.stdout)
	require.Regexp(t, `(?m)^  SECRET +password\n      NAME:password$`, narrow.stdout)
}

func TestClassifyRefusesAGuardWithoutPII(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	r := classifyCLI(t, d, "", false, 0, "--dry-run")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "basalt: guard schema v0 has no PII classification; run basalt init again to upgrade it (same flags as before)")
}

// TestClassifyPrintsNoValue runs every mode and checks that no value of
// the fixture's PII columns, and not the admin password, reaches stdout,
// stderr or basalt_meta.
func TestClassifyPrintsNoValue(t *testing.T) {
	t.Parallel()
	d := classifyDB(t, "public.leads", "public.bad_cast")
	ctx := context.Background()
	rows, err := d.Admin.Query(ctx, `SELECT DISTINCT v FROM (
		SELECT unnest(ARRAY[password, email, phone, full_name, address, iban, description, login, contact,
			citizen_ref, device_ref, payout_ref, payment_ref, attendee, feedback, phone_intl, phone_local,
			msisdn::text, member_code::text]) AS v FROM public.customers) s`)
	require.NoError(t, err)
	values, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Greater(t, len(values), 1000)
	u, err := url.Parse(d.URL)
	require.NoError(t, err)
	password, _ := u.User.Password()

	outputs := make([]string, 0, 32)
	for _, run := range []struct {
		stdin       string
		interactive bool
		args        []string
	}{
		{"", false, nil},
		{"", false, []string{"--dry-run", "--yes"}},
		{"", false, []string{"--json", "--review=all"}},
		{"", false, []string{"--check"}},
		{"", false, []string{"--check", "--json"}},
		{"", false, []string{"--set", "public.customers.email=identifier:email"}},
		{"\ne\nnope=public\n" + strings.Repeat("y\n", 20), true, nil},
		{"", false, []string{"--yes", "--review=all"}},
		{"", false, []string{"--json", "--review=all"}},
	} {
		r := classifyCLI(t, d, run.stdin, run.interactive, 80, run.args...)
		// Without a terminal and without --yes the review ends in exit 1.
		require.True(t, r.code == exitOK || run.args == nil && !run.interactive, "%v: %s", run.args, r.stderr)
		outputs = append(outputs, r.stdout, r.stderr)
	}
	reasons, err := d.Admin.Query(ctx, `SELECT coalesce(reason, '') FROM basalt_meta.pii_columns`)
	require.NoError(t, err)
	stored, err := pgx.CollectRows(reasons, pgx.RowTo[string])
	require.NoError(t, err)
	outputs = append(outputs, stored...)
	all := strings.Join(outputs, "\n")
	require.NotEmpty(t, password)
	require.NotContains(t, all, d.URL)
	require.NotContains(t, all, ":"+password+"@")
	for _, v := range values {
		for _, form := range []string{v, strings.ReplaceAll(v, " ", "")} {
			if len(form) < 6 {
				continue
			}
			require.NotContains(t, all, form)
		}
	}
	// The words of names and addresses are values too.
	for _, w := range []string{"Alice", "Tamm", "Olivia", "Wijaya", "Jalan", "Melati", "Bandung", "courier", "@example",
		"Blue Widget", "Widget", "invalid input", "CB-1", "62812", "62815", "62813"} {
		require.NotContains(t, all, w)
	}
}
