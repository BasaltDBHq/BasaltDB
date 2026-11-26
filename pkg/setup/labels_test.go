package setup_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

var unlabeled = setup.Label{Class: guardmodel.ClassUnclassified}

// labelsOf reads the stored classes of table as the guard role.
func labelsOf(t *testing.T, d *guardtest.DB, table string) map[string]setup.Label {
	t.Helper()
	got, err := guard.ReadLabels(context.Background(), d.Admin, d.Names, []string{table})
	require.NoError(t, err)
	out := map[string]setup.Label{}
	for _, c := range got {
		out[c.Column] = setup.Label(c.Label)
	}
	return out
}

func catalogSet(t *testing.T, d *guardtest.DB) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := d.Admin.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, fmt.Sprintf(`SET LOCAL ROLE %s_guard`, d.Names.Prefix))
	require.NoError(t, err)
	var n int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM basalt_meta.pii_catalog WHERE fingerprint = basalt_meta.pii_fingerprint()`).Scan(&n))
	return n == 1
}

// Check lists every column of the agent's tables, UNCLASSIFIED on a
// database with no guard yet; Run writes the person's labels and, with
// RestPublic, PUBLIC for the rest, then sets the catalog.
func TestColumnLabelsWritten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	code := newCode(t, d, connectOnly(t))
	checked, err := setup.Check(ctx, d.Admin, ticked(code, "public.leads"))
	require.NoError(t, err)
	require.Equal(t, []setup.ColumnLabel{
		{Table: "public.leads", Column: "id", Label: unlabeled},
		{Table: "public.leads", Column: "name", Label: unlabeled},
		{Table: "public.leads", Column: "status", Label: unlabeled},
		{Table: "public.leads", Column: "score", Label: unlabeled},
	}, checked.Columns, "by column order; no guard yet, so nothing is labeled")

	_, give := personPasskey(t)
	name := setup.Label{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPersonName}
	_, err = setup.Run(ctx, d.Admin, ticked(code, "public.leads"), setup.RunInput{
		Passkey: verified(t, give),
		ColumnClasses: []setup.ColumnClass{
			{Table: "public.leads", Column: "name", Label: name, Was: unlabeled},
			{Table: "public.leads", Column: "score", Label: setup.Label{Class: guardmodel.ClassSecret}, Was: unlabeled},
		},
		RestPublic: true,
	})
	require.NoError(t, err)
	require.Equal(t, map[string]setup.Label{
		"id": {Class: guardmodel.ClassPublic}, "name": name, "score": {Class: guardmodel.ClassSecret}, "status": {Class: guardmodel.ClassPublic},
	}, labelsOf(t, d, "public.leads"))
	require.True(t, catalogSet(t, d), "pii_catalog is the fingerprint now, so a running engine reloads")
}

// A label whose column's class changed since Check, or whose column is
// gone, refuses the setup CLASSES_CHANGED, nothing changed; RestPublic
// never touches a labeled column; the rules that need no database are
// ANSWERS_INVALID.
func TestColumnLabelsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	code := newCode(t, d, connectOnly(t))
	_, give := personPasskey(t)
	secret := setup.Label{Class: guardmodel.ClassSecret}
	pk := verified(t, give)
	run := func(in setup.RunInput, tables ...string) error {
		in.Passkey = pk
		_, err := setup.Run(ctx, d.Admin, ticked(code, tables...), in)
		return err
	}

	err := run(setup.RunInput{ColumnClasses: []setup.ColumnClass{
		{Table: "public.leads", Column: "name", Label: secret, Was: setup.Label{Class: guardmodel.ClassPublic}},
	}}, "public.leads")
	require.Equal(t, setup.CodeClassesChanged, codeOf(t, err))
	require.Zero(t, installedVersion(t, d), "nothing changed")
	err = run(setup.RunInput{ColumnClasses: []setup.ColumnClass{
		{Table: "public.leads", Column: "gone", Label: secret, Was: unlabeled},
	}}, "public.leads")
	require.Equal(t, setup.CodeClassesChanged, codeOf(t, err), "a column dropped since Check reloads the labels")

	for why, c := range map[string]setup.ColumnClass{
		"a table not ticked":    {Table: "public.payroll", Column: "amount", Label: secret, Was: unlabeled},
		"UNCLASSIFIED":          {Table: "public.leads", Column: "name", Label: unlabeled, Was: unlabeled},
		"FREE_TEXT":             {Table: "public.leads", Column: "name", Label: setup.Label{Class: guardmodel.ClassFreeText}, Was: unlabeled},
		"IDENTIFIER, no entity": {Table: "public.leads", Column: "name", Label: setup.Label{Class: guardmodel.ClassIdentifier}, Was: unlabeled},
		"PHONE, no region":      {Table: "public.leads", Column: "name", Label: setup.Label{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone}, Was: unlabeled},
		"a region in lower case": {
			Table: "public.leads", Column: "name",
			Label: setup.Label{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: "de"}, Was: unlabeled,
		},
		"a region without PHONE":    {Table: "public.leads", Column: "name", Label: setup.Label{Class: guardmodel.ClassSecret, PhoneRegion: "DE"}, Was: unlabeled},
		"a was outside the classes": {Table: "public.leads", Column: "name", Label: secret, Was: setup.Label{Class: "PRIVATE"}},
	} {
		require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, run(setup.RunInput{ColumnClasses: []setup.ColumnClass{c}}, "public.leads")), why)
	}
	twice := setup.ColumnClass{Table: "public.leads", Column: "name", Label: secret, Was: unlabeled}
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, run(setup.RunInput{ColumnClasses: []setup.ColumnClass{twice, twice}}, "public.leads")))
	many := make([]setup.ColumnClass, 501)
	for i := range many {
		many[i] = setup.ColumnClass{Table: "public.leads", Column: fmt.Sprintf("c%d", i), Label: secret, Was: unlabeled}
	}
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, run(setup.RunInput{ColumnClasses: many}, "public.leads")))
	require.Zero(t, installedVersion(t, d), "nothing changed")

	// Without RestPublic, a column the person did not label stays so.
	require.NoError(t, run(setup.RunInput{ColumnClasses: []setup.ColumnClass{twice}}, "public.leads"))
	got := labelsOf(t, d, "public.leads")
	require.Equal(t, secret, got["name"])
	require.Equal(t, unlabeled, got["status"])
}

// RestPublic never touches a column that already has a class: a later
// setup (another agent on the same database) marks only the unlabeled
// rest PUBLIC.
func TestRestPublicKeepsStoredClasses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	_, give := personPasskey(t)
	secret := setup.Label{Class: guardmodel.ClassSecret}
	first := newCode(t, d, connectOnly(t))
	_, err := setup.Run(ctx, d.Admin, ticked(first, "public.leads"), setup.RunInput{
		Passkey:       verified(t, give),
		ColumnClasses: []setup.ColumnClass{{Table: "public.leads", Column: "name", Label: secret, Was: unlabeled}},
	})
	require.NoError(t, err)

	second := newCode(t, d, func(p *setupcode.Payload) {
		p.Agent.Name, p.Agent.Write = "helper", []string{"public.leads"}
	})
	_, err = setup.Run(ctx, d.Admin, setup.Request{Code: second, Now: time.Now()}, setup.RunInput{RestPublic: true})
	require.NoError(t, err)
	got := labelsOf(t, d, "public.leads")
	require.Equal(t, secret, got["name"], "a stored class is never lowered")
	require.Equal(t, setup.Label{Class: guardmodel.ClassPublic}, got["status"])
}
