package pgpii_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
)

func TestSampleTimesOut(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE VIEW public.slow AS SELECT pg_sleep(2)::text || 'x' AS v FROM generate_series(1, 3)`)
	ctx := context.Background()
	s, err := pgpii.Sampler{ReadOnly: pgquerier.ReadOnlyTx(d.Admin), Timeout: 50 * time.Millisecond}.Sample(ctx,
		piistore.Column{Namespace: "public", Resource: "slow", Name: "v", Kind: piistore.KindText, DataType: "text"})
	require.NoError(t, err)
	require.Equal(t, piistore.UnavailableTimeout, s.Unavailable)
	require.Empty(t, s.Values)
}

// TestSampleErrorKeepsOnlyTheSQLState: an error that would quote a value
// (invalid input syntax for type integer: "Blue Widget") leaves the column
// unsampled with its SQLSTATE only.
func TestSampleErrorKeepsOnlyTheSQLState(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.items (id bigint, label text);
		INSERT INTO public.items VALUES (1, 'Blue Widget');
		CREATE VIEW public.bad AS SELECT label::integer AS n FROM public.items`)
	col := piistore.Column{Namespace: "public", Resource: "bad", Name: "n", Kind: piistore.KindInt, DataType: "integer"}
	s, err := pgpii.Sampler{ReadOnly: pgquerier.ReadOnlyTx(d.Admin), Timeout: 5 * time.Second}.Sample(context.Background(), col)
	require.NoError(t, err)
	require.Equal(t, piistore.Sample{Unavailable: "error 22P02"}, s)
}

func TestSampleIsBounded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.big (v text); INSERT INTO public.big SELECT repeat('x', 5000) FROM generate_series(1, 1500)`)
	s, err := pgpii.Sampler{ReadOnly: pgquerier.ReadOnlyTx(d.Admin), Timeout: 5 * time.Second}.Sample(context.Background(),
		piistore.Column{Namespace: "public", Resource: "big", Name: "v", Kind: piistore.KindText, DataType: "text"})
	require.NoError(t, err)
	require.Len(t, s.Values, piistore.SampleRows)
	for _, v := range s.Values {
		require.LessOrEqual(t, len(v), 1024)
	}
}

func TestSampleCutsEachValueToMaxChars(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.wide (v text); INSERT INTO public.wide SELECT repeat('é', 5000) FROM generate_series(1, 5)`)
	s, err := pgpii.Sampler{ReadOnly: pgquerier.ReadOnlyTx(d.Admin), Timeout: 5 * time.Second, MaxChars: 256}.Sample(context.Background(),
		piistore.Column{Namespace: "public", Resource: "wide", Name: "v", Kind: piistore.KindText, DataType: "text"})
	require.NoError(t, err)
	require.Len(t, s.Values, 5)
	for _, v := range s.Values {
		require.Equal(t, 256, len([]rune(v)), "characters, not bytes")
	}
}

// TestColumnsFillsKindKeysAndDomains: Columns resolves the listed columns
// by name, marks keys and generated columns, gives a domain the kind of the
// type it is built on, and leaves a column it cannot find with the kind of
// its data type.
func TestColumnsFillsKindKeysAndDomains(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE DOMAIN public.mail AS text;
		CREATE DOMAIN public.work_mail AS public.mail;
		CREATE TABLE public.owners (id bigint PRIMARY KEY);
		CREATE TABLE public.people (id bigserial PRIMARY KEY, owner_id bigint REFERENCES public.owners(id),
			email public.work_mail, joined date, active boolean, tag uuid)`)
	col := func(name, typ string) piistore.Column {
		return piistore.Column{Namespace: "public", Resource: "people", Name: name, DataType: typ}
	}
	listed := []piistore.Column{
		col("id", "bigint"), col("owner_id", "bigint"), col("email", "public.work_mail"),
		col("joined", "date"), col("active", "boolean"), col("tag", "uuid"), col("gone", "text"),
	}
	got, err := pgpii.Columns(context.Background(), pgquerier.Neutralize(d.Admin), listed)
	require.NoError(t, err)
	want := []piistore.Column{
		{Namespace: "public", Resource: "people", Name: "id", DataType: "bigint", Kind: piistore.KindInt, Key: true, Generated: true},
		{Namespace: "public", Resource: "people", Name: "owner_id", DataType: "bigint", Kind: piistore.KindInt, Key: true},
		{Namespace: "public", Resource: "people", Name: "email", DataType: "public.work_mail", Kind: piistore.KindText},
		{Namespace: "public", Resource: "people", Name: "joined", DataType: "date", Kind: piistore.KindDate},
		{Namespace: "public", Resource: "people", Name: "active", DataType: "boolean", Kind: piistore.KindBool},
		{Namespace: "public", Resource: "people", Name: "tag", DataType: "uuid", Kind: piistore.KindOther},
		{Namespace: "public", Resource: "people", Name: "gone", DataType: "text", Kind: piistore.KindText},
	}
	require.Equal(t, want, got)
}

// TestColumnsReadsADottedSchemaByItsOwnName: a schema name with a dot and a
// mixed-case table are matched by their own names, never split.
func TestColumnsReadsADottedSchemaByItsOwnName(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE DOMAIN public.mail AS text;
		CREATE SCHEMA "app.v2";
		CREATE TABLE "app.v2"."People" (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email public.mail)`)
	listed := []piistore.Column{
		{Namespace: "app.v2", Resource: "People", Name: "id", DataType: "bigint"},
		{Namespace: "app.v2", Resource: "People", Name: "email", DataType: "public.mail"},
	}
	got, err := pgpii.Columns(context.Background(), pgquerier.Neutralize(d.Admin), listed)
	require.NoError(t, err)
	require.Equal(t, []piistore.Column{
		{Namespace: "app.v2", Resource: "People", Name: "id", DataType: "bigint", Kind: piistore.KindInt, Key: true, Generated: true},
		{Namespace: "app.v2", Resource: "People", Name: "email", DataType: "public.mail", Kind: piistore.KindText},
	}, got)
}
