package setupcode

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHasPassword(t *testing.T) {
	t.Parallel()
	for conn, want := range map[string]bool{
		"postgres://postgres@db.example.com/postgres":                                                    false,
		"postgres://postgres:@db.example.com/postgres":                                                   false,
		"postgresql://postgres.ref:[YOUR-PASSWORD]@aws-0-eu-central-1.pooler.supabase.com:6543/postgres": false,
		"postgres://postgres:s3cret@db.example.com/postgres":                                             true,
		"postgres://postgres@db.example.com/postgres?password=s3cret":                                    true,
		"postgres://postgres@db.example.com/postgres?PASSWORD=s3cret":                                    true,
		"host=db.example.com user=postgres password=s3cret":                                              true,
		"host=db.example.com user=postgres password = s3cret":                                            true,
		"host=db.example.com user=postgres Password\t=\t's3cret'":                                        true,
		"postgres://postgres@db.example.com/postgres?password%20=s3cret":                                 true,
		"postgres://postgres:s3[cret@db.example.com/postgres":                                            true,
	} {
		require.Equal(t, want, HasPassword(conn), conn)
	}
}

func TestParseConnURL(t *testing.T) {
	t.Parallel()
	_, tg, err := ParseConnURL("postgresql://postgres.abcdefghijklmnopqrst:[YOUR-PASSWORD]@aws-0-eu-central-1.pooler.supabase.com:6543/postgres")
	require.NoError(t, err)
	require.Equal(t, Target{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}, tg)

	_, tg, err = ParseConnURL("postgresql://postgres.abcdefghijklmnopqrst:[YOUR-PASSWORD]@aws-0-eu-central-1.pooler.supabase.co:6543/postgres")
	require.NoError(t, err)
	require.Equal(t, "abcdefghijklmnopqrst", tg.SupabaseRef, "the pooler's .co name")
	_, tg, err = ParseConnURL("postgresql://postgres.abcdefghijklmnopqrst@evilpooler.supabase.co:6543/postgres")
	require.NoError(t, err)
	require.Empty(t, tg.SupabaseRef, "a look-alike is no pooler")

	_, tg, err = ParseConnURL("postgres://postgres@db.abcdefghijklmnopqrst.supabase.co/postgres")
	require.NoError(t, err)
	require.Equal(t, Target{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}, tg)

	_, tg, err = ParseConnURL("postgres://app@10.0.0.5:6000/crm?sslmode=require")
	require.NoError(t, err)
	require.Equal(t, Target{Host: "10.0.0.5", Port: 6000, Database: "crm"}, tg)

	_, _, err = ParseConnURL("postgres://app:pw@10.0.0.5/crm")
	require.ErrorIs(t, err, ErrHasPassword)
	require.NotContains(t, err.Error(), "pw@")
	for _, bad := range []string{"mysql://a@h/db", "postgres://a@h", "postgres://a@h1,h2/db", "postgres://a@h:99999/db"} {
		_, _, err = ParseConnURL(bad)
		require.Error(t, err, bad)
	}
}

func TestParseConnURLRefusesTargetParams(t *testing.T) {
	t.Parallel()
	for _, param := range []string{"host=10.0.0.9", "hostaddr=10.0.0.9", "port=6000", "dbname=other", "DBName=other"} {
		_, _, err := ParseConnURL("postgres://app@10.0.0.5:5432/crm?sslmode=require&" + param)
		require.Error(t, err, param)
		require.Contains(t, err.Error(), "put the host, port and database in the URL itself", param)
	}
	u, err := url.Parse("postgres://app:pw@10.0.0.5/crm?dbname=other")
	require.NoError(t, err)
	_, err = TargetOf(u)
	require.ErrorContains(t, err, "dbname=")
	var pe *TargetParamError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "dbname", pe.Param)
}

func TestNewSetupID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 6, 2, 11, 987654321, time.UTC)
	id, expires, err := NewSetupID(now, bytes.NewReader(make([]byte, 16)))
	require.NoError(t, err)
	require.Regexp(t, setupIDPattern, id)
	require.Equal(t, "2026-11-12T06:12:11Z", expires)
	p := Payload{SetupID: id, ExpiresAt: expires}
	created, err := p.CreatedAt()
	require.NoError(t, err)
	require.Equal(t, now.Truncate(time.Millisecond), created)
	require.NoError(t, p.validateExpiry())
}
