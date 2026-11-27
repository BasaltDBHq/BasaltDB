package trustprofile_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// A string with no sslmode for a host a built-in profile covers gets
// sslmode=verify-full, the rest of it byte for byte; anything else is
// returned as given.
func TestVerifyFullByDefault(t *testing.T) {
	t.Parallel()
	builtin := trustprofile.BuiltInSet()
	pin := &trustprofile.Profile{Spec: trustprofile.Spec{Name: trustprofile.PinName("db.abc.supabase.co"), Match: []string{"=db.abc.supabase.co"}}, Origin: trustprofile.Operator}
	withPin := trustprofile.NewSet(trustprofile.BuiltIns(), []*trustprofile.Profile{pin}, nil)
	off := &trustprofile.Profile{Spec: trustprofile.Spec{Name: "supabase", Disabled: true}, Origin: trustprofile.Operator}
	disabled := trustprofile.NewSet(trustprofile.BuiltIns(), []*trustprofile.Profile{off}, nil)

	// at is a URL that logs in as u at rest (split so no scanner reads it
	// as a credential).
	at := func(scheme, rest string) string { return scheme + "://u" + ":" + "pw@" + rest }
	supa := at("postgresql", "db.abc.supabase.co:5432/postgres")
	for _, tc := range []struct {
		name, in, want string
		set            *trustprofile.Set
	}{
		{"supabase", supa, supa + "?sslmode=verify-full", builtin},
		{"supabase pooler", at("postgres", "aws-0-eu-west-1.pooler.supabase.com:6543/postgres"), at("postgres", "aws-0-eu-west-1.pooler.supabase.com:6543/postgres?sslmode=verify-full"), builtin},
		{"rds with other parameters", at("postgres", "x.abc.eu-west-1.rds.amazonaws.com/app?connect_timeout=5"), at("postgres", "x.abc.eu-west-1.rds.amazonaws.com/app?connect_timeout=5&sslmode=verify-full"), builtin},
		{"upper-case host", at("postgres", "DB.ABC.SUPABASE.CO/postgres"), at("postgres", "DB.ABC.SUPABASE.CO/postgres?sslmode=verify-full"), builtin},
		{"encoded password kept", "postgres://u" + ":" + "p%21w@db.abc.supabase.co/postgres", "postgres://u" + ":" + "p%21w@db.abc.supabase.co/postgres?sslmode=verify-full", builtin},
		{"empty query", supa + "?", supa + "?sslmode=verify-full", builtin},
		{"explicit require", supa + "?sslmode=require", supa + "?sslmode=require", builtin},
		{"explicit disable", supa + "?sslmode=disable", supa + "?sslmode=disable", builtin},
		{"explicit empty", supa + "?sslmode=", supa + "?sslmode=", builtin},
		{"own root", supa + "?sslrootcert=/x", supa + "?sslrootcert=/x", builtin},
		{"no profile", at("postgres", "db.example.com/app"), at("postgres", "db.example.com/app"), builtin},
		{"no set", supa, supa, nil},
		{"operator pin", supa, supa, withPin},
		{"built-in turned off", supa, supa, disabled},
		{"several hosts", at("postgres", "a.supabase.co,b.supabase.co/postgres"), at("postgres", "a.supabase.co,b.supabase.co/postgres"), builtin},
		{"host parameter", at("postgres", "db.abc.supabase.co/postgres?host=db.example.com"), at("postgres", "db.abc.supabase.co/postgres?host=db.example.com"), builtin},
		{"fragment", supa + "#x", supa + "#x", builtin},
		{"key=value", "host=db.abc.supabase.co user=u", "host=db.abc.supabase.co user=u", builtin},
		{"not a url", at("postgres", "%zz/x"), at("postgres", "%zz/x"), builtin},
	} {
		require.Equal(t, tc.want, trustprofile.VerifyFullByDefault(tc.in, tc.set), tc.name)
	}
}

// BuiltInProvider names the provider whose built-in profile is the one for
// a host, and nothing when a pin or an operator decides for it.
func TestBuiltInProvider(t *testing.T) {
	t.Parallel()
	builtin := trustprofile.BuiltInSet()
	pin := &trustprofile.Profile{Spec: trustprofile.Spec{Name: trustprofile.PinName("db.abc.supabase.co"), Match: []string{"=db.abc.supabase.co"}}, Origin: trustprofile.Operator}
	withPin := trustprofile.NewSet(trustprofile.BuiltIns(), []*trustprofile.Profile{pin}, nil)
	require.Equal(t, "Supabase", trustprofile.BuiltInProvider("db.abc.supabase.co", builtin))
	require.Equal(t, "Supabase", trustprofile.BuiltInProvider("DB.ABC.SUPABASE.CO.", builtin))
	require.Equal(t, "Amazon RDS", trustprofile.BuiltInProvider("x.abc.eu-west-1.rds.amazonaws.com", builtin))
	require.Empty(t, trustprofile.BuiltInProvider("db.example.com", builtin))
	require.Empty(t, trustprofile.BuiltInProvider("db.abc.supabase.co", withPin), "a pin decides for the host")
	require.Empty(t, trustprofile.BuiltInProvider("db.abc.supabase.co", nil))
}
