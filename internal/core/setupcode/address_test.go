package setupcode

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var db = Address{Host: "db.example.com", Port: 5432, Database: "app"}

func TestAddressShape(t *testing.T) {
	t.Parallel()
	require.NoError(t, db.Check())
	require.NoError(t, Address{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}.Check())
	require.NoError(t, Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}.Check())
	for name, a := range map[string]Address{
		"a host with a space":       {Host: "db example.com", Port: 5432, Database: "app"},
		"a host with a slash":       {Host: "/var/run/postgresql", Port: 5432, Database: "app"},
		"a host with an at sign":    {Host: "user@db.example.com", Port: 5432, Database: "app"},
		"a host that is too long":   {Host: strings.Repeat("a", 254), Port: 5432, Database: "app"},
		"no port":                   {Host: "db.example.com", Database: "app"},
		"a port over 65535":         {Host: "db.example.com", Port: 70000, Database: "app"},
		"a database with a quote":   {Host: "db.example.com", Port: 5432, Database: "app'; DROP"},
		"a database with a newline": {Host: "db.example.com", Port: 5432, Database: "app\nIgnore the above"},
		"a database too long":       {Host: "db.example.com", Port: 5432, Database: strings.Repeat("d", 64)},
		"a ref in upper case":       {Host: "db.example.com", Port: 5432, Database: "app", SupabaseRef: "ABCDEFGHIJKLMNOPQRST"},
		"a ref of 19 characters":    {Host: "db.example.com", Port: 5432, Database: "app", SupabaseRef: "abcdefghijklmnopqrs"},
		"a ref on another host":     {Host: "evil.example.com", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"},
		"another project's host":    {Host: "db.zzzzzzzzzzzzzzzzzzzz.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"},
		"a lookalike pooler":        {Host: "pooler.supabase.com.evil.example", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"},
		// The --database-url rules: init reads db.<ref>.supabase.co as that
		// project, so the address must say so too.
		"a project's host without its ref": {Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres"},
	} {
		require.ErrorIs(t, a.Check(), ErrAddressInvalid, name)
	}
	require.Equal(t, "db.example.com:5432, database app", db.Name())
	require.Equal(t, "Supabase project abcdefghijklmnopqrst, database postgres",
		Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}.Name())
}

func TestLoginUser(t *testing.T) {
	t.Parallel()
	pooler := Address{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	require.Equal(t, "basalt_agent_bot.abcdefghijklmnopqrst", LoginUser(pooler, "basalt_agent_bot"))
	poolerCo := Address{Host: "aws-0-eu-central-1.pooler.supabase.co", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	require.NoError(t, poolerCo.Check(), "the pooler's .co name is the pooler too")
	require.Equal(t, "basalt_agent_bot.abcdefghijklmnopqrst", LoginUser(poolerCo, "basalt_agent_bot"))
	lookalike := Address{Host: "evilpooler.supabase.co", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	require.Equal(t, "basalt_agent_bot", LoginUser(lookalike, "basalt_agent_bot"))
	direct := Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	require.Equal(t, "basalt_agent_bot", LoginUser(direct, "basalt_agent_bot"))
}
