package localsetup

import (
	"net/url"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// A repaired credential keeps its user name, a Supabase pooler's
// role.<ref> included, and changes only the password.
func TestNewCredentialKeepsTheUserName(t *testing.T) {
	t.Parallel()
	s, err := New(Options{
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: "http://localhost:8787",
		Profiles: func() *trustprofile.Set { return trustprofile.NewSet(nil, nil, nil) },
	})
	require.NoError(t, err)
	const old = "postgres://basalt_agent_bot.abcdefghijklmnopqrst:oldpw@aws-0-eu-central-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
	got, err := s.newCredential(agentJob{role: "basalt_agent_bot"}, old, "newpw")
	require.NoError(t, err)
	u, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, "basalt_agent_bot.abcdefghijklmnopqrst", u.User.Username())
	pw, _ := u.User.Password()
	require.Equal(t, "newpw", pw)
	require.Equal(t, "aws-0-eu-central-1.pooler.supabase.com:5432", u.Host)
	require.Equal(t, "verify-full", u.Query().Get("sslmode"))

	// With the file gone, it is made from the admin string as the install
	// makes it: the pooler's user name too.
	admin := "postgres://postgres.abcdefghijklmnopqrst:" + "adminpw@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"
	got, err = s.newCredential(agentJob{role: "basalt_agent_bot", missing: true, req: Request{DatabaseURL: admin}}, "", "newpw")
	require.NoError(t, err)
	u, err = url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, "basalt_agent_bot.abcdefghijklmnopqrst", u.User.Username())
	require.NotContains(t, got, "adminpw")
}
