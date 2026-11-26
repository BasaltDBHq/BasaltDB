package localsetup_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// An admin string with no sslmode for a host a built-in trust profile
// covers is dialed with sslmode=verify-full by both the check and the run;
// an explicit sslmode, and a host no profile covers, are dialed as given.
func TestAdminStringVerifiesByDefaultForABuiltInProfile(t *testing.T) {
	t.Parallel()
	var dialed []string
	svc, err := localsetup.New(localsetup.Options{
		Backend:    setupbackend.Backend{},
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: origin, Users: okUsers{},
		Profiles: trustprofile.BuiltInSet,
		Dial: setupbackend.Dialer(func(_ context.Context, dsn string) (*pgx.Conn, error) {
			dialed = append(dialed, dsn)
			return nil, errors.New("not here")
		}),
	})
	require.NoError(t, err)
	const supabase = "postgresql://postgres:" + "pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres"
	const rds = "postgres://admin:" + "pw@app.abc.eu-west-1.rds.amazonaws.com/app"
	for _, tc := range []struct{ in, want string }{
		{supabase, supabase + "?sslmode=verify-full"},
		{rds, rds + "?sslmode=verify-full"},
		{supabase + "?sslmode=require", supabase + "?sslmode=require"},
		{supabase + "?sslmode=disable", supabase + "?sslmode=disable"},
		{unusedAdminURL, unusedAdminURL},
	} {
		req := localsetup.Request{
			Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: tc.in,
			Tables:    []localsetup.TablePick{{Table: "public.a", Access: "READ"}},
			Challenge: &localsetup.Challenge{ExpiresAt: time.Now().Add(time.Hour)},
		}
		dialed = nil
		_, err := svc.Check(context.Background(), req)
		require.Error(t, err)
		_, err = svc.Run(context.Background(), req)
		require.Error(t, err)
		require.Equal(t, []string{tc.want, tc.want}, dialed, tc.in)
	}
}
