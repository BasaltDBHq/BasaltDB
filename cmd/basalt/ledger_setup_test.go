package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// revertSetup is a demo database with basalt init done (agent bot on
// leads, the person's passkey registered), and a run of the agent that
// marked leads 40 to 45 won.
func revertSetup(t *testing.T) (*guardtest.DB, *passkeytest.Authenticator, string) {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	cred := initWithPasskey(t, d, person)
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Mark leads won"}
	require.NoError(t, guard.StartRun(ctx, conn, in))
	require.NoError(t, guardtest.Guarded(ctx, conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 40 AND 45`))
	return d, person, cred
}
