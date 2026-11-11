package guard_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

func lastUsedAt(t *testing.T, d *guardtest.DB, p *passkeytest.Authenticator) *time.Time {
	t.Helper()
	return scalarOf[*time.Time](t, d.Admin, `SELECT last_used_at FROM basalt_meta.passkeys WHERE credential_id = $1`, p.ID)
}

func TestRevokedPasskeyCannotApproveOrRevert(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	spare := person(t, d)
	ctx := context.Background()

	// A run to revert later, and a held write to approve.
	in := newRun(t, a, "Mark leads won")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 90 AND 92`))
	const stmt = `DELETE FROM public.leads WHERE id = $1`
	held, _ := previewAndHold(t, a.Conn, in, stmt, []any{3}, []string{})

	remaining, err := guard.RevokePasskey(ctx, d.Admin, p.ID, false)
	require.NoError(t, err)
	require.Equal(t, 1, remaining)

	_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
	requireInvalid(t, err, "passkey revoked")

	prep, as := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)
	_, err = guard.ApplyRevert(ctx, a.Conn, prep.RevertID, as)
	requireRevertInvalid(t, err, "passkey revoked")
	require.Equal(t, "won", leadStatus(t, d, 90), "nothing was reverted")

	// The other passkey still signs.
	_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, spare, held, nil))
	require.NoError(t, err)

	// Revoked passkeys leave the agent view (and so the links).
	keys, err := ledger.ListPasskeys(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, spare.ID, keys[0].Credential.ID)

	// Revoked stays revoked: re-registering the same id is refused.
	err = guard.RegisterPasskey(ctx, d.Admin, p.Credential(), "again")
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	_, err = guard.RevokePasskey(ctx, d.Admin, p.ID, false)
	requireCode(t, err, guard.CodeLedgerInputInvalid)

	// The revocation is in the chained ledger.
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind = 'PASSKEY_REVOKED' AND detail ->> 'credentialId' = $1 AND (detail ->> 'remaining')::int = 1
		AND NOT (detail ->> 'forced')::boolean`, passkey.Bytes(p.ID).String()))
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))
}

func TestLastPasskeyNeedsForce(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()

	_, err := guard.RevokePasskey(ctx, d.Admin, p.ID, false)
	requireCode(t, err, guard.CodeNotAllowed)
	require.Nil(t, scalarOf[*time.Time](t, d.Admin, `SELECT revoked_at FROM basalt_meta.passkeys WHERE credential_id = $1`, p.ID))

	remaining, err := guard.RevokePasskey(ctx, d.Admin, p.ID, true)
	require.NoError(t, err)
	require.Equal(t, 0, remaining)
	keys, err := guard.ActivePasskeys(ctx, d.Admin)
	require.NoError(t, err)
	require.Empty(t, keys)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind = 'PASSKEY_REVOKED' AND (detail ->> 'forced')::boolean`))
}

func TestLastUsedAtUpdates(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	require.Nil(t, lastUsedAt(t, d, p))

	in := newRun(t, a, "remove the spam lead")
	held, _ := previewAndHold(t, a.Conn, in, `DELETE FROM public.leads WHERE id = $1`, []any{3}, []string{})

	// A refused assertion does not count as a use.
	_, err := guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, func(as *passkey.Assertion) { as.AuthenticatorData[32] = passkeytest.FlagUP }))
	require.Error(t, err)
	require.Nil(t, lastUsedAt(t, d, p))

	_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
	require.NoError(t, err)
	used := lastUsedAt(t, d, p)
	require.NotNil(t, used)
	require.WithinDuration(t, time.Now(), *used, time.Minute)

	keys, err := ledger.ListPasskeys(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.NotNil(t, keys[0].LastUsedAt, "the agent view shows when it was last used")
	require.False(t, keys[0].Unused(time.Now()))
	require.True(t, keys[0].Unused(time.Now().Add(ledger.PasskeyUnusedAfter)))
}

func TestAgentCannotRegisterOrRevokePasskeys(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()

	_, err := guard.RevokePasskey(ctx, a.Conn, p.ID, true)
	require.Equal(t, "42501", guardtest.SQLState(err))
	stranger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.Equal(t, "42501", guardtest.SQLState(guard.RegisterPasskey(ctx, a.Conn, stranger.Credential(), "mine")))
	_, err = a.Conn.Exec(ctx, `UPDATE basalt_meta.passkeys SET revoked_at = NULL`)
	require.Equal(t, "42501", guardtest.SQLState(err))
	_, err = guard.ActivePasskeys(ctx, a.Conn)
	require.Equal(t, "42501", guardtest.SQLState(err), "the agent reads passkeys only through its view")
}

func TestRegisterPasskeyStoresUserHandle(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Init(t, guard.AgentSpec{})
	ctx := context.Background()
	p, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	cred := p.Credential()
	cred.UserHandle = []byte{1, 2, 3, 4}
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, cred, "laptop"))
	keys, err := guard.ActivePasskeys(ctx, d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, []byte{1, 2, 3, 4}, keys[0].UserHandle)
	require.Equal(t, "laptop", keys[0].Label)

	cred.UserHandle = make([]byte, 65)
	cred.ID = []byte{9}
	requireCode(t, guard.RegisterPasskey(ctx, d.Admin, cred, "too long"), guard.CodeLedgerInputInvalid)
}
