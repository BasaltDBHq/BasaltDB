package agent_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// The pages pass credentialIds as allowCredentials, so the browser offers
// only this database's passkeys. Both the engine's answers and the long
// links carry exactly the active ones: a revoked passkey is left out.
func TestPagesOfferOnlyThisDatabasesActivePasskeys(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	ctx := context.Background()
	admin := s.env.d.Admin
	other, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, admin, other.Credential(), "laptop"))
	revoked, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, admin, revoked.Credential(), "old phone"))
	_, err = guard.RevokePasskey(ctx, admin, revoked.Credential().ID, true)
	require.NoError(t, err)
	want := []passkey.Bytes{s.env.person.Credential().ID, other.Credential().ID}

	req, _ := s.approvalRequest(t)
	require.ElementsMatch(t, want, req.CredentialIDs)
	rv, _ := s.revertRequest(t)
	require.ElementsMatch(t, want, rv.CredentialIDs)

	// A long link carries them too.
	frag, err := approval.Request{ApprovalID: req.ApprovalID, Binding: req.Binding, Lines: req.Lines, CredentialIDs: req.CredentialIDs}.Fragment()
	require.NoError(t, err)
	back, _, err := approval.ParseRequest(frag)
	require.NoError(t, err)
	require.ElementsMatch(t, want, back.CredentialIDs)
	rvFrag, err := revert.Request{RevertID: rv.RevertID, Binding: rv.Binding, Lines: rv.Lines, CredentialIDs: rv.CredentialIDs}.Fragment()
	require.NoError(t, err)
	rvBack, _, err := revert.ParseRequest(rvFrag)
	require.NoError(t, err)
	require.ElementsMatch(t, want, rvBack.CredentialIDs)
}
