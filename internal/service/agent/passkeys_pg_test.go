package agent_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
)

// The pages pass credentialIds as allowCredentials, so the browser offers
// only this database's passkeys. Both the engine's answers and the long
// links carry exactly the active ones on the pages' origin: a revoked
// passkey, and one of another origin that cannot sign there, are left out.
func TestPagesOfferOnlyThisDatabasesActivePasskeys(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	ctx := context.Background()
	admin := s.env.d.Admin
	pages := s.env.person.Credential().Relying
	other, err := passkeytest.New(pages)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, admin, other.Credential(), "laptop"))
	portal, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, admin, portal.Credential(), "portal phone"))
	revoked, err := passkeytest.New(pages)
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
	back, _, err := approvaltest.ParseRequest(frag)
	require.NoError(t, err)
	require.ElementsMatch(t, want, back.CredentialIDs)
	rvFrag, err := revert.Request{RevertID: rv.RevertID, Binding: rv.Binding, Lines: rv.Lines, CredentialIDs: rv.CredentialIDs}.Fragment()
	require.NoError(t, err)
	rvBack, _, err := reverttest.ParseRequest(rvFrag)
	require.NoError(t, err)
	require.ElementsMatch(t, want, rvBack.CredentialIDs)
}
