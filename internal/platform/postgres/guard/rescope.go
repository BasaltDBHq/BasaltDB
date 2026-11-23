package guard

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// rescopeProof is the proof as rescope_revert reads it: base64url fields.
type rescopeProof struct {
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

// RescopeRevert changes the scope of the caller's own pending revert
// (basalt_meta.rescope_revert). Inside the caller's own work it needs
// nothing while nobody widened the revert; anything wider, and anything
// after a widen, needs the person's proof or the scope token, and fails as
// REVERT_INVALID detail RevertWidenRefused otherwise. Run it in its own
// transaction.
func RescopeRevert(ctx context.Context, q Querier, req action.RescopeRequest) (action.RescopedRevert, error) {
	sel, err := json.Marshal(req.Select)
	if err != nil {
		return action.RescopedRevert{}, err
	}
	var proof any
	if req.Proof != nil {
		b, err := proofJSON(*req.Proof)
		if err != nil {
			return action.RescopedRevert{}, err
		}
		proof = b
	}
	var out action.RescopedRevert
	// Plain SQL: one function call returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.rescope_revert($1::uuid, $2::jsonb, $3::jsonb, $4::bytea, $5::bytea)`,
		req.RevertID.String(), string(sel), proof, req.RescopeKey, req.Token).Scan(&out)
	if err != nil {
		return action.RescopedRevert{}, err
	}
	return out, nil
}

// RescopeOwn changes the scope of the caller's own pending revert to s, the
// caller's own work (agents = [session_user]), with no proof or token
// (basalt_meta.rescope_revert): the person's CLI narrowing a revert, never
// widening it. A select outside the caller's own work, or any rescope of a
// widened revert, fails as REVERT_INVALID detail RevertWidenRefused. Run it
// in its own transaction.
func RescopeOwn(ctx context.Context, q Querier, revertID uuid.UUID, s action.Scope) (action.PreparedRevert, error) {
	args, err := scopeArgs(s)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	var out action.RescopedRevert
	// Plain SQL: one function call over a built descriptor, returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.rescope_revert($5::uuid, `+ownSelect+`, NULL, NULL, NULL)`,
		append(args, revertID.String())...).Scan(&out)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	b, err := revert.ParseBinding(out.BindingText)
	if err != nil {
		return action.PreparedRevert{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	return action.PreparedRevert{
		RevertID: out.RevertID, BindingText: out.BindingText, ExpiresAt: out.ExpiresAt, Lines: out.Lines,
		Batched: b.Batched,
	}, nil
}

// ResetRevert puts the caller's own pending revert back to its proposal
// (basalt_meta.reset_revert), for the agent's reissueLink on a widened
// revert: the person's scope, ceiling and token are dropped and the reset
// is recorded (REVERT_RESET).
func ResetRevert(ctx context.Context, q Querier, revertID uuid.UUID) (action.RescopedRevert, error) {
	var out action.RescopedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reset_revert($1::uuid)`, revertID.String()).Scan(&out)
	if err != nil {
		return action.RescopedRevert{}, err
	}
	return out, nil
}

// RevertNonce is the rescope nonce of the caller's own revert, which the
// person's next widen proof signs (basalt_meta.revert_nonce, version 22).
// Another role's revert, or none, is REVERT_INVALID "no such revert".
func RevertNonce(ctx context.Context, q Querier, revertID uuid.UUID) ([]byte, error) {
	var out []byte
	// Plain SQL: one function call returning bytea.
	err := q.QueryRow(ctx, `SELECT basalt_meta.revert_nonce($1::uuid)`, revertID.String()).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RejectRevert marks the caller's own pending, unsigned revert REJECTED
// (basalt_meta.reject_revert, version 23) with the person's note ("" for
// none). Once the person widened the revert, token must be its scope token;
// before that it is nil. A missing or wrong token is REVERT_INVALID detail
// RevertWidenRefused; another role's revert, or none, is REVERT_INVALID "no
// such revert".
func RejectRevert(ctx context.Context, q Querier, revertID uuid.UUID, note string, token []byte) (action.RejectedRevert, error) {
	var out action.RejectedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reject_revert($1::uuid, $2::text, $3::bytea)`,
		revertID.String(), note, token).Scan(&out)
	if err != nil {
		return action.RejectedRevert{}, err
	}
	return out, nil
}
