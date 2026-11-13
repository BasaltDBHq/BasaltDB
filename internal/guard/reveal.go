package guard

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// RevealRefused is the one detail of APPROVAL_INVALID and REVERT_INVALID for
// every failed reveal proof, key, nonce or ticket check (CONTRACT.md, Rows
// hidden from the agent; version 29).
const RevealRefused = "REVEAL_REFUSED"

// RevealedRevert is reveal_revert_rows' answer: the values of the
// request's redacted lines, or RowsChanged (and no row) when a hidden row
// changed since the revert was prepared. Either way the proof used up the
// revert's reveal nonce.
type RevealedRevert struct {
	Rows        []approval.RevealedRow `json:"rows"`
	RowsChanged bool                   `json:"rowsChanged"`
}

// RevealNonce is the reveal nonce of the caller's own approval
// (approval.KindApprove) or revert (approval.KindRevert), which the person's
// reveal proof signs (basalt_meta.reveal_nonce, version 29). Another role's
// item, or none, is APPROVAL_INVALID "no such approval" or REVERT_INVALID
// "no such revert".
func RevealNonce(ctx context.Context, q Querier, kind string, id uuid.UUID) ([]byte, error) {
	var out []byte
	// Plain SQL: one function call returning bytea.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reveal_nonce($1::text, $2::uuid)`, kind, id.String()).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevealRevertRows asks Postgres for the values of the caller's own
// pending revert's redacted lines with the person's reveal proof and the
// key the engine derived from the page's reveal secret
// (approval.RevealKey; never the secret). Every proof or key failure is
// REVERT_INVALID detail RevealRefused and changes nothing. Run it in its
// own transaction.
func RevealRevertRows(ctx context.Context, q Querier, revertID uuid.UUID, proof passkey.Assertion, key []byte) (RevealedRevert, error) {
	b, err := json.Marshal(rescopeProof{
		CredentialID: proof.CredentialID, AuthenticatorData: proof.AuthenticatorData,
		ClientDataJSON: proof.ClientDataJSON, Signature: proof.Signature,
	})
	if err != nil {
		return RevealedRevert{}, err
	}
	var out RevealedRevert
	// Plain SQL: one function call returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.reveal_revert_rows($1::uuid, $2::jsonb, $3::bytea)`,
		revertID.String(), string(b), key).Scan(&out)
	if err != nil {
		return RevealedRevert{}, err
	}
	return out, nil
}
